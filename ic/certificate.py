# reference: https://smartcontracts.org/docs/interface-spec/index.html#certification

import hashlib
import time
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union

import cbor2
import leb128

from ic.principal import Principal


class NodeId(Enum):
    Empty = 0
    Fork = 1
    Labeled = 2
    Leaf = 3
    Pruned = 4


def domain_sep(s: str) -> bytes:
    """Return a one-byte length prefix + ASCII bytes of the domain string."""
    b = s.encode("utf-8")
    if len(b) > 255:
        raise ValueError("domain separator too long")
    return bytes([len(b)]) + b


IC_STATE_ROOT_DOMAIN_SEPARATOR = b"\x0Dic-state-root"
IC_BLS_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
IC_ROOT_KEY = bytes.fromhex(
    "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100"
    "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd5"
    "46d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d1450"
    "5ffd7484b01291091c5f87b98883463f98091a0baaae"
)

DS_EMPTY = domain_sep("ic-hashtree-empty")
DS_FORK = domain_sep("ic-hashtree-fork")
DS_LABELED = domain_sep("ic-hashtree-labeled")
DS_LEAF = domain_sep("ic-hashtree-leaf")

DER_PREFIX = bytes.fromhex(
    "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100"
)
KEY_LEN = 96


class BlstUnavailable(RuntimeError):
    """Raised when the runtime does not provide the official 'blst' Python binding."""


def ensure_blst_available() -> "object":
    """
    Ensure the official supranational/blst SWIG binding is available and return the module.
    - If not installed: raise BlstUnavailable with installation instructions.
    - If a different 'blst' is shadowing: raise BlstUnavailable describing API mismatch.
    """
    try:
        import blst as _blst  # official supranational/blst SWIG binding
    except ModuleNotFoundError as e:
        raise BlstUnavailable(
            "BLS verification requires the official 'blst' Python binding, which was not found.\n\n"
            "Install (macOS/Linux):\n"
            "  1) git clone https://github.com/supranational/blst\n"
            "  2) cd blst/bindings/python && python3 run.me\n"
            "  3) Add that directory to PYTHONPATH, or copy blst.py and _blst*.so into site-packages\n\n"
            "For Apple Silicon (M1/M2): if you hit ABI issues, run with BLST_PORTABLE=1, e.g.\n"
            "  export BLST_PORTABLE=1 && python3 run.me"
        ) from e

    required = ("P1_Affine", "P2_Affine", "Pairing", "BLST_SUCCESS")
    if not all(hasattr(_blst, name) for name in required):
        raise BlstUnavailable(
            "A module named 'blst' was imported, but it does not expose the expected API.\n"
            "Ensure you are using the official supranational/blst SWIG binding."
        )
    return _blst


def verify_bls_signature_blst(signature: bytes, message: bytes, public_key_96: bytes) -> bool:
    """
    Verify BLS12-381 MinSig (G1 signature / G2 public key) using the official blst binding.
      - signature: compressed G1 (48 bytes)
      - public_key_96: compressed G2 (96 bytes)
      - DST: IC_BLS_DST (G1 ciphersuite)
    Returns True on success; False on failure.
    Raises BlstUnavailable if blst is not present.
    """
    _blst = ensure_blst_available()

    sig_bytes = bytes(signature)
    pubkey_bytes = bytes(public_key_96)
    msg_bytes = bytes(message)

    # Quick sanity checks.
    if len(sig_bytes) != 48 or len(pubkey_bytes) != 96:
        return False
    if (sig_bytes[0] & 0x80) == 0 or (pubkey_bytes[0] & 0x80) == 0:
        return False

    try:
        p1_ctor = getattr(_blst.P1_Affine, "from_compressed", _blst.P1_Affine)
        p2_ctor = getattr(_blst.P2_Affine, "from_compressed", _blst.P2_Affine)
        sig_aff = p1_ctor(sig_bytes)
        pk_aff = p2_ctor(pubkey_bytes)
    except Exception:
        return False

    # Path A: core_verify
    try:
        err = sig_aff.core_verify(pk_aff, True, msg_bytes, IC_BLS_DST, None)
        if err == _blst.BLST_SUCCESS:
            return True
    except Exception:
        return False

    # Path B: pairing-based verification as a fallback/diagnostic
    try:
        pairing = _blst.Pairing(True, IC_BLS_DST)
        pairing.aggregate(pk_aff, sig_aff, msg_bytes, None)
        return bool(pairing.finalverify())
    except Exception:
        return False


def extract_der(der: bytes) -> bytes:
    """Extract the raw 96-byte G2 public key from a DER-wrapped key with a fixed prefix."""
    if not isinstance(der, (bytes, bytearray, memoryview)):
        raise TypeError("der must be a bytes-like object")
    der = bytes(der)

    expected_len = len(DER_PREFIX) + KEY_LEN  # 37 + 96 = 133
    if len(der) != expected_len:
        raise ValueError(
            f"BLS DER-encoded public key must be {expected_len} bytes long (got {len(der)})"
        )

    prefix = der[: len(DER_PREFIX)]
    if prefix != DER_PREFIX:
        raise ValueError(
            "BLS DER-encoded public key prefix mismatch: "
            f"expected {DER_PREFIX.hex()}, got {prefix.hex()}"
        )

    return der[len(DER_PREFIX) :]  # 96 bytes


class Certificate:
    """
    Usage:
        cert = Certificate(certificate_dict)
        reply = cert.lookup_reply(request_id)
        status = cert.lookup_request_status(request_id)
        rej = cert.lookup_request_rejection(request_id)

        root = cert.root_hash()                # hash tree root
        msg  = cert.signed_message()           # domain_sep('ic-state-root') + root hash
        # der_key = cert.check_delegation(effective_canister_id)
        # bls_pubkey = extract_der(der_key)
        # cert.verify_signature(bls_pubkey)
    """

    IC_STATE_ROOT_DOMAIN_SEPARATOR = domain_sep("ic-state-root")

    def __init__(self, cert: Dict[str, Any]):
        tree = cert.get("tree", cert.get(b"tree"))
        if tree is None:
            raise ValueError("certificate missing 'tree'")
        self.tree: Any = tree

        sig_val = cert.get("signature", cert.get(b"signature"))
        self.signature: Optional[bytes] = bytes(sig_val) if sig_val is not None else None

        self.delegation: Optional[Dict[str, Any]] = cert.get(
            "delegation", cert.get(b"delegation")
        )

    def read_root_key(self) -> bytes:
        """Return the IC root DER-encoded public key."""
        return IC_ROOT_KEY

    # ---------------- HashTree lookup helpers ----------------

    def lookup_reply(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Optional[bytes]:
        path = [b"request_status", self._to_bytes(request_id), b"reply"]
        return self.lookup(path)

    def lookup_request_status(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[bytes]:
        path = [b"request_status", self._to_bytes(request_id), b"status"]
        return self.lookup(path)

    def lookup_reject_code(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[str]:
        path = [b"request_status", self._to_bytes(request_id), b"reject_code"]
        value = self.lookup(path)
        return None if value is None else str(value)

    def lookup_reject_message(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[str]:
        path = [b"request_status", self._to_bytes(request_id), b"reject_message"]
        value = self.lookup(path)
        return None if value is None else str(value)

    def lookup_error_code(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Optional[str]:
        path = [b"request_status", self._to_bytes(request_id), b"error_code"]
        value = self.lookup(path)
        return None if value is None else str(value)

    def lookup_request_rejection(
        self, request_id: Union[bytes, bytearray, memoryview, str]
    ) -> Dict[str, Optional[str]]:
        return {
            "reject_code": self.lookup_reject_code(request_id),
            "reject_message": self.lookup_reject_message(request_id),
            "error_code": self.lookup_error_code(request_id),
        }

    def lookup(self, path: Sequence[Union[str, bytes, bytearray, memoryview]]) -> Optional[bytes]:
        """lookup(path, self.tree)"""
        return self._lookup_path([self._to_bytes(x) for x in path], self.tree)

    def _lookup_path(self, path: Sequence[bytes], tree: Any) -> Optional[bytes]:
        if not path:
            # Only return the value if we land on a Leaf.
            if tree[0] == NodeId.Leaf.value:
                return bytes(tree[1])
            return None

        label = path[0]
        subtree = self._find_label(label, self._flatten_forks(tree))
        if subtree is None:
            return None
        return self._lookup_path(path[1:], subtree)

    def _flatten_forks(self, node: Any) -> List[Any]:
        if node[0] == NodeId.Empty.value:
            return []
        elif node[0] == NodeId.Fork.value:
            return self._flatten_forks(node[1]) + self._flatten_forks(node[2])
        else:
            return [node]

    def _find_label(self, label: bytes, trees: Sequence[Any]) -> Optional[Any]:
        for node in trees:
            if node[0] == NodeId.Labeled.value:
                node_label = bytes(node[1])
                if label == node_label:
                    return node[2]
        return None

    # ---------------- HashTree digest helpers ----------------

    def tree_digest(self, tree: Optional[Any] = None) -> bytes:
        """Compute the SHA-256 digest of a node according to the IC hashtree scheme."""
        if tree is None:
            tree = self.tree
        tag = tree[0]

        if tag == NodeId.Empty.value:
            return hashlib.sha256(DS_EMPTY).digest()

        elif tag == NodeId.Pruned.value:
            digest_bytes = bytes(tree[1])
            if len(digest_bytes) != 32:
                raise ValueError("Pruned node must carry a 32-byte digest")
            return digest_bytes

        elif tag == NodeId.Leaf.value:
            val = bytes(tree[1])
            return hashlib.sha256(DS_LEAF + val).digest()

        elif tag == NodeId.Labeled.value:
            label = bytes(tree[1])
            sub_digest = self.tree_digest(tree[2])
            return hashlib.sha256(DS_LABELED + label + sub_digest).digest()

        elif tag == NodeId.Fork.value:
            left = self.tree_digest(tree[1])
            right = self.tree_digest(tree[2])
            return hashlib.sha256(DS_FORK + left + right).digest()

        else:
            raise RuntimeError("unreachable")

    def root_hash(self) -> bytes:
        """Compute the hashtree root digest."""
        return self.tree_digest(self.tree)

    def signed_message(self) -> bytes:
        """Return domain separator + root hash (the message to be BLS-verified)."""
        return self.IC_STATE_ROOT_DOMAIN_SEPARATOR + self.root_hash()

    # ---------------- Delegation and verification ----------------

    def check_delegation(
        self,
        effective_canister_id: Union[bytes, bytearray, memoryview, str],
        *,
        must_verify: bool = True,
    ) -> bytes:
        """
        Equivalent to the Rust logic:
          - No delegation: return the IC root DER public key.
          - With delegation: decode the parent certificate (CBOR),
              * The parent must NOT itself contain a delegation.
              * If must_verify=True: cryptographically verify the parent with blst.
              * Ensure effective_canister_id is within canister_ranges.
              * Return the subnet DER public_key.
        """
        eff = self._to_bytes(effective_canister_id)

        # No delegation: use the root key.
        if self.delegation is None:
            return self.read_root_key()

        deleg = self.delegation
        subnet_id = bytes(deleg["subnet_id"])
        try:
            parent_cert_dict = cbor2.loads(deleg["certificate"])
        except Exception as e:
            raise ValueError("InvalidCborData: delegation.certificate") from e

        parent_cert = Certificate(parent_cert_dict)

        if parent_cert.delegation is not None:
            raise ValueError("CertificateHasTooManyDelegations")

        if must_verify:
            verified = parent_cert.verify_cert(eff, backend="blst")
            if verified is not True:
                raise ValueError("ParentCertificateVerificationFailed")

        # Check canister_ranges
        canister_range_path = [b"subnet", subnet_id, b"canister_ranges"]
        canister_range = parent_cert.lookup(canister_range_path)
        if canister_range is None:
            raise ValueError("Missing canister_ranges in delegation certificate")

        try:
            ranges_raw = cbor2.loads(canister_range)
        except Exception as e:
            raise ValueError("InvalidCborData: canister_ranges") from e

        try:
            ranges = [(bytes(lo), bytes(hi)) for (lo, hi) in ranges_raw]
        except Exception as e:
            raise ValueError("InvalidCborData: ranges format") from e

        if not any(lo <= eff <= hi for (lo, hi) in ranges):
            raise ValueError("CertificateNotAuthorized")

        # Read subnet public key (DER)
        public_key_path = [b"subnet", subnet_id, b"public_key"]
        der_key = parent_cert.lookup(public_key_path)
        if der_key is None:
            raise ValueError("Missing public_key in delegation certificate")

        return der_key

    def verify_cert(self, effective_canister_id, *, backend: str = "auto"):
        """
        Follow the Rust verify_cert flow:
          - message = b'\\x0D' + 'ic-state-root' + root_hash
          - obtain DER key from delegation -> extract 96B G2 public key
          - verify BLS(min_sig) (G1 signature / G2 public key)
        backend:
          - "auto" / "blst": verify with blst (will raise if blst is unavailable)
          - "return_materials": return verification materials (skip cryptographic check)
        """
        if self.signature is None:
            raise ValueError("certificate missing signature")

        sig_bytes = bytes(self.signature)
        if len(sig_bytes) != 48:
            raise ValueError("invalid signature length (expect 48 bytes for G1)")

        root_hash = self.tree_digest()
        message = IC_STATE_ROOT_DOMAIN_SEPARATOR + root_hash

        must_verify_chain = backend != "return_materials"
        der_key = self.check_delegation(effective_canister_id, must_verify=must_verify_chain)
        bls_pubkey_96 = extract_der(der_key)

        if backend == "return_materials":
            return {
                "signature": sig_bytes,
                "message": message,
                "der_public_key": der_key,
                "bls_public_key": bls_pubkey_96,
            }

        if backend in ("auto", "blst"):
            ok = verify_bls_signature_blst(sig_bytes, message, bls_pubkey_96)
            if not ok:
                raise ValueError("CertificateVerificationFailed")
            return True

        raise ValueError(f"Unknown backend: {backend}")

    def assert_certificate_valid(
        self, effective_canister_id: Union[str, bytes, bytearray, memoryview]
    ) -> None:
        """
        Validate that this Certificate is valid for the effective_canister_id.
        - On success: return None.
        - On failure: raise an exception (parse/authorization/BLS failure, or missing blst).
        Always uses the 'blst' backend (will raise if blst is unavailable).
        """
        eid_bytes = _to_effective_canister_bytes(effective_canister_id)
        result = self.verify_cert(eid_bytes, backend="blst")
        if result is True:
            return
        if isinstance(result, str):
            raise RuntimeError(f"BLS backend unavailable: {result}")
        raise RuntimeError("invalid certificate: BLS verification failed")

    # ---------------- Timestamp verification ----------------

    def verify_cert_timestamp(self, ingress_expiry_ns: int) -> None:
        """
        Verify the certificate timestamp:
          - read the 'time' (nanoseconds) from the certificate
          - ensure |now - time| <= ingress_expiry_ns
        Raise ValueError if the skew exceeds the allowed window.
        """
        cert_time_ns = self.lookup_time()
        now_ns = time.time_ns()
        skew = abs(now_ns - cert_time_ns)
        if skew > int(ingress_expiry_ns):
            raise ValueError(
                f"CertificateOutdated: skew={skew}ns > allowed={ingress_expiry_ns}ns"
            )

    def lookup_time(self) -> int:
        """Read and decode the 'time' label from the hashtree (ULEB128, nanoseconds)."""
        data = self.lookup([b"time"])
        if data is None:
            raise ValueError("Missing 'time' in certificate")
        try:
            return leb128.u.decode(bytes(data))
        except Exception as e:
            raise ValueError("Invalid 'time' encoding (expected ULEB128)") from e

    # ---------------- Utilities ----------------

    @staticmethod
    def _to_bytes(x: Union[str, bytes, bytearray, memoryview]) -> bytes:
        if isinstance(x, str):
            return x.encode()
        if isinstance(x, (bytearray, memoryview)):
            return bytes(x)
        if isinstance(x, bytes):
            return x
        raise TypeError(f"expected bytes-like or str, got {type(x)}")


def _to_effective_canister_bytes(
    eid: Union[str, bytes, bytearray, memoryview]
) -> bytes:
    """
    Normalize an effective canister id into raw bytes:
      - str: parse IC textual format (with checksum) -> bytes
      - bytes/bytearray/memoryview: convert to bytes
    """
    if isinstance(eid, str):
        return Principal.from_str(eid).bytes
    if isinstance(eid, (bytes, bytearray, memoryview)):
        return bytes(eid)
    raise TypeError(f"unsupported effective_canister_id type: {type(eid)}")