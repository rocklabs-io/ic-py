# reference: https://smartcontracts.org/docs/interface-spec/index.html#certification

'''
A certificate consists of:
    - a tree
    - a signature on the tree root hash valid under some public key
    - an optional delegation that links that public key to root public key.

Certificate = {
  tree : HashTree
  signature : Signature
  delegation : NoDelegation | Delegation
}
HashTree
  = Empty
  | Fork HashTree HashTree
  | Labeled Label HashTree
  | Leaf blob
  | Pruned Hash
Label = Blob
Hash = Blob
Signature = Blob

Lookup:

    lookup(path, cert) = lookup_path(path, cert.tree)

    lookup_path([], Empty) = Absent
    lookup_path([], Leaf v) = v
    lookup_path([], Pruned _) = Unknown
    lookup_path([], Labeled _ _) = Error
    lookup_path([], Fork _ _) = Error

    lookup_path(l::ls, tree) =
      match find_label(l, flatten_forks(tree)) with
      | Absent -> Absent
      | Unknown -> Unknown
      | Error -> Error
      | Found subtree -> lookup_path ls subtree

    flatten_forks(Empty) = []
    flatten_forks(Fork t1 t2) = flatten_forks(t1) · flatten_forks(t2)
    flatten_forks(t) = [t]

    find_label(l, _ · Labeled l1 t · _)                | l == l1     = Found t
    find_label(l, _ · Labeled l1 _ · Labeled l2 _ · _) | l1 < l < l2 = Absent
    find_label(l,                    Labeled l2 _ · _) |      l < l2 = Absent
    find_label(l, _ · Labeled l1 _ )                   | l1 < l      = Absent
    find_label(l, [])                                                = Absent
    find_label(l, _)                                                 = Unknown
'''
import hashlib
import cbor2
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union

class NodeId(Enum):
    Empty = 0
    Fork = 1
    Labeled = 2
    Leaf = 3
    Pruned = 4


def domain_sep(s: str) -> bytes:
    b = s.encode('utf-8')
    if len(b) > 255:
        raise ValueError("domain separator too long")
    return bytes([len(b)]) + b

IC_STATE_ROOT_DOMAIN_SEPARATOR = b"\x0Dic-state-root"
IC_BLS_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"  # 与 IC Rust 实现一致
IC_ROOT_KEY = bytes.fromhex(
    "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100"
    "814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd5"
    "46d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d1450"
    "5ffd7484b01291091c5f87b98883463f98091a0baaae"
)
DS_EMPTY   = domain_sep('ic-hashtree-empty')
DS_FORK    = domain_sep('ic-hashtree-fork')
DS_LABELED = domain_sep('ic-hashtree-labeled')
DS_LEAF    = domain_sep('ic-hashtree-leaf')
DER_PREFIX = bytes.fromhex(
    "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100"
)
KEY_LEN = 96


class BlstUnavailable(RuntimeError):
    """Raised when the runtime doesn't provide the official 'blst' Python binding."""


def ensure_blst_available() -> "object":
    """
    确认宿主环境具备官方 blst 绑定，并返回 blst 模块。
    - 未安装：抛 BlstUnavailable，包含清晰安装指引
    - API 不完整：抛 BlstUnavailable，提示可能导入了错误的同名模块
    """
    try:
        import blst as _blst  # 官方 supranational/blst SWIG 绑定
    except ModuleNotFoundError as e:
        raise BlstUnavailable(
            "BLS verification requires the official 'blst' Python binding.\n"
            "It was not found in the current environment.\n\n"
            "Install steps (macOS/Linux):\n"
            "  1) git clone https://github.com/supranational/blst\n"
            "  2) cd blst/bindings/python && python3 run.me\n"
            "  3) Ensure this directory is on PYTHONPATH or copy blst.py and _blst*.so into site-packages\n\n"
            "For Apple Silicon (M1/M2), if you hit ABI issues: export BLST_PORTABLE=1 before running run.me"
        ) from e

    # 简单 API 自检，避免被其它同名模块“遮蔽”
    required = ("P1_Affine", "P2_Affine", "Pairing", "BLST_ERROR")
    if not all(hasattr(_blst, name) for name in required):
        raise BlstUnavailable(
            "A module named 'blst' was imported, but it does not expose the expected API.\n"
            "Make sure you're using the official supranational/blst SWIG binding, not a different package."
        )
    return _blst


def verify_bls_signature_blst(signature: bytes, message: bytes, public_key_96: bytes) -> bool:
    # 兜底导入：优先 blst，其次 pyblst
    try:
        import blst as _blst
    except ModuleNotFoundError:
        import pyblst as _blst  # type: ignore

    signature = bytes(signature)
    public_key_96 = bytes(public_key_96)

    # 先做长度/flag 快速校验（不是必须，但能提早发现问题）
    if len(signature) != 48 or len(public_key_96) != 96:
        return False
    # 压缩串的第1字节应带压缩标志位（0x80）
    if (signature[0] & 0x80) == 0 or (public_key_96[0] & 0x80) == 0:
        return False

    # 关键：使用 from_compressed（pyblst 一般需要）
    try:
        if hasattr(_blst.P1_Affine, "from_compressed"):
            sig_aff = _blst.P1_Affine.from_compressed(signature)
        else:
            sig_aff = _blst.P1_Affine(signature)  # 某些发行版构造器本身支持压缩
    except Exception as e:
        # 临时调试时可以 print(e) 看具体原因（非曲线上/子群检查不过/编码无效）
        print(e)
        return False

    try:
        if hasattr(_blst.P2_Affine, "from_compressed"):
            pk_aff = _blst.P2_Affine.from_compressed(public_key_96)
        else:
            pk_aff = _blst.P2_Affine(public_key_96)
    except Exception as e:
        return False

    # 方案 A：core_verify（和你原来一致）
    err = sig_aff.core_verify(pk_aff, True, message, IC_BLS_DST, None)
    if err == _blst.BLST_SUCCESS:
        return True


    # 方案 B（可选）：用 Pairing 做一次独立验证，帮助诊断
    try:
        pairing = _blst.Pairing(True, IC_BLS_DST)
        pairing.aggregate(pk_aff, sig_aff, message, None)
        return pairing.finalverify()
    except Exception:
        return False

def extract_der(der: bytes) -> bytes:
    if not isinstance(der, (bytes, bytearray, memoryview)):
        raise TypeError("der must be a bytes-like object")
    der = bytes(der)

    expected_len = len(DER_PREFIX) + KEY_LEN  # 37 + 96 = 133
    if len(der) != expected_len:
        raise ValueError(
            f"BLS DER-encoded public key must be {expected_len} bytes long (got {len(der)})"
        )

    prefix = der[:len(DER_PREFIX)]
    if prefix != DER_PREFIX:
        raise ValueError(
            f"BLS DER-encoded public key prefix mismatch: "
            f"expected {DER_PREFIX.hex()}, got {prefix.hex()}"
        )

    return der[len(DER_PREFIX):]  # 96 bytes of key data

class Certificate:
    """
    Usage：
        cert = Certificate(certificate_dict)
        reply = cert.lookup_reply(request_id)
        status = cert.lookup_request_status(request_id)
        rej = cert.lookup_request_rejection(request_id)

        root = cert.root_hash()                # HashTree 的根哈希
        msg  = cert.signed_message()           # domain_sep("ic-state-root") + root_hash
        # der_key = cert.check_delegation(effective_canister_id)  # TODO: 你后续实现
        # bls_pubkey = extract_der(der_key)
        # cert.verify_signature(bls_pubkey)    # TODO: 你后续接入 BLS 校验
    """

    IC_STATE_ROOT_DOMAIN_SEPARATOR = domain_sep("ic-state-root")

    def __init__(self, cert: Dict[str, Any]):
        tree = cert.get("tree", cert.get(b"tree"))
        if tree is None:
            raise ValueError("certificate missing 'tree'")
        self.tree: Any = tree

        sig_val = cert.get("signature", cert.get(b"signature"))
        self.signature: Optional[bytes] = bytes(sig_val) if sig_val is not None else None

        self.delegation: Optional[Dict[str, Any]] = cert.get("delegation", cert.get(b"delegation"))

    def read_root_key(self) -> bytes:
        return IC_ROOT_KEY

    def lookup_reply(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Optional[bytes]:
        path = [b'request_status', self._to_bytes(request_id), b'reply']
        return self.lookup(path)

    def lookup_request_status(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Optional[bytes]:
        path = [b'request_status', self._to_bytes(request_id), b'status']
        return self.lookup(path)

    def lookup_reject_code(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Optional[str]:
        path = [b'request_status', self._to_bytes(request_id), b'reject_code']
        v = self.lookup(path)
        return None if v is None else str(v)

    def lookup_reject_message(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Optional[str]:
        path = [b'request_status', self._to_bytes(request_id), b'reject_message']
        v = self.lookup(path)
        return None if v is None else str(v)

    def lookup_error_code(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Optional[str]:
        path = [b'request_status', self._to_bytes(request_id), b'error_code']
        v = self.lookup(path)
        return None if v is None else str(v)

    def lookup_request_rejection(self, request_id: Union[bytes, bytearray, memoryview, str]) -> Dict[str, Optional[str]]:
        return {
            "reject_code":    self.lookup_reject_code(request_id),
            "reject_message": self.lookup_reject_message(request_id),
            "error_code":     self.lookup_error_code(request_id),
        }

    def lookup(self, path: Sequence[Union[str, bytes, bytearray, memoryview]]) -> Optional[bytes]:
        """lookup(path, self.tree)"""
        return self._lookup_path([self._to_bytes(x) for x in path], self.tree)

    def _lookup_path(self, path: Sequence[bytes], tree: Any) -> Optional[bytes]:
        if not path:
            # TODO：规范[] 命中 Leaf 才返回值；其它节点返回 Absent/Unknown。
            if tree[0] == NodeId.Leaf.value:
                return bytes(tree[1])
            else:
                return None

        label = path[0]
        subtree = self._find_label(label, self._flatten_forks(tree))
        if subtree is None:
            return None
        return self._lookup_path(path[1:], subtree)

    def _flatten_forks(self, t: Any) -> List[Any]:
        if t[0] == NodeId.Empty.value:
            return []
        elif t[0] == NodeId.Fork.value:
            return self._flatten_forks(t[1]) + self._flatten_forks(t[2])
        else:
            return [t]

    def _find_label(self, l: bytes, trees: Sequence[Any]) -> Optional[Any]:
        for t in trees:
            if t[0] == NodeId.Labeled.value:
                p = bytes(t[1])
                if l == p:
                    return t[2]
        return None

    def tree_digest(self, tree: Optional[Any] = None) -> bytes:
        if tree is None:
            tree = self.tree
        tag = tree[0]

        if tag == NodeId.Empty.value:
            return hashlib.sha256(DS_EMPTY).digest()

        elif tag == NodeId.Pruned.value:
            h = bytes(tree[1])
            if len(h) != 32:
                raise ValueError("Pruned node must carry a 32-byte digest")
            return h

        elif tag == NodeId.Leaf.value:
            v = bytes(tree[1])
            return hashlib.sha256(DS_LEAF + v).digest()

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
        return self.tree_digest(self.tree)

    def signed_message(self) -> bytes:
        """域分隔符 + 根哈希，用于 BLS 验签的消息"""
        return self.IC_STATE_ROOT_DOMAIN_SEPARATOR + self.root_hash()

    def check_delegation(
            self,
            effective_canister_id: Union[bytes, bytearray, memoryview, str],
            *,
            must_verify: bool = True,  # ⭐ 新增：是否必须对父证书做加密验签（默认 True，符合 Rust）
    ) -> bytes:
        """
        等价于 Rust 版逻辑：
          - 无 delegation：返回主网根 DER 公钥
          - 有 delegation：解析 delegation.certificate（CBOR）为父证书
              * 父证书不得再含有 delegation（只允许一层）
              * 若 must_verify=True：对父证书做加密验签（blst）
              * 校验 effective_canister_id 是否落在 canister_ranges 里
              * 取 subnet public_key（DER）并返回

        注：
          - must_verify=False 用于“联调/只取材料”场景（与生产安全要求相悖，谨慎使用）
        """
        eff = self._to_bytes(effective_canister_id)

        # 1) 无委托：返回主网根公钥（DER）
        if self.delegation is None:
            return self.read_root_key()

        # 2) 解析父证书
        d = self.delegation
        subnet_id = bytes(d["subnet_id"])
        try:
            parent_cert_dict = cbor2.loads(d["certificate"])
        except Exception as e:
            raise ValueError("InvalidCborData: delegation.certificate") from e

        parent_cert = Certificate(parent_cert_dict)

        # 3) 父证书不得再含有 delegation
        if parent_cert.delegation is not None:
            raise ValueError("CertificateHasTooManyDelegations")

        # 4) （⭐ 新增）父证书加密验签（与 Rust 等价）
        if must_verify:
            # 要求严格验证：如未安装 blst 或验证失败，将抛出异常
            # must_verify=False 时跳过（仅用于联调；不安全）
            ok = parent_cert.verify(eff, backend="blst")
            if ok is not True:
                # parent_cert.verify("blst") 正常通过会返回 True；不应返回 dict
                raise ValueError("ParentCertificateVerificationFailed")

        # 5) 读取 canister_ranges，并校验授权范围
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

        # 6) 读取 subnet public_key（DER）
        public_key_path = [b"subnet", subnet_id, b"public_key"]
        der_key = parent_cert.lookup(public_key_path)
        if der_key is None:
            raise ValueError("Missing public_key in delegation certificate")

        return der_key

    def verify(self, effective_canister_id, *, backend: str = "auto"):
        """
        对应 Rust verify_cert：
          - msg = b'\x0D' + 'ic-state-root' + root_hash
          - 从 delegation 拿 DER 公钥 -> 提取 96B G2 公钥
          - 用 BLS(min_sig) 验签（G1签名 / G2公钥）
        backend:
          - "auto": 强制验证整条链；若环境缺 blst，将抛错（与 Rust 语义一致）
          - "blst": 同上，强制用 blst 验证
          - "return_materials": 仅返回验签材料（会跳过父证书验证；仅用于联调）
        """
        if self.signature is None:
            raise ValueError("certificate missing signature")
        sig = bytes(self.signature)
        if len(sig) != 48:
            raise ValueError("invalid signature length (expect 48 bytes for G1)")

        sig = bytes(self.signature)
        root_hash = self.tree_digest()
        msg = b"\x0Dic-state-root" + root_hash  # 与 Rust 常量完全一致

        # （⭐ 修改）严格语义：除非是 return_materials，否则必须验证父证书
        must_verify_chain = (backend != "return_materials")

        # 若必须验证，则在 check_delegation 内部会 parent_cert.verify(..., "blst")
        der_key = self.check_delegation(effective_canister_id, must_verify=must_verify_chain)
        bls_pubkey_96 = extract_der(der_key)

        if backend == "return_materials":
            return {
                "signature": sig,
                "message": msg,
                "der_public_key": der_key,
                "bls_public_key": bls_pubkey_96,
            }

        if backend in ("auto", "blst"):
            # 用 blst 做最终验签
            ok = verify_bls_signature_blst(sig, msg, bls_pubkey_96)  # 若没装 blst，会抛 ModuleNotFoundError
            if not ok:
                raise ValueError("CertificateVerificationFailed")
            return True

        raise ValueError(f"Unknown backend: {backend}")

    @staticmethod
    def _to_bytes(x: Union[str, bytes, bytearray, memoryview]) -> bytes:
        if isinstance(x, str):
            return x.encode()
        if isinstance(x, (bytearray, memoryview)):
            return bytes(x)
        if isinstance(x, bytes):
            return x
        raise TypeError(f"expected bytes-like or str, got {type(x)}")


# TODO: 单元测试