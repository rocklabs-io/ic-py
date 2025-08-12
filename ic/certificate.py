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
        # 必要字段
        self.tree: Any = cert["tree"]
        self.signature: bytes = bytes(cert["signature"])
        self.delegation: Optional[Dict[str, Any]] = cert.get("delegation")

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

    def digest(self, tree: Optional[Any] = None) -> bytes:
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
            sub_digest = self.digest(tree[2])
            return hashlib.sha256(DS_LABELED + label + sub_digest).digest()

        elif tag == NodeId.Fork.value:
            left = self.digest(tree[1])
            right = self.digest(tree[2])
            return hashlib.sha256(DS_FORK + left + right).digest()

        else:
            raise RuntimeError("unreachable")

    def root_hash(self) -> bytes:
        return self.digest(self.tree)

    def signed_message(self) -> bytes:
        """域分隔符 + 根哈希，用于 BLS 验签的消息"""
        return self.IC_STATE_ROOT_DOMAIN_SEPARATOR + self.root_hash()

    # TODO: check delegation
    def check_delegation(self, effective_canister_id: Any) -> bytes:
        """
        TODO: 解析/验证 self.delegation，返回 DER 编码的 BLS 公钥（bytes）
        """
        raise NotImplementedError("check_delegation(...) is not implemented yet")

    def prepare_for_verify(self, effective_canister_id: Any) -> Dict[str, bytes]:
        der_key = self.check_delegation(effective_canister_id)  # TODO
        bls_pubkey = extract_der(der_key)
        return {
            "signature": self.signature,
            "message": self.signed_message(),
            "bls_pubkey": bls_pubkey,
        }

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