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
from enum import Enum
from .utils import blsVerify
import leb128
import hashlib
import cbor2

class NodeId(Enum):
    Empty = 0
    Fork = 1
    Labeled = 2
    Leaf = 3
    Pruned = 4


def lookup_path(path, tree):
    offset = 0
    if len(path) == 0:
        if tree[0] == NodeId.Leaf.value:
          return tree[1]
        else:
          return None
    label = path[0].encode() if type(path[0]) == str else path[0]
    t = find_label(label, flatten_forks(tree))
    if t:
      offset +=1
      return lookup_path(path[offset:], t)


def flatten_forks(t):
  if t[0] == NodeId.Empty.value:
      return []
  elif t[0] == NodeId.Fork.value:
      val1 = flatten_forks(t[1])
      val2 = flatten_forks(t[2])
      val1.extend(val2)
      return val1
  else:
      return [t]

def find_label(l, trees):
    if len(trees) == 0:
        return None
    for t in trees:
        if t[0] == NodeId.Labeled.value:
            p = t[1]
            if l == p :
                return t[2]

def domain_seq(s: str):
    return bytes(leb128.u.encode(len(s)) + s.encode())


def reconstruct(tree):
    if tree[0] == NodeId.Empty.value:
        return hashlib.sha256(domain_seq('ic-hashtree-empty')).digest()
    elif tree[0] == NodeId.Pruned.value:
        return tree[1]
    elif tree[0] == NodeId.Leaf.value:
        return hashlib.sha256(domain_seq('ic-hashtree-leaf') + tree[1]).digest()
    elif tree[0] == NodeId.Labeled.value:
        res = reconstruct(tree[2])
        return hashlib.sha256(domain_seq('ic-hashtree-labeled') + tree[1] + res).digest()
    elif tree[0] == NodeId.Fork.value:
        res1 = reconstruct(tree[1])
        res2 = reconstruct(tree[2])
        return hashlib.sha256(domain_seq('ic-hashtree-fork') + res1 + res2).digest()
    else:
        raise "unreachable"

def extract_der(der: bytes):
    der_prefix = bytes.fromhex('308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100')
    key_len = 96
    expectedLength = len(der_prefix) + key_len
    if (len(der) != expectedLength):
        raise f"BLS DER-encoded public key must be {expectedLength} bytes long"
    prefix = der[:len(der_prefix)]
    if(prefix != der_prefix):
        raise f"BLS DER-encoded public key is invalid. Expect the following prefix: {der_prefix}, but get {prefix}"
    return der[len(der_prefix):]


class Certificate(object):
    def __init__(self, cert, agent) -> None:
        super().__init__()
        self.cert = cert
        self.agent = agent
        self.root_key = None
        self.verified = False
    
    def lookup(self, path):
        if not self.verified:
            raise "Cannot lookup unverified certificate. Call 'verify()' first."
        return lookup_path(path, self.cert['tree'])

    def verify(self):
        rootHash = reconstruct(self.cert.get('tree'))
        derKey = self._checkDelegation(self.cert.get('delegation'))
        sig = self.cert['signature']
        key = extract_der(derKey)
        msg = domain_seq('ic-state-root') + rootHash
        res = blsVerify(key, sig, msg)
        self.verified = res
        return res

    
    def _checkDelegation(self, delegation=None):
        if delegation is None:
            if self.root_key is None:
                if self.agent.root_key:
                    self.root_key = self.agent.root_key
                    return self.root_key
                else:
                    raise 'Agent does not have a rootKey.'
            return self.root_key
        cert = Certificate(cbor2.loads(delegation['certificate']), self.agent)
        if not (cert.verify()):
            raise 'fail to verify delegation certificate'

        lookup = cert.lookup(['subnet', delegation['subnet_id'], 'public_key'])
        if not lookup:
            subnet = hex(delegation['subnet_id'])
            raise f'Could not find subnet key for subnet 0x{subnet}'
        return lookup 

if __name__=='__main__':
    tree = [1, [4, b'W\xb4\x1b\x00\xc9x\xc0\xcb\\\xf4\xb6\xa1\xbbE\\\x9fr\xe2\x1a8\xd2bE\x14\x11\xab:\xb5\x1b`\x98\x9d'], [1, [4, b'\xac>_\x80\xeb.$\x9c\x00\xbc\x12\xce&!^\xa8,i\x08\xaeH\x8e\x9ce9\x87\xbahGPo\xe6'], [2, b'time', [3, b'\xd2\xac\xd3\x8a\xfc\xa0\xd0\xe0\x16']]]]
    tree2 = [1, [4, b'5J\xe2\x98A\x8d5\xc8\xe6\x94V\xc9\x90\x87\x00\xc9:\xe1\xb3i\x91fS\xc0udD\x19mQ\x1c\x85'], [1, [4, b'\xac>_\x80\xeb.$\x9c\x00\xbc\x12\xce&!^\xa8,i\x08\xaeH\x8e\x9ce9\x87\xbahGPo\xe6'], [2, b'time', [3, b'\xe7\xfc\xcf\x90\x87\x85\xd0\xe0\x16']]]]
    path = b'time'
    print(lookup_path([path], tree))