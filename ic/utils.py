import leb128
import hashlib

def encode_list(l):
    ret = b''
    for item in l:
        v = item
        if isinstance(item, list):
            v = encode_list(item)
        if isinstance(item, int):
            v = bytes(leb128.u.encode(v))
        if isinstance(item, str):
            v = item.encode()
        ret += hashlib.sha256(v).digest()
    return ret

# used for sort record by key
def labelHash(s:str) -> int:
    #TODO input regulatization
    h = 0
    for c in s.encode():
        h = (h * 223 + c) % 2 ** 32
    return h


def to_request_id(d):
    if not isinstance(d, dict):
        print(d)
        pass
    vec = []
    for k, v in d.items():
        if isinstance(v, list):
            v = encode_list(v)
        if isinstance(v, int):
            v = bytes(leb128.u.encode(v))
        if not isinstance(k, bytes):
            k = k.encode()
        if not isinstance(v, bytes):
            v = v.encode()
        h_k = hashlib.sha256(k).digest()
        h_v = hashlib.sha256(v).digest()
        vec.append(h_k + h_v)
    s = b''.join(sorted(vec))
    return hashlib.sha256(s).digest()
