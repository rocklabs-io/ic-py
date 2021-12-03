import leb128
import hashlib

def to_request_id(d):
    if not isinstance(d, dict):
        print(d)
        pass
    vec = []
    for k, v in d.items():
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
