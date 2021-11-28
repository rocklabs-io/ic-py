import hashlib

def to_request_id(d):
    print(d)
    if not isinstance(d, dict):
        pass
    vec = []
    for k, v in d.items():
        if isinstance(v, int):
            v = str(v).encode()
        if not isinstance(k, bytes):
            k = k.encode()
        if not isinstance(v, bytes):
            v = v.encode()
        h_k = hashlib.sha256(k).digest()
        h_v = hashlib.sha256(v).digest()
        vec.append(h_k + h_v)
    s = b''.join(sorted(vec))
    return hashlib.sha256(s).digest()
