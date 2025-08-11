def extract_der(der: bytes):
    der_prefix = bytes.fromhex('308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100')
    key_len = 96
    expectedLength = len(der_prefix) + key_len
    if len(der) != expectedLength:
        raise f"BLS DER-encoded public key must be {expectedLength} bytes long"
    prefix = der[:len(der_prefix)]
    if prefix != der_prefix:
        raise f"BLS DER-encoded public key is invalid. Expect the following prefix: {der_prefix}, but get {prefix}"
    return der[len(der_prefix):]


