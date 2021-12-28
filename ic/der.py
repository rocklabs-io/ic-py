# der publickey
from six import int2byte, b, text_type
import base64


def encodeLenBytes(l):
    if l <= 0x7f:
        return 1
    elif l <= 0xff:
        return 2
    elif l <= 0xffff:
        return 3
    elif l <= 0xffffff:
        return 4
    else:
        raise "Length out of bound(> 4 bytes)"

def encodeLen(buf, offset, l):
    if l <= 0x7f:
        buf[offset] = l
        return 1
    elif l <= 0xff:
        buf[offset] = 0x81
        buf[offset + 1] = l
        return 2
    elif l <= 0xffff:
        buf[offset] = 0x82
        buf[offset + 1] = l >> 8
        buf[offset + 2] = l
        return 3
    elif l <= 0xffffff:
        buf[offset] = 0x83
        buf[offset + 1] = l >> 16
        buf[offset + 2] = l >> 8
        buf[offset + 3] = l
        return 4
    else:
        raise "Length out of bound(> 4 bytes)"


def decodeLenBytes(buf, offset):
    if buf[offset] < 0x80: return 1
    if buf[offset] == 0x80: raise "Invalid length 0"
    if buf[offset] == 0x81: return 2
    if buf[offset] == 0x82: return 3
    if buf[offset] == 0x83: return 4
    raise "Length too long (> 4 bytes)"

def decodeLen(buf, offset):
    lenBytes = decodeLenBytes(buf, offset)
    if lenBytes == 1: return buf[offset]
    elif lenBytes == 2: return buf[offset + 1]
    elif lenBytes == 3: return (buf[offset + 1] << 8) + buf[offset + 2]
    elif lenBytes == 4:
        return (buf[offset + 1] << 16) + (buf[offset + 2] << 8) + buf[offset + 3]
    else:
        raise "Length too long (> 4 bytes)"

# A DER encoded `SEQUENCE(OID)` for DER-encoded-COSE
DER_COSE_OID = bytes.fromhex('300c060a2b0601040183b8430101')
#A DER encoded `SEQUENCE(OID)` for the Ed25519 algorithm
ED25519_OID = bytes.fromhex('300506032b6570')
# A DER encoded `SEQUENCE(OID)` for secp256k1 with the ECDSA algorithm
SECP256K1_OID = bytes.fromhex('301006072a8648ce3d020106052b8104000a')

'''
@param payload The payload to encode as the bit string
@param oid The DER encoded (and SEQUENCE wrapped!) OID to tag the payload with
'''

def wrapDER(payload, oid):
    bitStringHeaderLength = 2 + encodeLenBytes(len(payload) + 1)
    length = len(oid) + bitStringHeaderLength + len(payload)
    offset = 0
    buf = bytearray(1 + encodeLenBytes(length) + length)

    buf[offset] = 0x30
    offset += 1
    offset += encodeLen(buf, offset, length)

    buf[offset: offset + len(oid)] = oid
    offset += len(oid)

    buf[offset] = 0x03
    offset += 1
    offset += encodeLen(buf, offset, len(payload) + 1 )

    buf[offset] = 0x00
    offset += 1
    buf[offset: offset +len(payload)] = payload

    return bytes(buf)

'''
  @param derEncoded The DER encoded and tagged data
  @param oid The DER encoded (and SEQUENCE wrapped!) expected OID
  @returns The unwrapped payload
'''

def unwrapDER(derEncoded, oid):
    offset = 0
    if derEncoded[offset] != 0x30:
        raise "Expected: sequence"
    offset += 1
    offset += decodeLenBytes(derEncoded, offset)

    if derEncoded[offset: offset + len(oid)] != oid:
        raise "Not the expected OID."

    offset += len(oid)

    if derEncoded[offset] != 0x03:
        raise "Excepted: bit string"
    offset += 1
    payloadLen = decodeLen(derEncoded, offset) - 1

    offset += decodeLenBytes(derEncoded, offset)
    if derEncoded[offset] !=0x00:
        raise "Excepted: 0 padding"
    offset += 1

    res = derEncoded[offset:]
    if payloadLen != len(res):
        raise "`DER payload mismatch: Expected length {}, actual length {}".format(payloadLen, len(res))
    
    return res


def toDer(publicKey, t):
    if type(publicKey) == str:
        pub = bytes.fromhex(publicKey)
    elif type(publicKey) == bytes:
        pub = publicKey
    else:
        raise "public key is supposed to be bytes or hex string"
    if t == 'secp256k1':
        oid = SECP256K1_OID
    elif t == 'ed25519':
        oid = ED25519_OID
    else:
        raise "Now only support secp256k1 and ed25519"
    return wrapDER(pub, oid)

def fromDer(der, t):
    if t == 'secp256k1':
        oid = SECP256K1_OID
    elif t == 'ed25519':
        oid = ED25519_OID
    else:
        raise "Now only support secp256k1 and ed25519"
    assert(type(der) == bytes)
    return unwrapDER(der, oid)

def unpem(pem):
    if isinstance(pem, text_type):  # pragma: no branch
        pem = pem.encode()

    d = b("").join(
        [
            l.strip()
            for l in pem.split(b("\n"))
            if l and not l.startswith(b("-----"))
        ]
    )
    pkcs = base64.b64decode(d).hex()
    version = pkcs[:10]
    if version == '302e020100':
        privateKeyAlgorithm = pkcs[10:32]
        privateKey, publicKey = pkcs[32:], None
        return privateKey, publicKey
    elif version == '3053020101':
        privateKeyAlgorithm = pkcs[10:32]
        privateKey = pkcs[32:96]
        attributes = pkcs[96:106]
        publicKey = pkcs[106:]
        return privateKey, publicKey
    else:
        raise "Wrong pem format!"


def topem(der, name):
    b64 = base64.b64encode(der)
    lines = [("-----BEGIN %s-----\n" % name).encode()]
    lines.extend(
        [b64[start : start + 64] + b("\n") for start in range(0, len(b64), 64)]
    )
    lines.append(("-----END %s-----\n" % name).encode())
    return b("").join(lines)