
# principal type: https://github.com/dfinity/ic-types/blob/main/src/principal.rs

import zlib
import math
import base64
import hashlib
from enum import Enum

CRC_LENGTH_IN_BYTES = 4
HASH_LENGTH_IN_BYTES = 28
MAX_LENGTH_IN_BYTES = 29

class PrincipalClass(Enum):
    OpaqueId = 1
    SelfAuthenticating = 2
    DerivedId = 3
    Anonymous = 4
    # Unassigned

class Principal:
    def __init__(self, bytes = b''):
        self._len = len(bytes) 
        self._bytes = bytes 
        self.hex = str(self._bytes.hex()).upper()
        
    @staticmethod
    def management_canister():
        return Principal()

    @staticmethod
    def self_authenticating(pubkey):
        if isinstance(pubkey, str):
            pubkey = pubkey.encode()
        hash_ = hashlib.sha224(pubkey).digest()
        hash_ += bytes([PrincipalClass.SelfAuthenticating.value])
        return Principal(bytes = hash_)

    @staticmethod
    def anonymous():
        return Principal(bytes = b'\x04')

    @property
    def len(self):
        return self._len

    @property
    def bytes(self):
        return self._bytes

    @staticmethod
    def from_str(s): 
        s1 = s.replace('-', '')
        pad_len = math.ceil(len(s1) / 8) * 8 - len(s1)
        b = base64.b32decode(s1.upper().encode() + b'=' * pad_len)
        if len(b) < CRC_LENGTH_IN_BYTES:
            raise "principal length error"
        p = Principal(bytes = b[CRC_LENGTH_IN_BYTES:])
        if not p.to_str() == s:
            raise "principal format error"
        return p

    @staticmethod
    def from_hex(s):
        return Principal(bytes.fromhex(s.lower()))

    def to_str(self):
        checksum = zlib.crc32(self._bytes) & 0xFFFFFFFF
        b = b''
        b += checksum.to_bytes(CRC_LENGTH_IN_BYTES, byteorder='big')
        b += self.bytes
        s = base64.b32encode(b).decode('utf-8').lower().replace('=', '')
        ret = ''
        while len(s) > 5:
            ret += s[:5]
            ret += '-'
            s = s[5:]
        ret += s
        return ret

    def __repr__(self):
        return "Principal(" + self.to_str() + ")"

    def __str__(self):
        return self.to_str()
