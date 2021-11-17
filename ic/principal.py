
# principal type: https://github.com/dfinity/ic-types/blob/main/src/principal.rs

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
    Unassigned

class Principal(Object):
    def __init__(self, bytes = [0 * MAX_LENGTH_IN_BYTES]):
        self.len = len(bytes) 
        self.bytes = bytes 

    @staticmethod
    def management_canister():
        return Principal()

    @staticmethod
    def self_authenticating(pubkey):
        hash_ = hashlib.sha224(pubkey)
        hash_.append(PrincipalClass.SelfAuthenticating.value)
        return Principal(len(hash_), hash_)

    @staticmethod
    def anonymous():
        pass

    def from_str(): 
        pass

    def from_bytes():
        pass

    def to_bytes():
        pass

    def to_str():
        pass
