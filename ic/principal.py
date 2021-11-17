
# principal type: https://github.com/dfinity/ic-types/blob/main/src/principal.rs

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
    def __init__(self):
        self.len = 0
        self.bytes = [0 * MAX_LENGTH_IN_BYTES]

    @static
    def management_canister():
        pass

    @static
    def self_authenticating(pubkey):
        pass

    def from_str(): 
        pass

    def from_bytes():
        pass

    def to_bytes():
        pass

    def to_str():
        pass
