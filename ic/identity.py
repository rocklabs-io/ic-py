import hashlib
import json

from ecdsa.curves import Ed25519, SECP256k1
from .principal import Principal
import ecdsa
from mnemonic import Mnemonic

class Identity:
    def __init__(self, privkey = "", type = "ed25519", anonymous = False):
        privkey = bytes(bytearray.fromhex(privkey))
        self.anonymous = anonymous
        if anonymous:
            return
        self.key_type = type
        if type == 'secp256k1':
            if len(privkey) > 0:
                self.sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
            else:
                self.sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
            self._privkey = self.sk.to_string().hex()
            self.vk = self.sk.get_verifying_key()
            self._pubkey = self.vk.to_string().hex()
            self._der_pubkey = self.vk.to_der()
        elif type == 'ed25519':
            if len(privkey) > 0:
                self.sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.Ed25519)
            else:
                self.sk = ecdsa.SigningKey.generate(curve=ecdsa.Ed25519)
            self._privkey = self.sk.to_string().hex()
            self.vk = self.sk.get_verifying_key()
            self._pubkey = self.vk.to_string().hex()
            self._der_pubkey = self.vk.to_der()
        else:
            raise 'unsupported identity type'

    @staticmethod
    def from_seed(mnemonic: str):
        mnemo = Mnemonic('english')
        seed = mnemo.to_seed(mnemonic).hex()
        privkey = seed[:64]
        type = "ed25519"
        return Identity(privkey=privkey, type=type)

    @staticmethod
    def from_pem(pem: str):
        key = ecdsa.SigningKey.from_pem(pem)
        privkey = key.to_string().hex()
        type = "unknown"
        if key.curve == Ed25519:
            type = 'ed25519'
        elif key.curve == SECP256k1:
            type = 'secp256k1'
        return Identity(privkey=privkey, type=type)

    def to_pem(self):
        pem = self.sk.to_pem(format="pkcs8")
        return pem

    def sender(self):
        if self.anonymous:
            return Principal.anonymous()
        return Principal.self_authenticating(self._der_pubkey)

    def sign(self, msg: bytes):
        if self.anonymous:
            return (None, None)
        if self.key_type == 'ed25519':
            sig = self.sk.sign(msg)
            return (self._der_pubkey, sig)
        elif self.key_type == 'secp256k1':
            sig = self.sk.sign(msg)
            return (self._der_pubkey, sig)

    @property
    def privkey(self):
        return self._privkey

    @property
    def pubkey(self):
        return self._pubkey

    @property
    def der_pubkey(self):
        return self._der_pubkey

    def __repr__(self):
        return "Identity(" + self.key_type + ', ' + self._privkey + ", " + self._pubkey + ")"

    def __str__(self):
        return "(" + self.key_type + ', ' + self._privkey + ", " + self._pubkey + ")"

def _map_delegation(delegation: dict):
        return {
            "delegation": {
                "expiration": int(delegation["delegation"]["expiration"], 16),
                "pubkey": bytes.fromhex(delegation["delegation"]["pubkey"])
            },
            "signature": bytes.fromhex(delegation["signature"])
        }

class DelegateIdentity:
    def __init__(self, identity: Identity, delegation):
        self.identity = identity
        self._delegations = [_map_delegation(d) for d in delegation['delegations']]
        self._der_pubkey = bytes.fromhex(delegation["publicKey"])

    def sign(self, msg: bytes):
        return self.identity.sign(msg)

    def sender(self):
        return Principal.self_authenticating(self._der_pubkey)

    @property
    def delegations(self):
        return self._delegations

    @property
    def der_pubkey(self):
        return self._der_pubkey

    @staticmethod
    def from_json(ic_identity: str, ic_delegation: str):
        parsed_ic_identity = json.loads(ic_identity)
        parsed_ic_delegation = json.loads(ic_delegation)

        return DelegateIdentity(
            Identity(parsed_ic_identity[1][:64]),
            parsed_ic_delegation
        )

    def __repr__(self):
        return "DelegationIdentity(" + self.identity + ',\n' + self.delegation + ")"

    def __str__(self):
        return "(" + self.identity + ',\n' + self.delegation + ")"