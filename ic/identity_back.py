import ecdsa
import hashlib
# from .der import *
from .principal import Principal

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
            self._der_pubkey = self.vk.to_der().hex()
        elif type == 'ed25519':
            if len(privkey) > 0:
                self.sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.Ed25519)
                self.vk = self.sk.get_verifying_key() 
            else:
                self.sk = ecdsa.SigningKey.generate(curve=ecdsa.Ed25519)
            self._privkey = self.sk.to_string().hex()
            self.vk = self.sk.get_verifying_key()
            self._pubkey = self.vk.to_string().hex()
            self._der_pubkey = self.vk.to_der().hex()
        else:
            raise 'unsupported identity type'

    @staticmethod
    def from_pem(pem: str):
        sk = ecdsa.SigningKey.from_pem(pem)
        return Identity(sk.to_string().hex())

    def to_pem(self):
        return self.sk.to_pem()

    def sender(self):
        if self.anonymous:
            return Principal.anonymous()
        return Principal.self_authenticating(self._der_pubkey)

    def sign(self, msg: bytes):
        if self.anonymous:
            return (None, None)
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
