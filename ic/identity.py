
# identity type: https://github.com/dfinity/agent-rs/tree/main/ic-agent/src/identity

import ecdsa
import hashlib
# from .der import *
from .principal import Principal

# TODO: complete ed25519 support
class Identity:
    def __init__(self, privkey = "", type = "secp256k1", anonymous = False):
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
                self.sk = ed25519.SigningKey(privkey.encode(), encoding='hex') 
                self.vk = self.sk.get_verifying_key() 
            else:
                (self.sk, self.vk) = ed25519.create_keypair()
            self._privkey = self.sk.to_ascii(encoding='hex')
            self._pubkey = self.vk.to_ascii(encoding='hex')
            # self._der_pubkey = 
        else:
            raise 'unsupported identity type'

    @staticmethod
    def from_pem(pem: str):
        if self.key_type == 'secp256k1':
            sk = ecdsa.SigningKey.from_pem(pem)
            return Identity(sk.to_string().hex())
        else:
            pass

    def to_pem(self):
        if self.key_type == 'secp256k1':
            return self.sk.to_pem()
        else:
            pass

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

    def __repr__(self):
        return "Identity(" + self.key_type + ', ' + self._privkey + ", " + self._pubkey + ")"

    def __str__(self):
        return "(" + self.key_type + ', ' + self._privkey + ", " + self._pubkey + ")"
