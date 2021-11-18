
# identity type: https://github.com/dfinity/agent-rs/tree/main/ic-agent/src/identity

import ecdsa
import hashlib
from principal import Principal

# TODO: add ed25519
class Identity:
    def __init__(self, privkey = "", anonymous = False):
        self.anonymous = anonymous
        if anonymous:
            return
        if len(privkey) > 0:
            self._privkey = privkey
            self.sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
            self.vk = self.sk.get_verifying_key()
            self._pubkey = self.vk.to_string().hex()
            self._der_pubkey = self.vk.to_der().hex()
        else:
            self.sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
            self._privkey = self.sk.to_string().hex()
            self.vk = self.sk.get_verifying_key()
            self._pubkey = self.vk.to_string().hex()
            self._der_pubkey = self.vk.to_der().hex()

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

    def __repr__(self):
        return "Identity(" + self._privkey + ", " + self._pubkey + ")"

    def __str__(self):
        return "(" + self._privkey + ", " + self._pubkey + ")"
