import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from .principal import Principal

class Identity:
    def __init__(self, privkey = "", type = "ed25519", anonymous = False):
        privkey = bytes(bytearray.fromhex(privkey))
        self.anonymous = anonymous
        if anonymous:
            return
        self.key_type = type
        if type == 'secp256k1':
            self.sk = ec.generate_private_key(ec.SECP256K1())
            self.vk = self.sk.public_key()
            self._privkey = self.sk.private_bytes(encoding=Encoding.DER, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption()).hex()
            self._pubkey = self.vk.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo).hex()
            self._der_pubkey = self.vk.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        elif type == 'ed25519':
            if len(privkey) > 0:
                self.sk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey)
            else:
                self.sk = ed25519.Ed25519PrivateKey.generate()
            self.vk = self.sk.public_key()
            self._privkey = self.sk.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()).hex()
            self._pubkey = self.vk.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw).hex()
            # der encoded public key, bytes
            self._der_pubkey = self.vk.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        else:
            raise 'unsupported identity type'

    @staticmethod
    def from_pem(pem: str):
        key = load_pem_private_key(pem.encode(), password=None)
        privkey = key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()).hex()
        return Identity(privkey=privkey, type='ed25519')

    def to_pem(self):
        pem = self.sk.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
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
            sig = self.sk.sign(msg, ec.ECDSA(hashes.SHA256()))
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
