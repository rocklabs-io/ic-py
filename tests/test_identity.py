from ic.identity import *

class TestIdentity:

    def test_ed25519_privatekey(self):
        iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        assert iden.key_type == 'ed25519'
        assert iden.pubkey == 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf'

    def test_secp256k1_privatekey(self):
        pass

    def test_ed25519_frompem(self):
        pem = """
        -----BEGIN PRIVATE KEY-----
        MFMCAQEwBQYDK2VwBCIEIGQqNAZlORmn1k4QrYz1FvO4fOQowS3GXQMqRKDzmx9P
        oSMDIQCrO5iGM5hnLWrHavywoXekAoXPpYRuB0Dr6DjZF6FZkg==
        -----END PRIVATE KEY-----"""
        iden = Identity.from_pem(pem)
        assert iden.key_type == 'ed25519'
        assert iden.privkey == '642a3406653919a7d64e10ad8cf516f3b87ce428c12dc65d032a44a0f39b1f4f'
        assert iden.pubkey == 'ab3b98863398672d6ac76afcb0a177a40285cfa5846e0740ebe838d917a15992'

    def test_secp256k1_frompem(self):
        pass

    def test_ed25519_from_seed(self):
        mnemonic = 'fence dragon soft spoon embrace bronze regular hawk more remind detect slam'
        iden = Identity.from_seed(mnemonic)
        assert iden.key_type == 'ed25519'
        assert iden.privkey == '97cc884647e7e0ef58c36b57448269ba6a123521a7f234fa5fdc5816d824ef50'