from ic.principal import Principal

class TestPrincipal:

    def test_default(self):
        p = Principal()
        assert p.to_str() == 'aaaaa-aa'

    def test_anonymous(self):
        p = Principal.anonymous();
        assert p.to_str() == '2vxsx-fae'

    def test_pubkey(self):
        p = Principal.self_authenticating("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf") # create a principal from public key
        assert p.to_str() == 'zbtml-m23rk-szoaa-5x6p5-co5in-yylx6-463xu-zbjp4-4oizn-cqaij-tae'

    def test_fromstr(self):
        p = Principal.from_str("zbtml-m23rk-szoaa-5x6p5-co5in-yylx6-463xu-zbjp4-4oizn-cqaij-tae")
        assert p.to_str() == 'zbtml-m23rk-szoaa-5x6p5-co5in-yylx6-463xu-zbjp4-4oizn-cqaij-tae'
