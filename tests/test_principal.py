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

    def test_eq(self):
        p0 = Principal.anonymous()
        p1 = Principal.management_canister()
        assert p0 != p1

        p2 = Principal.from_str("aaaaa-aa")
        assert p1 == p2

    def test_hash(self):
        p = Principal.management_canister()
        m = {}
        m[p] = 1
        assert m[p] == 1
        m[p] = 2
        assert m[p] == 2
        assert len(m) == 1