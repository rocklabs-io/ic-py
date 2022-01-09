from ic.candid import *

# TODO
class TestCandid:

    def test_nat_encode(self):
        nat = NatClass()
        res = encode([{'type':nat, 'value':10000000000}])
        assert res.hex() == "4449444c00017d80c8afa025"

    def test_nat_decode(self):
        data = bytes.fromhex("4449444c00017d80c8afa025")
        res = decode(data)
        assert len(res) == 1
        assert res[0]["type"] == 'nat'
        assert res[0]["value"] == 10000000000

    def test_principal_encode(self):
        principal = PrincipalClass()
        res = encode([{'type': principal, 'value':'aaaaa-aa'}])
        assert res.hex() == "4449444c0001680100"
    
    def test_principal_decode(self):
        data = bytes.fromhex("4449444c0001680100")
        res = decode(data)
        assert len(res) == 1
        assert res[0]["type"] == 'principal'
        assert res[0]["value"].to_str() == 'aaaaa-aa'

    # data = b'DIDL\x00\x01q\x08XTC Test'
    # print('decode data: {}'.format(data))
    # out = decode(data)
    # print(out)

    # data = b'DIDL\x00\x01}\xe2\x82\xac\xe2\x82\xac\xe2\x80'
    # print('decode data: {}'.format(data))
    # out = decode(data)
    # print(out)

    def test_record_encode(self):
        record = Types.Record({'foo':Types.Text, 'bar': Types.Int})
        res = encode([{'type': record, 'value':{'foo': '💩', 'bar': 42}}])
        assert res.hex() == '4449444c016c02d3e3aa027c868eb7027101002a04f09f92a9'
        
    def test_record_decode(self):
        data = bytes.fromhex('4449444c016c02d3e3aa027c868eb7027101002a04f09f92a9')
        res = decode(data)
        assert len(res) == 1
        assert type(res[0]["type"]) == int
        assert res[0]['value'] == {'_4895187': 42, '_5097222': '💩'}

    # def test_tuple_encode(self):
    #     tup = Types.Tuple(Types.Int, Types.Text)
    #     res = encode([{'type': tup, 'value': [42, '💩']}])
    #     assert res.hex() == '4449444c016c02007c017101002a04f09f92a9'
        

    # # variant
    # tup = Types.Variant({'ok': Types.Text, 'err': Types.Text})
    # res = encode([{'type': tup, 'value': {'ok': 'good'} }])
    # print('expected:', '4449444c016b03017e9cc20171e58eb4027101000104676f6f64')
    # print('current:', res.hex())
    # print(decode(res, tup))
    
    # # tuple(variant)
    # tup = Types.Tuple(Types.Variant({'ok': Types.Text, 'err': Types.Text}))
    # res = encode([{'type': tup, 'value': [{'ok': 'good'}] }])
    # print('expected:', '4449444c026b029cc20171e58eb402716c01000001010004676f6f64')
    # print('current:', res.hex())
    # print(decode(res, tup))

    # # Vec
    # vec = Types.Vec(Types.Nat64)
    # param = [0, 1, 2, 3]
    # res = encode([{'type': vec, 'value': param}])
    # print('expected:', '4449444c016d7c01000400010203')
    # print('current :', res.hex())
    # print('decode Vec:', decode(res, vec))
 
    # # Principle
    # Prin = Types.Principal
    # param = 'expmt-gtxsw-inftj-ttabj-qhp5s-nozup-n3bbo-k7zvn-dg4he-knac3-lae'
    # res = encode([{'type': Prin, 'value': param}])
    # print('current :', res.hex())
    # print('decode Principal:', decode(res))

    # # Opt principal
    # Prin = Types.Opt(Types.Principal)
    # param = ['expmt-gtxsw-inftj-ttabj-qhp5s-nozup-n3bbo-k7zvn-dg4he-knac3-lae']
    # res = encode([{'type': Prin, 'value': param}])
    # print('current :', res.hex())
    # print('decode Principal:', decode(res, Prin))
    
    # # NULL
    # Prin = Types.Null
    # param = None
    # res = encode([{'type': Prin, 'value': param}])
    # print('current :', res.hex())
    # print('decode Null:', decode(res, Prin))
