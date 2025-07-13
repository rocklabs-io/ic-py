from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.candid import Types, encode

class TestAgent:

    def setup_class(self):
        client = Client()
        iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        self.agent = Agent(iden, client)

    def test_query(self):
        # query token totalSupply
        ret = self.agent.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", encode([]))
        assert ret[0]['value'] == 10000000000000000

        # query token name
        ret = self.agent.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
        assert ret[0]['value'] == 'XTC Test'

    def test_update(self):
        ret = self.agent.update_raw(
            "gvbup-jyaaa-aaaah-qcdwa-cai",
            "transfer",
            encode([
                {'type': Types.Principal, 'value': 'aaaaa-aa'},
                {'type': Types.Nat, 'value': 10000000000}
                ])
            )
        assert ret != None
