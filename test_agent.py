from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.candid import Types, encode

client = Client()
iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
print('principal:', Principal.self_authenticating(iden.der_pubkey))
ag = Agent(iden, client)

# query token totalSupply
ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", encode([]))
print('totalSupply:', ret)

# query token name
ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
print('name:', ret)

# query token balance of user
ret = ag.query_raw(
        "gvbup-jyaaa-aaaah-qcdwa-cai",
        "balanceOf",
        encode([
            {'type': Types.Principal, 'value': iden.sender().bytes}
        ])
      )
print('balanceOf:', ret)

# transfer 100 tokens to blackhole
ret = ag.update_raw(
        "gvbup-jyaaa-aaaah-qcdwa-cai",
        "transfer",
        encode([
            {'type': Types.Principal, 'value': 'aaaaa-aa'},
            {'type': Types.Nat, 'value': 10000000000}
            ])
        )
print('result: ', ret)
