from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.candid import Types, encode

iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
print(iden)
msg = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
sig = iden.sign(bytes(bytearray.fromhex(msg)))
print(sig[1].hex())
ag = Agent(iden, Client())

# ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", encode([]))
ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
'''
ret = ag.query_raw(
        "gvbup-jyaaa-aaaah-qcdwa-cai",
        "balanceOf",
        encode([
            {'type': Types.Principal, 'value': iden.sender().bytes}
        ])
      )
'''

print(ret)
