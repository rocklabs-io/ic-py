from ic.agent import *
from ic.identity import *
from ic.client import *

iden = Identity(privkey = "9b5c0140bfb49e5f40e1b9c64b079fe1b46cc8d9b0379a88261aa5807a7a7f0c")#, type = "secp256k1")
print(iden)
ag = Agent(iden, Client())

ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", b'')

# print(ret)
