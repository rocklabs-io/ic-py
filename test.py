from ic.agent import *
from ic.identity import *
from ic.client import *

iden = Identity()#type = "secp256k1")
print(iden)
ag = Agent(iden, Client())

ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", b'')

# print(ret)
