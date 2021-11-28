from ic.agent import *
from ic.identity import *
from ic.client import *

ag = Agent(Identity(), Client())

ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", b'')

print(ret)
