from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.system_state import *

client = Client()
iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
print('principal:', Principal.self_authenticating(iden.der_pubkey))
ag = Agent(iden, client)

ret = time(ag, "gvbup-jyaaa-aaaah-qcdwa-cai")
print(ret)

ret = subnet_public_key(ag, "gvbup-jyaaa-aaaah-qcdwa-cai", "pjljw-kztyl-46ud4-ofrj6-nzkhm-3n4nt-wi3jt-ypmav-ijqkt-gjf66-uae")
print(ret)

ret = subnet_canister_ranges(ag, "gvbup-jyaaa-aaaah-qcdwa-cai", "pjljw-kztyl-46ud4-ofrj6-nzkhm-3n4nt-wi3jt-ypmav-ijqkt-gjf66-uae")
print(ret)

ret = canister_module_hash(ag, "gvbup-jyaaa-aaaah-qcdwa-cai")
print(ret)

ret = canister_controllers(ag, "sxhuu-qqaaa-aaaai-qbbcq-cai")
print(ret)