from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.candid import encode

client = Client(url="https://ic0.app")
iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
# print('principal:', Principal.self_authenticating(iden.der_pubkey))
ag = Agent(iden, client)

# start = time.time()
# # query token totalSupply
# ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", encode([]))
# print('totalSupply:', ret)
#
# # query token name
# ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
# print('name:', ret)
#
# # query token balance of user
# ret = ag.query_raw(
#         "gvbup-jyaaa-aaaah-qcdwa-cai",
#         "balanceOf",
#         encode([
#             {'type': Types.Principal, 'value': iden.sender().bytes}
#         ])
#       )
# print('balanceOf:', ret)
#
# transfer 100 tokens to blackhole
t0 = time.perf_counter()

ret = ag.update_raw(
        "v3y75-6iaaa-aaaak-qikaa-cai",
        "set",
        encode([])
        )
print('result: ', ret)

t1 = time.perf_counter()
# 4. 计算并打印延迟
latency_ms = (t1 - t0) * 1000
print(f"update_raw latency: {latency_ms:.2f} ms")
print("result:", ret)

#
# t = time.time()
# print("sync call elapsed: ", t - start)

# async def test_async():
#     ret = await ag.query_raw_async("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", encode([]))
#     print('totalSupply:', ret)
#
#     # query token name
#     ret = await ag.query_raw_async("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
#     print('name:', ret)
#
#     # query token balance of user
#     ret = await ag.query_raw_async(
#             "gvbup-jyaaa-aaaah-qcdwa-cai",
#             "balanceOf",
#             encode([
#                 {'type': Types.Principal, 'value': iden.sender().bytes}
#             ])
#         )
#     print('balanceOf:', ret)
#
#     # transfer 100 tokens to blackhole
#     ret = await ag.update_raw_async(
#             "gvbup-jyaaa-aaaah-qcdwa-cai",
#             "transfer",
#             encode([
#                 {'type': Types.Principal, 'value': 'aaaaa-aa'},
#                 {'type': Types.Nat, 'value': 10000000000}
#                 ])
#             )
#     print('result: ', ret)
#
# asyncio.run(test_async())
# print("sync call elapsed: ", time.time() - t)