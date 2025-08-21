import pytest

from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.candid import encode
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

# update canister state
CANISTER_ID_TEXT = "wcrzb-2qaaa-aaaap-qhpgq-cai"

@pytest.fixture(scope="session")
def ag() -> "Agent":
        client = Client(url="https://ic0.app")
        iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        # print('principal:', Principal.self_authenticating(iden.der_pubkey))
        ag = Agent(iden, client)
        return ag


def test_update_raw_sync(ag):
    # 如果 update_raw 接受 Principal/bytes，推荐这样传：
    arg = encode([])

    t0 = time.perf_counter()
    ret = ag.update_raw(CANISTER_ID_TEXT, "set", arg, verify_certificate=True)
    t1 = time.perf_counter()

    latency_ms = (t1 - t0) * 1000
    print(f"update_raw latency: {latency_ms:.2f} ms")
    print("update result:", ret)

    assert ret is not None

# query canister state
# t0 = time.perf_counter()
# ret = ag.query_raw(
#         CANISTER_ID_TEXT,
#         "get",
#         encode([])
#         )
# t1 = time.perf_counter()
# latency_ms = (t1 - t0) * 1000
# print(f"query_raw latency: {latency_ms:.2f} ms")
# print('query result: ', ret)

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