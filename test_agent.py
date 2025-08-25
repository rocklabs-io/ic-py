import pytest

from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.candid import encode

CANISTER_ID_TEXT = "wcrzb-2qaaa-aaaap-qhpgq-cai"

@pytest.fixture(scope="session")
def ag() -> "Agent":
        client = Client(url="https://ic0.app")
        iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
        ag = Agent(iden, client)
        return ag


def test_update_raw_sync(ag):
    arg = encode([])

    t0 = time.perf_counter()
    ret = ag.update_raw(CANISTER_ID_TEXT, "set", arg, verify_certificate=True)
    t1 = time.perf_counter()

    latency_ms = (t1 - t0) * 1000
    print(f"update_raw latency: {latency_ms:.2f} ms")
    print("update result:", ret)

    assert ret is not None


def test_query_raw_sync(ag):
    t0 = time.perf_counter()
    ret = ag.query_raw(
            CANISTER_ID_TEXT,
            "get",
            encode([])
            )
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) * 1000
    print(f"query_raw latency: {latency_ms:.2f} ms")
    print('query result: ', ret)

    assert ret is not None