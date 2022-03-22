from .agent import Agent
from .certificate import lookup
from .principal import Principal
import leb128
import cbor2

def time(agent: Agent, canister_id: str) -> int:
    cert = agent.read_state_raw(canister_id, [["time".encode()]])
    timestamp = lookup(["time".encode()], cert)
    return leb128.u.decode(timestamp)

def subnet_public_key(agent: Agent, canister_id: str, subnet_id: str) -> str:
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "public_key".encode()]
    cert = agent.read_state_raw(canister_id, [path])
    pubkey = lookup(path, cert)
    return pubkey.hex()

def subnet_canister_ranges(agent: Agent, canister_id: str, subnet_id: str) -> list[list[Principal]]:
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "canister_ranges".encode()]
    cert = agent.read_state_raw(canister_id, [path])
    ranges = lookup(path, cert)
    return list(
        map(lambda range: 
            list(map(lambda item: Principal(bytes=item), range)),  
        cbor2.loads(ranges))
        )

def canister_module_hash(agent: Agent, canister_id: str) -> str:
    path = ["canister".encode(), Principal.from_str(canister_id).bytes, "module_hash".encode()]
    cert = agent.read_state_raw(canister_id, [path])
    module_hash = lookup(path, cert)
    return module_hash.hex()

def canister_controllers(agent: Agent, canister_id: str) -> list[Principal]:
    path = ["canister".encode(), Principal.from_str(canister_id).bytes, "controllers".encode()]
    cert = agent.read_state_raw(canister_id, [path])
    controllers = lookup(path, cert)
    return list(map(lambda item: Principal(bytes=item), cbor2.loads(controllers)))