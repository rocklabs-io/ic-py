from .agent import Agent
from .certificate import Certificate
from .principal import Principal
import leb128
import cbor2

def time(agent: Agent, canister_id: str) -> int:
    raw_cert = agent.read_state_raw(canister_id, [["time".encode()]])
    certificate = Certificate(raw_cert)
    timestamp = certificate.lookup_time()
    return leb128.u.decode(timestamp)

def subnet_public_key(agent: Agent, canister_id: str, subnet_id: str) -> str:
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "public_key".encode()]
    raw_cert = agent.read_state_raw(canister_id, [path])
    certificate = Certificate(raw_cert)
    pubkey = certificate.lookup(path)
    return pubkey.hex()

def subnet_canister_ranges(agent: Agent, canister_id: str, subnet_id: str) -> list[list[Principal]]:
    path = ["subnet".encode(), Principal.from_str(subnet_id).bytes, "canister_ranges".encode()]
    raw_cert = agent.read_state_raw(canister_id, [path])
    certificate = Certificate(raw_cert)
    ranges = certificate.lookup(path)
    return list(
        map(lambda range: 
            list(map(lambda item: Principal(bytes=item), range)),  
        cbor2.loads(ranges))
        )

def canister_module_hash(agent: Agent, canister_id: str) -> str:
    path = ["canister".encode(), Principal.from_str(canister_id).bytes, "module_hash".encode()]
    raw_cert = agent.read_state_raw(canister_id, [path])
    certificate = Certificate(raw_cert)
    module_hash = certificate.lookup(path)
    return module_hash.hex()

def canister_controllers(agent: Agent, canister_id: str) -> list[Principal]:
    path = ["canister".encode(), Principal.from_str(canister_id).bytes, "controllers".encode()]
    raw_cert = agent.read_state_raw(canister_id, [path])
    certificate = Certificate(raw_cert)
    controllers = certificate.lookup(path)
    return list(map(lambda item: Principal(bytes=item), cbor2.loads(controllers)))