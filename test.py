from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent
from ic.candid import encode, decode

iden = Identity()
client = Client()
agent = Agent(iden, client)

name = agent.query_raw("hbi4x-wqaaa-aaaaj-aad7a-cai", "getRegistryCount", encode([]))
print(name)
