## Python Agent Library for the Internet Computer

![ic-py](./pics/ic-py.png)

`ic-py` provides basic modules to interact with canisters on the DFINITY Internet Computer.

### Install

```
pip3 install ic-py
```

### Features

- **Core Functionality**
  - Candid types encoding & decoding
  - Canister interaction and management
  - Async/await support for non-blocking operations

- **Identity & Security**
  - Multiple identity types supported:
    - Secp256k1
    - Ed25519
  - PEM file import capabilities
  - Secure key management

- **Canister Integration**
  - Canister DID file parsing
  - Easy canister initialization with ID and DID file
  - Built-in interfaces for common canisters:
    - Ledger
    - Management
    - Network Nervous System (NNS)
    - Cycles wallet

- **Developer Experience**
  - Simple, intuitive API design
  - Comprehensive type support
  - Full async/await support for concurrent operations

### Modules & Usage

#### 1. Principal

Create an instance:

```python
from ic.principal import Principal
p = Principal() # default is management canister id `aaaaa-aa`
p1 = Principal(bytes=b'') # create an instance from bytes
p2 = Principal.anonymous() # create anonymous principal
p3 = Principal.self_authenticating(pubkey) # create a principal from public key
p4 = Principal.from_str('aaaaa-aa') # create an instance from string
p5 = Principal.from_hex('xxx') # create an instance from hex
```

Class methods:

```python
p.bytes # principal bytes
p.len # byte array length
p.to_str() # convert to string
```

#### 2. Identity

Create an instance:

```python
from ic.identity import Identity
i = Identity() # create an identity instance, key is randomly generated
i1 = Identity(privkey = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42") # create an instance from private key
```

Sign a message:

```python
msg = b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
sig = i.sign(msg) # sig = (der_encoded_pubkey, signature)
```

#### 3. Client

Create an instance:

```python
from ic.client import Client
client = Client(url = "https://ic0.app")
```

#### 4. Candid

Encode parameters:

```python
from ic.candid import encode, decode, Types
# params is an array, return value is encoded bytes
params = [{'type': Types.Nat, 'value': 10}]
data = encode(params)
```

Decode parameters:

```python
# data is bytes, return value is an parameter array
params = decode(data)
```

#### 5. Agent

Create an instance:

```python
from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent
# Identity and Client are dependencies of Agent
iden = Identity()
client = Client()
agent = Agent(iden, client)
```

Query call:

```python
# query the name of token canister `gvbup-jyaaa-aaaah-qcdwa-cai`
name = agent.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
```

Update call:

```python
# transfer 100 token to blackhole address `aaaaa-aa`
params = [
	{'type': Types.Principal, 'value': 'aaaaa-aa'},
	{'type': Types.Nat, 'value': 10000000000}
]
result = agent.update_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "transfer", encode(params))
```

#### 6. Canister

Create a canister instance with candid interface file and canister id, and call canister method with canister instance:

```python
from ic.canister import Canister
from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent
from ic.candid import Types

iden = Identity()
client = Client()
agent = Agent(iden, client)
# read governance candid from file
governance_did = open("governance.did").read()
# create a governance canister instance
governance = Canister(agent=agent, canister_id="rrkah-fqaaa-aaaaa-aaaaq-cai", candid=governance_did)
# call canister method with instance
res = governance.list_proposals(
    {
        'include_reward_status': [],
        'before_proposal': [],
        'limit': 100,
        'exclude_topic': [],
        'include_status': [1]
    }
)
```

### 7. Async request

ic-py also supports async requests:

```python
import asyncio
from ic.canister import Canister
from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent
from ic.candid import Types

iden = Identity()
client = Client()
agent = Agent(iden, client)
# read governance candid from file
governance_did = open("governance.did").read()
# create a governance canister instance
governance = Canister(agent=agent, canister_id="rrkah-fqaaa-aaaaa-aaaaq-cai", candid=governance_did)
# async call
async def async_test():
  res = await governance.list_proposals_async(
    {
        'include_reward_status': [], 
        'before_proposal': [],
        'limit': 100, 
        'exclude_topic': [], 
        'include_status': [1]
    }
  )
  print(res)
asyncio.run(async_test())
```

