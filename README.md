# Python Agent Library for the Internet Computer

![ic-py](./pics/ic-py.png)

`ic-py` provides basic modules to interact with canisters on the DFINITY Internet Computer.

---

## Install

```bash
pip3 install ic-py
```

---

## What’s New

### Optional certificate verification via BLS + blst

- `Agent.update_raw(..., verify_certificate: bool = False)`
  - When `verify_certificate=True`, the agent verifies certified update responses using **BLS12-381 (minsig: G1 signature, G2 public key)**.
  - This **requires** the official Python binding of **blst**.
  - If you don’t want to verify certificates (e.g., during prototyping), you can omit the flag or set `verify_certificate=False` (default).

> ⚠️ **Security advice:** For production workloads, enable certificate verification.

---

## Installing `blst` (only needed if you verify certificates)

`blst` is not on PyPI. Install the official binding from source.

### macOS (Intel & Apple Silicon) / Linux

```bash
# 1) Clone the official repo
git clone https://github.com/supranational/blst

# 2) Build the Python binding
cd blst/bindings/python

# Apple Silicon users: if you hit ABI/arch issues, build in portable mode
# export BLST_PORTABLE=1

python3 run.me

# 3) Make the module importable by Python, e.g.:
export PYTHONPATH="$PWD:$PYTHONPATH"
```

**Or copy** the generated `blst.py` and the native `_blst*.so` into your `site-packages`:

```bash
# 1) Set this to your local blst source (bindings/python)
BLST_SRC="/path/to/blst/bindings/python"

# 2) Choose the Python interpreter for your target environment
PYBIN="python3"

# 3) Resolve the site-packages paths (pure Python and platform-specific)
SITE_PURE="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
SITE_PLAT="$($PYBIN -c 'import sysconfig; print(sysconfig.get_paths()["platlib"])')"

# 4) Copy blst.py and the native extension .so files
cp "$BLST_SRC/blst.py" "$SITE_PURE"/
cp "$BLST_SRC"/_blst*.so "$SITE_PLAT"/

# 5) Verify
ls -l "$SITE_PURE/blst.py" "$SITE_PLAT"/_blst*.so
```

**Quick check:**

```python
import blst
print(blst)  # should show a module exposing P1_Affine / P2_Affine / Pairing / BLST_SUCCESS
```

### Windows

- **Recommended:** use **WSL2 (Ubuntu)** and follow the Linux steps above.
- Native Windows builds may require additional toolchain setup; WSL2 is strongly recommended.

---

## Features

1. Candid types encode & decode  
2. Support `secp256k1` & `ed25519` identities, PEM file import  
3. Canister DID file parsing  
4. `Canister` class, initialized with canister id and DID file  
5. Common canister interfaces: ledger, management, NNS, cycles wallet  
6. Async support  

---

## Modules & Usage

### 1. Principal

Create an instance:

```python
from ic.principal import Principal

p  = Principal()                 # default is management canister id `aaaaa-aa`
p1 = Principal(bytes=b'')        # from bytes
p2 = Principal.anonymous()       # anonymous principal
p3 = Principal.self_authenticating(pubkey)  # from public key
p4 = Principal.from_str('aaaaa-aa')         # from string
p5 = Principal.from_hex('deadbeef')         # from hex
```

Properties & methods:

```python
p.bytes   # principal bytes
p.len     # byte array length
p.to_str()# convert to string
```

### 2. Identity

Create an instance:

```python
from ic.identity import Identity

i  = Identity()  # randomly generated key
i1 = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
```

Sign a message:

```python
msg = bytes.fromhex(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
)
der_pubkey, signature = i.sign(msg)  # tuple: (der_encoded_pubkey, signature)
```

### 3. Client

```python
from ic.client import Client
client = Client(url="https://ic0.app")
```

### 4. Candid

Encode parameters:

```python
from ic.candid import encode, decode, Types

# params is a list, returns encoded bytes
params = [{'type': Types.Nat, 'value': 10}]
data = encode(params)
```

Decode parameters:

```python
# data is bytes, returns a parameter list
params = decode(data)
```

### 5. Agent

Create an instance:

```python
from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent

iden = Identity()
client = Client()
agent = Agent(iden, client)
```

Query call:

```python
# query the name of token canister `gvbup-jyaaa-aaaah-qcdwa-cai`
from ic.candid import encode
name = agent.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
```

Update call:

```python
# transfer 100 tokens to blackhole address `aaaaa-aa`
from ic.candid import Types, encode

params = [
  {'type': Types.Principal, 'value': 'aaaaa-aa'},
  {'type': Types.Nat,       'value': 10000000000}
]
result = agent.update_raw(
  "gvbup-jyaaa-aaaah-qcdwa-cai",
  "transfer",
  encode(params),
  # verify_certificate=True,  # enable if you installed `blst`
)
```

### 6. Canister

Create a canister instance with Candid interface file and canister id, and call a method:

```python
from ic.canister import Canister
from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent

iden = Identity()
client = Client()
agent = Agent(iden, client)

# read governance candid from file
governance_did = open("governance.did").read()

# create a governance canister instance
governance = Canister(agent=agent,
                      canister_id="rrkah-fqaaa-aaaaa-aaaaq-cai",
                      candid=governance_did)

# call canister method with instance
res = governance.list_proposals({
    'include_reward_status': [],
    'before_proposal': [],
    'limit': 100,
    'exclude_topic': [],
    'include_status': [1],
})
```

### 7. Async request

`ic-py` also supports async requests:

```python
import asyncio
from ic.canister import Canister
from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent

iden = Identity()
client = Client()
agent = Agent(iden, client)

governance_did = open("governance.did").read()
governance = Canister(agent=agent,
                      canister_id="rrkah-fqaaa-aaaaa-aaaaq-cai",
                      candid=governance_did)

async def async_test():
    res = await governance.list_proposals_async({
        'include_reward_status': [],
        'before_proposal': [],
        'limit': 100,
        'exclude_topic': [],
        'include_status': [1],
    })
    print(res)

asyncio.run(async_test())
```
