## Python Agent Library for the IC

`ic-py` provides basic modules for developers to make query/update calls to canisters on the DFINITY Internet Computer. Its still under active development.

### Modules & Usage

#### 1. Principal

Create an instance:

```js
p = Principal() # default is management canister id `aaaaa-aa`
p1 = Principal(bytes=xxx) # create an instance from bytes
p2 = Principal.anonymous() # create anonymous principal
p3 = Principal.self_authenticating(pubkey) # create a principal from public key
p4 = Principal.from_str('aaaaa-aa') # create an instance from string
p5 = Principal.from_hex('xxx') # create an instance from hex
```

Class methods:

```js
p.bytes # principal bytes
p.len # byte array length
p.to_str() # convert to string
```

#### 2. Identity

Create an instance:

```js
i = Identity() # create an identity instance, key is randomly generated
i1 = Identity(privkey = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42") # create an instance from private key
```

Sign a message:

```js
msg = b”ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f“
sig = i.sign(msg) # sig = (der_encoded_pubkey, signature)
```

#### 3. Client

Create an instance:

```js
client = Client(url = "https://ic0.app")
```

#### 4. Candid

Encode parameters:

```js
# params is an array, return value is encoded bytes
params = [{'type': Types.Nat, 'value': 10}]
data = encode(params)
```

Decode parameters:

```js
# data is bytes, return value is an parameter array
params = decode(data)
```

#### 5. Agent

Create an instance:

```js
# Identity and Client are dependencies of Agent
iden = Identity()
client = Client()
agent = Agent(iden, client)
```

Query call:

```js
# query the name of token canister `gvbup-jyaaa-aaaah-qcdwa-cai`
name = agent.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
```

Update call:

```js
# transfer 100 token to blackhole address `aaaaa-aa`
params = [
	{'type': Types.Principal, 'value': 'aaaaa-aa'},
	{'type': Types.Nat, 'value': 10000000000}
]
result = agent.update_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "transfer", encode(params))
```

### Status

1. candid: candid encode & decode  [WIP]
2. principal: principal class [Done]
3. identity: secp256k1 & ed25519 identity [Done]
4. client: http client [Done]
5. agent: ic agent to communicate with canisters on ic [WIP]
6. canister: canister class, initialized with canister id and did file [WIP]
