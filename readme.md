## Python Agent Library for the IC[WIP]



TODOs:

ic:

1. candid: candid encode & decode - abi
2. principal: principal class √
3. identity: secp256k1 & ed25519 identity; der.py: der encode √
4. client: http client - Web3.HTTPProvider
5. agent: ic agent to communicate with canisters on ic - Web3(HTTPProvider("http://xxx"))
6. canister: canister class, initialized with canister id and did file - contract = web3.eth.contract(address=addr, abi=abi); contract.functions.balanceOf(addr1).call()

examples:

1. principal example usage
2. agent example usage
3. canister instance example usage
