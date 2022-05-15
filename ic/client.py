# http client

import httpx

class Client:
    def __init__(self, url = "https://ic0.app"):
        self.url = url

    def query(self, canister_id, data):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/query'
        headers = {'Content-Type': 'application/cbor'}
        ret = httpx.post(endpoint, data = data, headers=headers)
        return ret.content

    def call(self, canister_id, req_id, data):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/call'
        headers = {'Content-Type': 'application/cbor'}
        ret = httpx.post(endpoint, data = data, headers=headers)
        return req_id

    def read_state(self, canister_id, data):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/read_state'
        headers = {'Content-Type': 'application/cbor'}
        ret = httpx.post(endpoint, data = data, headers=headers)
        return ret.content

    def status(self):
        endpoint = self.url + '/api/v2/status'
        ret = httpx.get(endpoint)
        print('client.status:', ret.text)
        return ret.content

    async def query_async(self, canister_id, data):
        async with httpx.AsyncClient() as client:
            endpoint = self.url + '/api/v2/canister/' + canister_id + '/query'
            headers = {'Content-Type': 'application/cbor'}
            ret = await client.post(endpoint, data = data, headers=headers)
            return ret.content

    async def call_async(self, canister_id, req_id, data):
        async with httpx.AsyncClient() as client:
            endpoint = self.url + '/api/v2/canister/' + canister_id + '/call'
            headers = {'Content-Type': 'application/cbor'}
            await client.post(endpoint, data = data, headers=headers)
            return req_id

    async def read_state_async(self, canister_id, data):
        async with httpx.AsyncClient() as client:
            endpoint = self.url + '/api/v2/canister/' + canister_id + '/read_state'
            headers = {'Content-Type': 'application/cbor'}
            ret = await client.post(endpoint, data = data, headers=headers)
            return ret.content

    async def status_async(self):
        async with httpx.AsyncClient() as client:
            endpoint = self.url + '/api/v2/status'
            ret = await client.get(endpoint)
            print('client.status:', ret.text)
            return ret.content