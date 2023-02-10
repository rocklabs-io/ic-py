# http client

import httpx

DEFAULT_TIMEOUT = 120.0
DEFAULT_TIMEOUT_QUERY = 30.0

class Client:
    def __init__(self, url = "https://ic0.app"):
        self.url = url

    def query(self, canister_id, data, *, timeout = DEFAULT_TIMEOUT_QUERY):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/query'
        headers = {'Content-Type': 'application/cbor'}
        ret = httpx.post(endpoint, data = data, headers=headers, timeout=timeout)
        return ret.content

    def call(self, canister_id, req_id, data, *, timeout = DEFAULT_TIMEOUT):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/call'
        headers = {'Content-Type': 'application/cbor'}
        ret = httpx.post(endpoint, data = data, headers=headers, timeout=timeout)
        return req_id

    def read_state(self, canister_id, data, *, timeout = DEFAULT_TIMEOUT_QUERY):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/read_state'
        headers = {'Content-Type': 'application/cbor'}
        ret = httpx.post(endpoint, data = data, headers=headers, timeout=timeout)
        return ret.content

    def status(self, *, timeout = DEFAULT_TIMEOUT_QUERY):
        endpoint = self.url + '/api/v2/status'
        ret = httpx.get(endpoint, timeout=timeout)
        print('client.status:', ret.text)
        return ret.content

    async def query_async(self, canister_id, data, *, timeout = DEFAULT_TIMEOUT_QUERY):
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = self.url + '/api/v2/canister/' + canister_id + '/query'
            headers = {'Content-Type': 'application/cbor'}
            ret = await client.post(endpoint, data = data, headers=headers)
            return ret.content

    async def call_async(self, canister_id, req_id, data, *, timeout = DEFAULT_TIMEOUT):
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = self.url + '/api/v2/canister/' + canister_id + '/call'
            headers = {'Content-Type': 'application/cbor'}
            await client.post(endpoint, data = data, headers=headers)
            return req_id

    async def read_state_async(self, canister_id, data, *, timeout = DEFAULT_TIMEOUT_QUERY):
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = self.url + '/api/v2/canister/' + canister_id + '/read_state'
            headers = {'Content-Type': 'application/cbor'}
            ret = await client.post(endpoint, data = data, headers=headers)
            return ret.content

    async def status_async(self, *, timeout = DEFAULT_TIMEOUT_QUERY):
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = self.url + '/api/v2/status'
            ret = await client.get(endpoint)
            print('client.status:', ret.text)
            return ret.content
