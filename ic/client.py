# http client

import httpx
from httpx import Timeout

DEFAULT_TIMEOUT_SEC = 360.0
DEFAULT_TIMEOUT = Timeout(DEFAULT_TIMEOUT_SEC)

class Client:
    def __init__(self, url: str = "https://ic0.app"):
        self.url = url

    # --------- sync ---------

    def query(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        endpoint = f"{self.url}/api/v2/canister/{canister_id}/query"
        headers = {"Content-Type": "application/cbor"}
        resp = httpx.post(endpoint, content=data, headers=headers, timeout=timeout)
        return resp.content

    def call(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> httpx.Response:
        # v3 endpoint
        endpoint = f"{self.url}/api/v3/canister/{canister_id}/call"
        headers = {"Content-Type": "application/cbor"}
        resp = httpx.post(endpoint, content=data, headers=headers, timeout=timeout)
        return resp

    def read_state(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        endpoint = f"{self.url}/api/v2/canister/{canister_id}/read_state"
        headers = {"Content-Type": "application/cbor"}
        resp = httpx.post(endpoint, content=data, headers=headers, timeout=timeout)
        return resp.content

    def status(self, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        endpoint = f"{self.url}/api/v2/status"
        resp = httpx.get(endpoint, timeout=timeout)
        print("client.status:", resp.text)
        return resp.content

    # --------- async ---------

    async def query_async(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = f"{self.url}/api/v2/canister/{canister_id}/query"
            headers = {"Content-Type": "application/cbor"}
            resp = await client.post(endpoint, content=data, headers=headers)
            return resp.content

    async def call_async(self, canister_id: str, req_id: bytes, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = f"{self.url}/api/v2/canister/{canister_id}/call"
            headers = {"Content-Type": "application/cbor"}
            await client.post(endpoint, content=data, headers=headers)
            return req_id

    async def read_state_async(self, canister_id: str, data: bytes, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = f"{self.url}/api/v2/canister/{canister_id}/read_state"
            headers = {"Content-Type": "application/cbor"}
            resp = await client.post(endpoint, content=data, headers=headers)
            return resp.content

    async def status_async(self, *, timeout: Timeout = DEFAULT_TIMEOUT) -> bytes:
        async with httpx.AsyncClient(timeout=timeout) as client:
            endpoint = f"{self.url}/api/v2/status"
            resp = await client.get(endpoint)
            print("client.status:", resp.text)
            return resp.content