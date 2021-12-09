# http client

import requests

class Client:
    def __init__(self, url = "https://ic0.app"):
        self.url = url

    def query(self, canister_id, data):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/query'
        headers = {'Content-Type': 'application/cbor'}
        ret = requests.post(endpoint, data, headers=headers)
        return ret.text

    def call(self, canister_id, req_id, data):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/call'
        headers = {'Content-Type': 'application/cbor'}
        ret = requests.post(endpoint, data, headers=headers)
        print(ret.text)
        return req_id

    def read_state(self, canister_id, data):
        endpoint = self.url + '/api/v2/canister/' + canister_id + '/read_state'
        headers = {'Content-Type': 'application/cbor'}
        ret = requests.post(endpoint, data, headers=headers)
        print(ret.text)
        return ret.text

    def status(self):
        pass
