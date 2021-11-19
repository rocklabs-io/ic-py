# http client

import requests

class Client:
    def __init__(self, url = "https://ic0.app/"):
        self.url = url

    def query(self, canister_id, data):
        endpoint = self.url + 'canister/' + canister_id + '/query'
        headers = {'Content-Type': 'application/cbor'}
        ret = requests.post(endpoint, data, headers=headers)
        print(ret.text)

    def call(self, canister_id, data):
        pass

    def read_state(self, canister_id, data):
        pass

    def status(self):
        pass
