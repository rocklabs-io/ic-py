import time
import cbor2
from .identity import *
from .constants import *
from .utils import to_request_id

# python agent class

def sign_request(req, iden):
    req_id = to_request_id(req)
    msg = IC_REQUEST_DOMAIN_SEPARATOR + req_id
    sig = iden.sign(msg)
    print(sig[0].hex(), sig[1].hex())
    envelop = {
        'content': req,
        'sender_pubkey': sig[0],
        'sender_sig': sig[1]
    }
    return cbor2.dumps(envelop)

class Agent:
    def __init__(self, identity, client, nonce_factory=None, ingress_expiry=300, root_key=IC_ROOT_KEY):
        self.identity = identity
        self.client = client
        self.ingress_expiry = ingress_expiry
        self.root_key = root_key
        self.nonce_factory = nonce_factory

    def get_principal(self):
        return self.identity.sender()

    def get_expiry_date(self):
        return int(time.time() + self.ingress_expiry) * 10**9

    def read_state(self):
        pass

    def query_endpoint(self, canister_id, data):
        ret = self.client.query(canister_id, data)
        print(ret)
        return cbor2.loads(ret.encode())

    def call_endpoint(self, canister_id, request_id, data):
        self.client.call(canister_id, data, request_id)
        return request_id

    def query_raw(self, canister_id, method_name, arg):
        req = {
            'request_type': "query",
            'sender': self.identity.sender().bytes,
            'canister_id': Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
            'method_name': method_name,
            'arg': arg,
            'ingress_expiry': self.get_expiry_date()
        }
        data = sign_request(req, self.identity)
        return self.query_endpoint(canister_id, data)

    def update_raw(self):
        pass

    def poll(self, req_id, canister_id):
        pass

    def request_status_raw(self, req_id, canister_id):
        pass

