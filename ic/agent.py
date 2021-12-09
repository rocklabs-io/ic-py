import time
import cbor2
from .candid import *
from .identity import *
from .constants import *
from .utils import to_request_id

# python agent class

def sign_request(req, iden):
    req_id = to_request_id(req)
    msg = IC_REQUEST_DOMAIN_SEPARATOR + req_id
    sig = iden.sign(msg)
    envelop = {
        'content': req,
        'sender_pubkey': sig[0],
        'sender_sig': sig[1]
    }
    return req_id, cbor2.dumps(envelop)

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
        # print(ret.encode())
        # remove tag 2 or tag 3 encode. 
        ret = ret.encode()[7:] # the 7 bytes header may be length info.
        if b'\xc2' or b'\xc3' in ret:
            ret = ret.replace(b'\xc2', b'')
            ret = ret.replace(b'\xc3', b'') 
        return cbor2.loads(ret)

    def call_endpoint(self, canister_id, request_id, data):
        self.client.call(canister_id, data, request_id)
        return request_id

    def read_state_endpoint(self, canister_id, data):
        result = self.client.read_state(canister_id, data)
        return result

    def query_raw(self, canister_id, method_name, arg):
        req = {
            'request_type': "query",
            'sender': self.identity.sender().bytes,
            'canister_id': Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
            'method_name': method_name,
            'arg': arg,
            'ingress_expiry': self.get_expiry_date()
        }
        _, data = sign_request(req, self.identity)
        result = self.query_endpoint(canister_id, data)
        print(result)
        if result['status'] == 'replied':
            arg = decode(result['reply']['arg'])
            return arg
        elif result['status'] == 'rejected':
            return result['reject_message']

    def update_raw(self):
        req = {
            'request_type': "call",
            'sender': self.identity.sender().bytes,
            'canister_id': Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
            'method_name': method_name,
            'arg': arg,
            'ingress_expiry': self.get_expiry_date()
        }
        req_id, data = sign_request(req, self.identity)
        _ = self.call_endpoint(canister_id, req_id, data)
        # poll req_id status to get result
        result = self.poll(canister_id, req_id)
        print(result)

    def read_state_raw(self, canister_id, paths):
        req = {
            'sender': self.identity.sender().bytes,
            'paths': paths, 
            'ingress_expiry': self.get_expiry_date(),
        }
        _, data = sign_request(req, self.identity)
        ret = self.read_state_endpoint(canister_id, data)
        cert = cbor2.loads(ret)
        return cert

    def request_status_raw(self, canister_id, req_id):
        paths = []
        cert = self.read_state_raw(canister_id, paths)
        lookup_request_status(cert, req_id)

    def poll(self, canister_id, req_id):
        ret = self.request_status_raw(canister_id, req_id)
        return ret
