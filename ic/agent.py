import time
import cbor2
import httpx
from waiter import wait
from .candid import decode, Types
from .certificate import Certificate
from .identity import *
from .constants import *
from .utils import to_request_id

DEFAULT_POLL_TIMEOUT_SECS=60.0

DEFAULT_INITIAL_DELAY = 0.5    # 500 ms
DEFAULT_MAX_INTERVAL   = 1.0    # 1 s
DEFAULT_MULTIPLIER     = 1.4

def sign_request(req, iden):
    req_id = to_request_id(req)
    msg = IC_REQUEST_DOMAIN_SEPARATOR + req_id
    sig = iden.sign(msg)
    envelope = {
        'content': req,
        'sender_pubkey': sig[0],
        'sender_sig': sig[1]
    }
    if isinstance(iden, DelegateIdentity):
        envelope.update({
            "sender_pubkey": iden.der_pubkey,
            "sender_delegation": iden.delegations
        })
    return req_id, cbor2.dumps(envelope)

DEFAULT_INGRESS_EXPIRY_SEC = 3 * 60  # Default ingress expiry time in seconds

class Agent:
    def __init__(self, identity, client, nonce_factory=None, ingress_expiry=DEFAULT_INGRESS_EXPIRY_SEC, root_key=IC_ROOT_KEY):
        self.identity = identity
        self.client = client
        self.ingress_expiry = ingress_expiry
        self.root_key = root_key
        self.nonce_factory = nonce_factory

    def get_principal(self):
        return self.identity.sender()

    def get_expiry_date(self):
        return time.time_ns() + int(self.ingress_expiry * 1e9)

    def query_endpoint(self, canister_id, data):
        ret = self.client.query(canister_id, data)
        return cbor2.loads(ret)

    async def query_endpoint_async(self, canister_id, data):
        ret = await self.client.query_async(canister_id, data)
        return cbor2.loads(ret)

    def call_endpoint(self, canister_id, request_id, data):
        ret = self.client.call(canister_id, request_id, data)
        return ret

    async def call_endpoint_async(self, canister_id, request_id, data):
        await self.client.call_async(canister_id, request_id, data)
        return request_id

    def read_state_endpoint(self, canister_id, data):
        result = self.client.read_state(canister_id, data)
        return result

    async def read_state_endpoint_async(self, canister_id, data):
        result = await self.client.read_state_async(canister_id, data)
        return result

    def query_raw(self, canister_id, method_name, arg, return_type = None, effective_canister_id = None):
        req = {
            'request_type': "query",
            'sender': self.identity.sender().bytes,
            'canister_id': Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
            'method_name': method_name,
            'arg': arg,
            'ingress_expiry': self.get_expiry_date()
        }
        _, data = sign_request(req, self.identity)
        result = self.query_endpoint(canister_id if effective_canister_id is None else effective_canister_id, data)
        if type(result) != dict or "status" not in result:
            raise Exception("Malformed result: " + str(result))
        if result['status'] == 'replied':
            arg = result['reply']['arg']
            if arg[:4] == b"DIDL":
                return decode(arg, return_type)
            else:
                return arg
        elif result['status'] == 'rejected':
            raise Exception("Canister reject the call: " + result['reject_message'])
        else:
            raise Exception("Unknown status: " + str(result['status']))

    async def query_raw_async(self, canister_id, method_name, arg, return_type = None, effective_canister_id = None):
        req = {
            'request_type': "query",
            'sender': self.identity.sender().bytes,
            'canister_id': Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
            'method_name': method_name,
            'arg': arg,
            'ingress_expiry': self.get_expiry_date()
        }
        _, data = sign_request(req, self.identity)
        result = await self.query_endpoint_async(canister_id if effective_canister_id is None else effective_canister_id, data)
        if type(result) != dict or "status" not in result:
            raise Exception("Malformed result: " + str(result))
        if result['status'] == 'replied':
            arg = result['reply']['arg']
            if arg[:4] == b"DIDL":
                return decode(arg, return_type)
            else:
                return arg
        elif result['status'] == 'rejected':
            raise Exception("Canister reject the call: " + result['reject_message'])
        else:
            raise Exception("Unknown status: " + str(result.get('status')))

    # TODO: verify certificate - Milestone2
    def update_raw(self, canister_id, method_name, arg, return_type = None, effective_canister_id = None):
        req = {
            'request_type': "call",
            'sender': self.identity.sender().bytes,
            'canister_id': Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
            'method_name': method_name,
            'arg': arg,
            'ingress_expiry': self.get_expiry_date()
        }
        req_id, data = sign_request(req, self.identity)
        eid = canister_id if effective_canister_id is None else effective_canister_id

        cbor_response: httpx.Response = self.call_endpoint(eid, req_id, data)
        response = cbor2.loads(cbor_response.content)
        if not isinstance(response, dict) or 'status' not in response:
            raise RuntimeError("Malformed update response: " + str(response))

        status = response.get('status')
        if status == "replied":
            cbor_certificate = response['certificate']
            decoded_certificate = cbor2.loads(cbor_certificate)
            # TODO: 在这儿verify cert
            certificate = Certificate(decoded_certificate)

            status = certificate.lookup_request_status(req_id)
            if status == "replied":
                reply_data = certificate.lookup_reply(req_id)
                decoded_data = decode(reply_data, return_type)
                return decoded_data
            elif status == "rejected":
                rejection = certificate.lookup_request_rejection(req_id)
                raise RuntimeError(f"Call rejected (code={rejection['reject_code']}): {rejection['reject_message']} [error_code={rejection.get('error_code')}]")
            else:
                return self.poll_and_wait(eid, req_id, return_type=return_type)
        elif status == "accepted":
            return self.poll_and_wait(eid, req_id, return_type=return_type)
        elif status == "non_replicated_rejection":
            code = response["reject_code"]
            message = response["reject_message"]
            error = response.get("error_code", "unknown")
            raise RuntimeError(f"Call rejected (code={code}): {message} [error_code={error}]")
        else:
            raise RuntimeError(f"Unknown status: {status}")

    async def update_raw_async(self, canister_id, method_name, arg, return_type = None, effective_canister_id = None, **kwargs):
        req = {
            'request_type': "call",
            'sender': self.identity.sender().bytes,
            'canister_id': Principal.from_str(canister_id).bytes if isinstance(canister_id, str) else canister_id.bytes,
            'method_name': method_name,
            'arg': arg,
            'ingress_expiry': self.get_expiry_date()
        }
        req_id, data = sign_request(req, self.identity)
        eid = canister_id if effective_canister_id is None else effective_canister_id
        _ = await self.call_endpoint_async(eid, req_id, data)
        # print('update.req_id:', req_id.hex())
        status, result = await self.poll_async(eid, req_id, **kwargs)
        if status == 'rejected':
            raise Exception('Rejected: ' + result.decode())
        elif status == 'replied': 
            if result[:4] == b"DIDL":
                return decode(result, return_type)
            else:
                return result
        else:
            raise Exception('Timeout to poll result, current status: ' + str(status))        

    def read_state_raw(self, canister_id, paths):
        req = {
            'request_type': 'read_state',
            'sender': self.identity.sender().bytes,
            'paths': paths, 
            'ingress_expiry': self.get_expiry_date(),
        }
        _, data = sign_request(req, self.identity)
        ret = self.read_state_endpoint(canister_id, data)
        if ret == b'Invalid path requested.':
            raise ValueError('Invalid path requested!')
        elif ret == b'Could not parse body as read request: invalid type: byte array, expected a sequence':
            raise ValueError('Could not parse body as read request: invalid type: byte array, expected a sequence')
        try:
            d = cbor2.loads(ret)
        except:
            raise ValueError("Unable to decode cbor value: " + ret.decode())
        cert = cbor2.loads(d['certificate'])
        return cert

    async def read_state_raw_async(self, canister_id, paths):
        req = {
            'request_type': 'read_state',
            'sender': self.identity.sender().bytes,
            'paths': paths, 
            'ingress_expiry': self.get_expiry_date(),
        }
        _, data = sign_request(req, self.identity)
        ret = await self.read_state_endpoint_async(canister_id, data)
        if ret == b'Invalid path requested.':
            raise ValueError('Invalid path requested!')
        elif ret == b'Could not parse body as read request: invalid type: byte array, expected a sequence':
            raise ValueError('Could not parse body as read request: invalid type: byte array, expected a sequence')
        d = cbor2.loads(ret)
        cert = cbor2.loads(d['certificate'])
        return cert

    def request_status_raw(self, canister_id, req_id):
        paths = [
            ['request_status'.encode(), req_id],
        ]
        cert = self.read_state_raw(canister_id, paths)
        certificate = Certificate(cert)
        status = certificate.lookup_request_status(req_id)
        if status is None:
            return status, cert
        else:
            return status.decode(), cert

    async def request_status_raw_async(self, canister_id, req_id):
        paths = [
            ['request_status'.encode(), req_id],
        ]
        cert = await self.read_state_raw_async(canister_id, paths)
        status = cert.lookup(['request_status'.encode(), req_id, 'status'.encode()], cert)
        if status is None:
            return status, cert
        else:
            return status.decode(), cert

    def poll_and_wait(self, canister_id, req_id, return_type=None):
        status, result = self.poll(canister_id, req_id)
        if status == "replied":
            decoded_data = decode(result, return_type)
            return decoded_data
        elif status == "rejected":
            code = result["reject_code"]
            message = result["reject_message"]
            error = result.get("error_code", "unknown")
            raise RuntimeError(f"Call rejected (code={code}): {message} [error_code={error}]")
        else:
            raise RuntimeError(f"Unknown status: {status}")

    def poll(
            self,
            canister_id,
            req_id,
            *,
            initial_delay: float = DEFAULT_INITIAL_DELAY,
            max_interval: float = DEFAULT_MAX_INTERVAL,
            multiplier: float = DEFAULT_MULTIPLIER,
            timeout: float = DEFAULT_POLL_TIMEOUT_SECS
    ):
        """
        Poll canister call status with exponential backoff.

        Args:
            canister_id: target canister identifier
            req_id:       request ID bytes
            initial_delay: initial backoff interval in seconds (default 0.5s)
            max_interval:   maximum backoff interval in seconds (default 1s)
            multiplier:     backoff multiplier (default 1.4)
            timeout:        maximum total polling time in seconds

        Returns:
            Tuple(status_str, result_bytes_or_data)
        """
        start = time.monotonic()
        delay = initial_delay
        request_accepted = False

        while True:
            status, raw_cert = self.request_status_raw(canister_id, req_id)
            cert = Certificate(raw_cert)
            if status in ("replied", "done", "rejected"):
                break

            # once we see Received or Processing, the request is accepted:
            # reset backoff so we don’t time out while it’s still in flight
            if status in ("received", "processing") and not request_accepted:
                delay = initial_delay
                request_accepted = True

            if time.monotonic() - start >= timeout:
                raise TimeoutError(f"Polling request {req_id.hex()} timed out after {timeout}s")

            # wait before next attempt
            time.sleep(delay)
            delay = min(delay * multiplier, max_interval)

        # handle the terminal state
        if status == "replied":
            reply = cert.lookup_reply(req_id)
            return status, reply

        elif status == "rejected":
            rejection = cert.lookup_request_rejection(req_id)
            return status, rejection

        elif status == "done":
            # request completed with no reply
            raise Exception(f"Request {req_id.hex()} finished (Done) with no reply")

        else:
            # should never happen
            raise Exception(f"Unexpected final status in poll(): {status!r}")



    async def poll_async(self, canister_id, req_id, delay=1, timeout=DEFAULT_POLL_TIMEOUT_SECS):
        global cert
        status = None
        for _ in wait(delay, timeout):
            status, cert = await self.request_status_raw_async(canister_id, req_id)
            if status == 'replied' or status == 'done' or status  == 'rejected':
                break
        
        if status == 'replied':
            path = ['request_status'.encode(), req_id, 'reply'.encode()]
            res = cert.lookup(path)
            return status, res
        elif status == 'rejected':
            path = ['request_status'.encode(), req_id, 'reject_message'.encode()]
            msg = cert.lookup(path)
            return status, msg
        else:
            return status, cert

    # def _parse_transport_response(
    #     status_code: int,
    #     content: bytes
    # ) -> Union[
    #     TransportCallResponse.Replied,
    #     TransportCallResponse.NonReplicatedRejection,
    #     TransportCallResponse.Accepted
    # ]:
    #     # 1) HTTP 202 → Accepted
    #     if status_code == httpx.codes.ACCEPTED:
    #         return TransportCallResponse.Accepted()
    #
    #     # 2) 其余先做 CBOR 解码
    #     try:
    #         msg = cbor2.loads(content)
    #     except cbor2.CBORDecodeError as e:
    #         raise AgentError.InvalidCborData from e
    #
    #     # 3) 内部 tag 分发
    #     status = msg.get("status")
    #     if status == "replied":
    #         cert = msg.get("certificate")
    #         return TransportCallResponse.Replied(certificate=cert)
    #
    #     elif status == "non_replicated_rejection":
    #         rr = RejectResponse(
    #             reject_code=msg["reject_code"],
    #             reject_message=msg["reject_message"],
    #             error_code=msg.get("error_code"),
    #         )
    #         return TransportCallResponse.NonReplicatedRejection(reject=rr)
    #
    #     else:
    #         # 出了未预期的 tag
    #         raise AgentError.InvalidCborData(f"Unexpected status: {status!r}")
