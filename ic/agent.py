import time
import asyncio
import cbor2
import httpx
from .candid import decode
from .certificate import Certificate
from .identity import *
from .constants import *
from .utils import to_request_id
from .principal import Principal

DEFAULT_POLL_TIMEOUT_SECS = 60.0

# Exponential backoff defaults
DEFAULT_INITIAL_DELAY = 0.5   # seconds
DEFAULT_MAX_INTERVAL  = 1.0   # seconds
DEFAULT_MULTIPLIER    = 1.4

NANOSECONDS = 1_000_000_000

def sign_request(req, iden):
    """
    Build and CBOR-encode an envelope for an IC request, signing the request_id with the identity.
    For delegated identities, include delegation and DER public key.
    """
    identity_obj = iden
    request_id = to_request_id(req)
    message = IC_REQUEST_DOMAIN_SEPARATOR + request_id
    sig_tuple = identity_obj.sign(message)
    envelope = {
        "content": req,
        "sender_pubkey": sig_tuple[0],
        "sender_sig": sig_tuple[1],
    }
    if isinstance(identity_obj, DelegateIdentity):
        envelope.update({
            "sender_pubkey": identity_obj.der_pubkey,
            "sender_delegation": identity_obj.delegations,
        })
    return request_id, cbor2.dumps(envelope)

# Default ingress expiry in seconds
DEFAULT_INGRESS_EXPIRY_SEC = 3 * 60

class Agent:
    def __init__(self, identity, client, nonce_factory=None,
                 ingress_expiry=DEFAULT_INGRESS_EXPIRY_SEC, root_key=IC_ROOT_KEY):
        self.identity = identity
        self.client = client
        self.ingress_expiry = ingress_expiry
        self.root_key = root_key
        self.nonce_factory = nonce_factory

    def get_principal(self):
        return self.identity.sender()

    def get_expiry_date(self):
        """Return ingress expiry in nanoseconds since epoch."""
        return time.time_ns() + int(self.ingress_expiry * 1e9)

    # ----------- HTTP endpoints -----------

    def query_endpoint(self, canister_id, data):
        raw_bytes = self.client.query(canister_id, data)
        return cbor2.loads(raw_bytes)

    async def query_endpoint_async(self, canister_id, data):
        raw_bytes = await self.client.query_async(canister_id, data)
        return cbor2.loads(raw_bytes)

    def call_endpoint(self, canister_id, request_id, data):
        return self.client.call(canister_id, request_id, data)

    async def call_endpoint_async(self, canister_id, request_id, data):
        await self.client.call_async(canister_id, request_id, data)
        return request_id

    def read_state_endpoint(self, canister_id, data):
        return self.client.read_state(canister_id, data)

    async def read_state_endpoint_async(self, canister_id, data):
        return await self.client.read_state_async(canister_id, data)

    # ----------- Query (one-shot) -----------

    def query_raw(self, canister_id, method_name, arg, return_type=None, effective_canister_id=None):
        req = {
            "request_type": "query",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        target_canister = canister_id if effective_canister_id is None else effective_canister_id
        result = self.query_endpoint(target_canister, signed_cbor)

        if not isinstance(result, dict) or "status" not in result:
            raise Exception("Malformed result: " + repr(result))

        if result["status"] == "replied":
            reply_arg = result["reply"]["arg"]
            if reply_arg[:4] == b"DIDL":
                return decode(reply_arg, return_type)
            return reply_arg
        elif result["status"] == "rejected":
            raise Exception("Canister rejected the call: " + result.get("reject_message", ""))
        else:
            raise Exception("Unknown status: " + repr(result.get("status")))

    async def query_raw_async(self, canister_id, method_name, arg, return_type=None, effective_canister_id=None):
        req = {
            "request_type": "query",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        target_canister = canister_id if effective_canister_id is None else effective_canister_id
        result = await self.query_endpoint_async(target_canister, signed_cbor)

        if not isinstance(result, dict) or "status" not in result:
            raise Exception("Malformed result: " + repr(result))

        if result["status"] == "replied":
            reply_arg = result["reply"]["arg"]
            if reply_arg[:4] == b"DIDL":
                return decode(reply_arg, return_type)
            return reply_arg
        elif result["status"] == "rejected":
            raise Exception("Canister rejected the call: " + result.get("reject_message", ""))
        else:
            raise Exception("Unknown status: " + repr(result.get("status")))

    # ----------- Update (call + poll) -----------

    def update_raw(self, canister_id, method_name, arg, return_type=None,
                   effective_canister_id=None, verify_certificate: bool = False):
        req = {
            "request_type": "call",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        request_id, signed_cbor = sign_request(req, self.identity)
        effective_id = canister_id if effective_canister_id is None else effective_canister_id

        http_response: httpx.Response = self.call_endpoint(effective_id, request_id, signed_cbor)
        response_obj = cbor2.loads(http_response.content)

        if not isinstance(response_obj, dict) or "status" not in response_obj:
            raise RuntimeError("Malformed update response: " + repr(response_obj))

        status = response_obj.get("status")

        if status == "replied":
            cbor_certificate = response_obj["certificate"]
            decoded_certificate = cbor2.loads(cbor_certificate)
            certificate = Certificate(decoded_certificate)

            if verify_certificate:
                certificate.assert_certificate_valid(effective_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            certified_status = certificate.lookup_request_status(request_id)
            if certified_status == "replied":
                reply_data = certificate.lookup_reply(request_id)
                return decode(reply_data, return_type)
            elif certified_status == "rejected":
                rejection = certificate.lookup_request_rejection(request_id)
                raise RuntimeError(
                    f"Call rejected (code={rejection['reject_code']}): "
                    f"{rejection['reject_message']} [error_code={rejection.get('error_code')}]"
                )
            else:
                # not yet terminal in certification; continue polling
                return self.poll_and_wait(effective_id, request_id, verify_certificate, return_type=return_type)

        elif status == "accepted":
            # Not yet executed; start polling
            return self.poll_and_wait(effective_id, request_id, verify_certificate, return_type=return_type)

        elif status == "non_replicated_rejection":
            code = response_obj.get("reject_code")
            message = response_obj.get("reject_message")
            error = response_obj.get("error_code", "unknown")
            raise RuntimeError(f"Call rejected (code={code}): {message} [error_code={error}]")

        else:
            raise RuntimeError(f"Unknown status: {status}")

    async def update_raw_async(self, canister_id, method_name, arg, return_type=None,
                               effective_canister_id=None, verify_certificate: bool = False,
                               **kwargs):
        req = {
            "request_type": "call",
            "sender": self.identity.sender().bytes,
            "canister_id": Principal.from_str(canister_id).bytes
                if isinstance(canister_id, str) else canister_id.bytes,
            "method_name": method_name,
            "arg": arg,
            "ingress_expiry": self.get_expiry_date(),
        }
        request_id, signed_cbor = sign_request(req, self.identity)
        effective_id = canister_id if effective_canister_id is None else effective_canister_id

        _ = await self.call_endpoint_async(effective_id, request_id, signed_cbor)

        status, result = await self.poll_async(
            effective_id, request_id, verify_certificate, **kwargs
        )

        if status == "rejected":
            # result is a dict with rejection fields
            code = result.get("reject_code")
            message = result.get("reject_message")
            error = result.get("error_code", "unknown")
            raise Exception(f"Rejected (code={code}): {message} [error_code={error}]")

        elif status == "replied":
            # result is raw reply bytes
            if result[:4] == b"DIDL":
                return decode(result, return_type)
            return result

        else:
            raise Exception("Timeout to poll result, current status: " + str(status))

    # ----------- Read state -----------

    def read_state_raw(self, canister_id, paths):
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        raw_bytes = self.read_state_endpoint(canister_id, signed_cbor)

        if raw_bytes == b"Invalid path requested.":
            raise ValueError("Invalid path requested!")
        elif raw_bytes == b"Could not parse body as read request: invalid type: byte array, expected a sequence":
            raise ValueError("Could not parse body as read request: invalid type: byte array, expected a sequence")

        try:
            decoded_obj = cbor2.loads(raw_bytes)
        except Exception:
            # Use repr to avoid decode errors
            raise ValueError("Unable to decode cbor value: " + repr(raw_bytes))
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        return cert_dict

    async def read_state_raw_async(self, canister_id, paths):
        req = {
            "request_type": "read_state",
            "sender": self.identity.sender().bytes,
            "paths": paths,
            "ingress_expiry": self.get_expiry_date(),
        }
        _, signed_cbor = sign_request(req, self.identity)
        raw_bytes = await self.read_state_endpoint_async(canister_id, signed_cbor)

        if raw_bytes == b"Invalid path requested.":
            raise ValueError("Invalid path requested!")
        elif raw_bytes == b"Could not parse body as read request: invalid type: byte array, expected a sequence":
            raise ValueError("Could not parse body as read request: invalid type: byte array, expected a sequence")

        decoded_obj = cbor2.loads(raw_bytes)
        cert_dict = cbor2.loads(decoded_obj["certificate"])
        return cert_dict

    # ----------- Request status -----------

    def request_status_raw(self, canister_id, req_id):
        paths = [
            [b"request_status", req_id],
        ]
        cert_dict = self.read_state_raw(canister_id, paths)
        certificate = Certificate(cert_dict)
        status_bytes = certificate.lookup_request_status(req_id)
        if status_bytes is None:
            return status_bytes, cert_dict
        return status_bytes.decode(), cert_dict

    async def request_status_raw_async(self, canister_id, req_id):
        paths = [
            [b"request_status", req_id],
        ]
        cert_dict = await self.read_state_raw_async(canister_id, paths)
        certificate = Certificate(cert_dict)
        status_bytes = certificate.lookup_request_status(req_id)
        if status_bytes is None:
            return status_bytes, cert_dict
        return status_bytes.decode(), cert_dict

    # ----------- Polling helpers -----------

    def poll_and_wait(self, canister_id, req_id, verify_certificate, return_type=None):
        status, result = self.poll(canister_id, req_id, verify_certificate)
        if status == "replied":
            return decode(result, return_type)
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
        verify_certificate,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
        timeout: float = DEFAULT_POLL_TIMEOUT_SECS,
    ):
        """
        Poll canister call status with exponential backoff (synchronous).

        Args:
            canister_id: target canister identifier (use effective canister id)
            req_id:      request ID bytes
            verify_certificate: whether to verify the certificate
            initial_delay: initial backoff interval in seconds (default 0.5s)
            max_interval:  maximum backoff interval in seconds (default 1s)
            multiplier:    backoff multiplier (default 1.4)
            timeout:       maximum total polling time in seconds

        Returns:
            Tuple(status_str, result_bytes_or_data)
        """
        start_monotonic = time.monotonic()
        backoff = initial_delay
        request_accepted = False

        while True:
            status_str, cert_dict = self.request_status_raw(canister_id, req_id)
            certificate = Certificate(cert_dict)

            if verify_certificate:
                certificate.assert_certificate_valid(canister_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            if status_str in ("replied", "done", "rejected"):
                break

            # Once we see Received or Processing, the request is accepted:
            # reset backoff so we don’t time out while it’s still in flight.
            if status_str in ("received", "processing") and not request_accepted:
                backoff = initial_delay
                request_accepted = True

            if time.monotonic() - start_monotonic >= timeout:
                raise TimeoutError(f"Polling request {req_id.hex()} timed out after {timeout}s")

            time.sleep(backoff)
            backoff = min(backoff * multiplier, max_interval)

        if status_str == "replied":
            reply_bytes = certificate.lookup_reply(req_id)
            return status_str, reply_bytes
        elif status_str == "rejected":
            rejection_obj = certificate.lookup_request_rejection(req_id)
            return status_str, rejection_obj
        elif status_str == "done":
            raise Exception(f"Request {req_id.hex()} finished (Done) with no reply")
        else:
            raise Exception(f"Unexpected final status in poll(): {status_str!r}")

    async def poll_async(
        self,
        canister_id,
        req_id,
        verify_certificate,
        *,
        initial_delay: float = DEFAULT_INITIAL_DELAY,
        max_interval: float = DEFAULT_MAX_INTERVAL,
        multiplier: float = DEFAULT_MULTIPLIER,
        timeout: float = DEFAULT_POLL_TIMEOUT_SECS,
    ):
        """
        Poll canister call status with exponential backoff (asynchronous).
        Mirrors `poll` but uses async read_state.
        """
        start_monotonic = time.monotonic()
        backoff = initial_delay
        request_accepted = False

        while True:
            status_str, cert_dict = await self.request_status_raw_async(canister_id, req_id)
            certificate = Certificate(cert_dict)

            if verify_certificate:
                certificate.assert_certificate_valid(canister_id)
                certificate.verify_cert_timestamp(self.ingress_expiry * NANOSECONDS)

            if status_str in ("replied", "done", "rejected"):
                break

            if status_str in ("received", "processing") and not request_accepted:
                backoff = initial_delay
                request_accepted = True

            if time.monotonic() - start_monotonic >= timeout:
                raise TimeoutError(f"Polling request {req_id.hex()} timed out after {timeout}s")

            await asyncio.sleep(backoff)
            backoff = min(backoff * multiplier, max_interval)

        if status_str == "replied":
            reply_bytes = certificate.lookup_reply(req_id)
            return status_str, reply_bytes
        elif status_str == "rejected":
            rejection_obj = certificate.lookup_request_rejection(req_id)
            return status_str, rejection_obj
        elif status_str == "done":
            raise Exception(f"Request {req_id.hex()} finished (Done) with no reply")
        else:
            raise Exception(f"Unexpected final status in poll_async(): {status_str!r}")