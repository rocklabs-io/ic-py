# test_certificate.py
import copy
import builtins
import pytest
import cbor2

from ic.principal import Principal
from ic.certificate import Certificate, extract_der, _to_effective_canister_bytes


# ---------------- blst availability helper (official binding only) ----------------
def blst_available() -> bool:
    try:
        import blst  # noqa: F401
        return all(hasattr(blst, n) for n in ("P1_Affine", "P2_Affine", "Pairing", "BLST_SUCCESS"))
    except ModuleNotFoundError:
        return False



# ---------------- Sample certificate ----------------
CERT_SAMPLE = {'tree': [1, [4, b'L\xd0\x0c\xae\xb5\x92V9Bwl\xa5\xb0\xbc\xee\xc3FhN\x17RP\xae\x92\tT>a\x9e*\n\x95'], [1, [1, [2, b'request_status', [1, [4, b'\xd7\r\xbd\x11-y\x9e9IVP\xe6\xd2\xb8;\xff\xa5E\xcc\x9b\xdc)D\x15\xc10#\xaes\n`f'], [1, [1, [1, [4, b'\x1d\x14f\xad\xf88\xb9\xd5\xcdD\x1e\xc6\xae`\xf7_\xb7`\xcc\xf6\x80,7\x01Y\xf8\x02\xb2(d\x8f\xdf'], [1, [4, b'."\xe9\xe3|\xc15\x0e-\xe16\xf0\n,u6\n\xc9\xa9\xe4\x8c\xa9w`\x84m\xd8\xab9\xfb\xcd\xc7'], [1, [4, b'\xa6BE?\x95^@\xb4}\xe4h!\xb2\x01\x18\xc0yJ\xd6w\xc3\x9c5\x88\xa0\x19\x08\xc5K^\xd5\xaf'], [2, b'\xb5\x00\xe6\xe3\t52J\xacu\x12\x08\x8f\xe5\x03V4\x8f\x88\x08\x1f\x98H\x07t\xc5w\xcaEp\xfb=', [1, [2, b'reply', [3, b'DIDL\x00\x01}\x02']], [2, b'status', [3, b'replied']]]]]]], [4, b"\xbd\xde\xa4k8\xad\x87'-B\xc6\xe9\xdf`\xd96\xb7 \x81\xb2#\xf0\xc5\xe1\xfe\x81\xa1\x96\xbf\xdb\x1d6"]], [4, b'J\xb0\x0c*\x9f\xdb\xb81\xad\x9d9H\xbf\xf2\x91\x91N{\x03\x950\xef\x93\\\xc8L\\@\xe9\xa9\xad\xb1']]]], [4, b'\xb2G\xde\xeb.\x87V\x96\xa2[B"\xf1\x01?a@\xd9F\t^w\x9a\xf9\xd5\xb0-2&\x1e\x14g']], [1, [4, b"\r4\x13\x90\xd2`\x8c\xd8k\x1dJ\xe2\xe5'\xdb,\xe5\x12OwI\xe12\xcdB\xbd \xd2x\xae\xdb\x07"], [2, b'time', [3, b'\xb4\xe1\xff\xa6\xb7\xfc\xae\xaf\x18']]]]], 'signature': b"\xab\x16\xcf\x18'\x1f\x03\x8ehvR\x89\x19\xce\xe2\xc7)\xe7\xbcn\x97\xe2\xd2\xb3|\xfa\xe5\xa3\xa7/9\xe5nD\x8c>|\x8c\x1f\x88\xc3\x91\xa9\x11\xe6%j_", 'delegation': {'subnet_id': b"\x1c\xc5\xadV?\x1b\xce\x93|0[\xe3\xd1+\xefb\x7fs\xb7'\x80\x86r\xdc$2\xae\xf9\x02", 'certificate': b'\xd9\xd9\xf7\xa2dtree\x83\x01\x82\x04X \xae:\x9f\t\xdb\xb2=\x06g\x15U\xb7\xa7\xab\x19\xcaO\x17\x92F\xaa\x8a\xb9\xfd^\xd3\xbd\x0b\xd0\x17\x83\x87\x83\x01\x82\x04X \xd0b<jH\xee\x19\x98\x96\xc1\x9c\xdd\'M\xd6\x8cI\x8f-\x97\x1a\xb9\x03\x03\x84\x87q\x17\xf0:Q\xff\x83\x01\x83\x02Fsubnet\x83\x01\x83\x01\x83\x01\x83\x01\x82\x04X yMP\xb5\xb9o\x1b\x0b\x1b:\xb1X\x14\xcf\xaa\xb3\xe1Q\xd6v`\xd4\xceI\xb5Lk@\x10\xc5?\x18\x83\x01\x82\x04X \x8c\xbaH-v.\x1e\xce\xd6\xd2\x03\n\x9aE/\x81\x84\xff"\xe5\x17\xd8\x90\xc5o>\x12-\xdfM&a\x83\x01\x83\x02X\x1d\x1c\xc5\xadV?\x1b\xce\x93|0[\xe3\xd1+\xefb\x7fs\xb7\'\x80\x86r\xdc$2\xae\xf9\x02\x83\x01\x83\x02Ocanister_ranges\x82\x03X\x1b\xd9\xd9\xf7\x81\x82J\x00\x00\x00\x00\x01\xf0\x00\x00\x01\x01J\x00\x00\x00\x00\x01\xff\xff\xff\x01\x01\x83\x02Jpublic_key\x82\x03X\x850\x81\x820\x1d\x06\r+\x06\x01\x04\x01\x82\xdc|\x05\x03\x01\x02\x01\x06\x0c+\x06\x01\x04\x01\x82\xdc|\x05\x03\x02\x01\x03a\x00\x93\x90w\x10\xf0\xf8\x9a\xf4\xb5\xbd5\xa2\x8e\x01b\x17\x1e/A\x1d\x11\xe1R\x15.\x88\xe3\xdaL yy\x9eN\xacz:\x9f9#\xfbc\xb3;h\x92\x8a\xe9\x16R\xfa\xe5\xc2\xcc\xce\x87!sc&H\xefM\xd7\x9a\xe7\xe8\xc1[\x9e\x97\xf12\xea4\xa44\x95\x06\xd2\x81\xbdf\xbb\xd0\xc3\xaf\xddx\xcb\xe0&\x92z\x8c\x16\x82\x04X ~\r\xc1\xbb\x9d)N\xacW"\x80\xd6<\x80\xc2@\x16<\xb9\xad\x121\xe1"\x80.\x1fV\xca\x9a\r\xd1\x82\x04X \x83\x11\x15\xd9\xd0\x82\xf6\xbb\xc4\xe1\xe1\xe0-\x05\x1d\x14\x7f{I\xa6\xfb\xb7\x02xx\xec\x12\xae\x9bP\xb4\x89\x82\x04X \xaf\xaa\x882\x10\x1b\xce\xe2>\xb8q\xf6\xa3\xb3r\xb9\'\xeb:\xd5\xba\xcb\xbb\xf6z\xa4\xdf)k\xf8\xc4\x93\x82\x04X \xe3\xa7\xcb\xd3\x9cU]G\xb6\x18\xd4\x91\xa0h\xb3\xf9W\x95t8\xd8\xc3\x9d\xd1\xb5`H\x0e\xed\x98\xf9#\x83\x02Dtime\x82\x03I\xb2\xf6\xcd\xc5\x95\xf7\xae\xaf\x18isignatureX0\xa76D\x9f:\xaa9\x87!\x7f\xe3x\xf0\xe4\xe2\xe4t\x16\xf2\xb3)\x15\x8f\xed\xfb/\xe1\x03\xde\x83\xf6^\xa8s\xd8\xde\xf3\xea1mUU\xc7\xa6F\x01^\xd1'}}
CERT_CANISTER_ID = "wcrzb-2qaaa-aaaap-qhpgq-cai"

# ---------------- helpers ----------------
def _get_ranges_from_parent(cert_dict):
    """Return (lo, hi) from the first canister_ranges entry in the parent certificate."""
    cert = Certificate(cert_dict)
    d = cert.delegation
    assert d is not None, "sample must contain delegation"
    parent_cert_dict = cbor2.loads(d["certificate"])
    parent = Certificate(parent_cert_dict)
    subnet_id = bytes(d["subnet_id"])
    canister_range = parent.lookup([b"subnet", subnet_id, b"canister_ranges"])
    assert canister_range is not None, "parent certificate must contain canister_ranges"
    ranges_raw = cbor2.loads(canister_range)
    assert isinstance(ranges_raw, list) and len(ranges_raw) >= 1
    lo, hi = ranges_raw[0]
    return bytes(lo), bytes(hi)

def _tamper_signature(cert_dict):
    """Flip the last bit of the signature to force a verification failure."""
    bad = copy.deepcopy(cert_dict)
    sig = bytearray(bad["signature"])
    sig[-1] ^= 0x01
    bad["signature"] = bytes(sig)
    return bad


# ========== Test 1: check_delegation authorized (use fixed canister id) ==========
def test_check_delegation_authorized():
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)

    if blst_available():
        der_key = cert.check_delegation(cid_bytes, must_verify=True)
    else:
        # in environments without blst, allow materials-only (must_verify=False)
        der_key = cert.check_delegation(cid_bytes, must_verify=False)

    assert isinstance(der_key, (bytes, bytearray, memoryview)) and len(der_key) == 133
    pk96 = extract_der(der_key)
    assert isinstance(pk96, (bytes, bytearray, memoryview)) and len(pk96) == 96


# ========== Test 2: check_delegation unauthorized (construct an out-of-range id) ==========
def test_check_delegation_unauthorized_raises():
    _lo, hi = _get_ranges_from_parent(CERT_SAMPLE)
    cert = Certificate(CERT_SAMPLE)
    eff_outside = bytes(hi) + b"\x01"  # strictly greater than high bound

    with pytest.raises(ValueError, match="CertificateNotAuthorized"):
        cert.check_delegation(eff_outside, must_verify=blst_available())


# ========== Test 3: verify_cert returns materials (no real verification) ==========
def test_verify_return_materials_lengths():
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)
    materials = cert.verify_cert(cid_bytes, backend="return_materials")

    assert set(materials.keys()) == {"signature", "message", "der_public_key", "bls_public_key"}
    assert isinstance(materials["signature"], (bytes, bytearray, memoryview)) and len(materials["signature"]) == 48
    # 1 + len("ic-state-root") + 32 = 46
    assert isinstance(materials["message"], (bytes, bytearray, memoryview)) and len(materials["message"]) == 46
    assert isinstance(materials["der_public_key"], (bytes, bytearray, memoryview)) and len(materials["der_public_key"]) == 133
    assert isinstance(materials["bls_public_key"], (bytes, bytearray, memoryview)) and len(materials["bls_public_key"]) == 96


# ========== Test 4: verify_cert success (requires blst) ==========
@pytest.mark.skipif(not blst_available(), reason="official 'blst' not installed")
def test_verify_with_blst_success():
    cid_bytes = _to_effective_canister_bytes(CERT_CANISTER_ID)
    cert = Certificate(CERT_SAMPLE)
    assert cert.verify_cert(cid_bytes, backend="blst") is True


# ========== Test 5: verify_cert fails when signature is tampered (requires blst) ==========
@pytest.mark.skipif(not blst_available(), reason="official 'blst' not installed")
def test_verify_with_blst_bad_signature_raises():
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    bad_cert = Certificate(_tamper_signature(CERT_SAMPLE))
    with pytest.raises(ValueError, match="CertificateVerificationFailed"):
        bad_cert.verify_cert(cid_bytes, backend="blst")


# ========== Test 6: require blst for backend='blst' (simulate missing blst) ==========
def test_verify_requires_blst_when_backend_blst(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "blst":
            raise ModuleNotFoundError("No module named 'blst'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)

    with pytest.raises(RuntimeError, match="official 'blst' Python binding"):
        cert.verify_cert(cid_bytes, backend="blst")


# ========== Test 7: extract_der prefix mismatch ==========
def test_extract_der_prefix_mismatch():
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    cert = Certificate(CERT_SAMPLE)
    der_key = cert.check_delegation(cid_bytes, must_verify=False)
    bad = bytearray(der_key)
    bad[0] ^= 0x01
    with pytest.raises(ValueError, match="prefix mismatch"):
        extract_der(bytes(bad))


# ========== Test 8: missing canister_ranges should fail ==========
def test_check_delegation_missing_ranges_raises():
    mutated = copy.deepcopy(CERT_SAMPLE)
    # Change subnet_id so lookups won't find "canister_ranges"
    mutated["delegation"]["subnet_id"] = b"\x01" * len(mutated["delegation"]["subnet_id"])
    cert = Certificate(mutated)
    cid_bytes = Principal.from_str(CERT_CANISTER_ID).bytes
    with pytest.raises(ValueError, match="Missing canister_ranges"):
        cert.check_delegation(cid_bytes, must_verify=False)


# ========== Test 9: timestamp skew check ==========
def test_verify_cert_timestamp_skew_too_large():
    cert = Certificate(CERT_SAMPLE)
    with pytest.raises(ValueError, match="CertificateOutdated"):
        cert.verify_cert_timestamp(ingress_expiry_ns=1)