# test_certificate.py
import pytest
import cbor2

from ic.principal import Principal
from ic.certificate import Certificate, extract_der

# ------------- 工具：判断 blst/pyblst 是否可用 -------------
def blst_available() -> bool:
    try:
        import blst  # noqa: F401
        return True
    except ModuleNotFoundError:
        try:
            import pyblst as blst  # noqa: F401
            return True
        except ModuleNotFoundError:
            return False


CERT_SAMPLE = {'tree': [1, [4, b'\x0f\x90?\xaa\xfe\x91\x08V[\x01\xecJ\xee\x85\xb0\x02:\xbb\xa4ca5W\xe8\xe8\xc8\xa5j\xe2\x94\xa0t'], [1, [1, [2, b'request_status', [1, [1, [1, [1, [4, b'zo\x88\n\xb0\xa1\xed\xd0V=^OT\x14\x8e\xf1\xdd$-\x0c\x86\xd8\xc1\xdf\xf5iS\xcd\x80\x992C'], [1, [1, [4, b'L_j\x1b\x13\xebKT\x93\x06\xe7j2\x19zK\xd1\x14\xf0>\xc9\xee\xd5\xcdNW\x9f\xc5o\xdf\xf3i'], [1, [1, [1, [4, b'y\x89\xf8\xb9\x91a\xe2\x1e\x03\xa2\x90\x05\xc6\xa9\xe4\x82\xbf\x14(\x90!&\xff\xa8\xa3m<\\\x115\x1d/'], [2, b"\x15\xdd\xe9\xef{\xc3i\xd0\xe4(\x12W{\x01?\x9b\xdd\xdb\xf1\xc2i?\xf0\x1a\xac\xd1<CI'[\x05", [1, [2, b'reply', [3, b'DIDL\x00\x01}\x02']], [2, b'status', [3, b'replied']]]]], [4, b'\xb9\xde\xc8\xeedcgja\x14&o/A\xf9)\xadw\xae\xcd\xee?\xdd\x9a\x05\xe2\xbd\x06\x98\xe2\nT']], [4, b'9\x0cJ8\xb6oh\x9c[\xce\x86.\xc7\xea\xbak\x9a\xd4\x1a=\xfe@w\xe7I\xe8\xb8\xd3\xfbx\xb8\x9f']]], [4, b'_}\x92\xba\xde\t\xb1n/\x8f\xbda\xcb\xd3\xcfo\xbf\x02!\xc5\xa6\x06\xa7\xf5:\x08\xc0\x135\xef\x7f\xda']]], [4, b'\xd5\xbd\xf1\x12\x95\x84\xfd\x9b<?i\xf4\x07\xa6\xa4<\xae\xfa\xf4\x07}\xea\x1dJ\x1a\x95!\x19\x93\xbb\xd6\xbb']], [4, b'\x86hs\xcf,\xf5\x08\xa7\xfb\x8f\xaa\xbdy\xc3\x91\xfa\x82x#\x0e\xac\xec\x1f\x8fW\xffRXD\x98l\xdd']], [4, b'\xf9\x9e\xb2\xaf8\x0360M\x1aj\x99M\xafn\x1b3\xda\xc6k\x13\xcb\x04\xff\x95\xb4"\xe5\x16\xba\\\xbd']]], [4, b'@\x83m2\xe2\xff}u\xea\xfc\xba\xf7`q\x17\x9f\xd3)\xae\xb5\xda\xca\xb2!\xa6\xe3q\x05F\xd3\xa3\x1f']], [1, [4, b'~.\xdcdN\xf3.x\xb2|\xe0\xff\x96\xa3\xdf\xf1\x9b\xdevW\xd1\xb48.wi+$\xfdd\xad\x98'], [2, b'time', [3, b'\x9c\xe2\x83\xb3\xf0\x93\xea\xae\x18']]]]], 'signature': b"\x8b\xfavN\x9a0\x18\x17\x13\xef\xef\xc1\x00\x89}\xa7&D:Y`\xea'\xb2\xc1\xa6g\x12\xce \xd4\xa4\x08\xd1\xd0\xfaH\xf45(Bcw\xef[\x06*\xf2", 'delegation': {'subnet_id': b'\x12y\x0eva\xfc\xcd=O\xc818\xdc\xaf\xfd\x9f\x18\x8e\x86{E\xae\x10\xc8\x83m\xd0\xb8\x02', 'certificate': b'\xd9\xd9\xf7\xa2dtree\x83\x01\x82\x04X k|\xabY?)\xa5S\xf06\xcf5\x8fY\xf4G\xd0\xc8!\r8\xb9/\rb\x92\x9eu\xa0I\x18\xe3\x83\x01\x82\x04X \x8f\xe6nG\xfco\x18\xc5\xb3=\x94\x16d`P\x8a\xf5\xc5\\\xab\xe2\xdc\x83\xc2\x93\xc0\xca?\xc72\x96c\x83\x01\x83\x02Fsubnet\x83\x01\x83\x01\x83\x01\x83\x01\x82\x04X yMP\xb5\xb9o\x1b\x0b\x1b:\xb1X\x14\xcf\xaa\xb3\xe1Q\xd6v`\xd4\xceI\xb5Lk@\x10\xc5?\x18\x83\x01\x83\x01\x83\x02X\x1d\x12y\x0eva\xfc\xcd=O\xc818\xdc\xaf\xfd\x9f\x18\x8e\x86{E\xae\x10\xc8\x83m\xd0\xb8\x02\x83\x01\x83\x02Ocanister_ranges\x82\x03X\x1b\xd9\xd9\xf7\x81\x82J\x00\x00\x00\x00\x01P\x00\x00\x01\x01J\x00\x00\x00\x00\x01_\xff\xff\x01\x01\x83\x02Jpublic_key\x82\x03X\x850\x81\x820\x1d\x06\r+\x06\x01\x04\x01\x82\xdc|\x05\x03\x01\x02\x01\x06\x0c+\x06\x01\x04\x01\x82\xdc|\x05\x03\x02\x01\x03a\x00\x86\xd8\x8e\xbb\xd2\xf1f>e\xd3\xa3\xff\x07\xe8\xee\x9f\xa4 \xd0\x8b\x9ah"\x91\x9f"K\x8b\x80-]\x9b\xe1P\xdcI?\x84\xc2>s\xa0\xcc\x1d,.\xe2\x87\t\xff\x14\x00\x00\x12\x8f\xcd]\xfb\xd7\xb4W\xef:\xf3Dvm\x7f\xf0\x92O\xe7\xa7\xf4V\xde\xd7|\xa6\xde;\x1b@kq\x0cN\xae\xd7(z\xb9\xa3Rvi\x82\x04X \xc9\xaa\x91d\x96\xd6t\x9d\xe9{\x8f( \xe7\xa7X\xf3\x907B&\xd1\xec \xd5\xb1\xa5\x96\xe1.h\xe8\x82\x04X \xb4\x0e"vB\xeffV1M\xf0x\x86N\x10kO\xdb\x9a\xe6\xeap\xcb\x91\x93\xcd\xc1\xce\x9a~\xa3y\x82\x04X \x83\x11\x15\xd9\xd0\x82\xf6\xbb\xc4\xe1\xe1\xe0-\x05\x1d\x14\x7f{I\xa6\xfb\xb7\x02xx\xec\x12\xae\x9bP\xb4\x89\x82\x04X \xaf\xaa\x882\x10\x1b\xce\xe2>\xb8q\xf6\xa3\xb3r\xb9\'\xeb:\xd5\xba\xcb\xbb\xf6z\xa4\xdf)k\xf8\xc4\x93\x82\x04X d"9\x19\xce\x8c\xa2\xf0\xc2d_\xa3\xbbWW\x1e\x01\xdb=\xea\xc0\x9c\xef\xfa\xb6}\xc8\xd5\xaf\xfc\xa7\x17\x83\x02Dtime\x82\x03I\xb9\x89\xfc\xf3\xbc\x83\xea\xae\x18isignatureX0\xb2U\xff\xc0\xc2\x8b\xb1+v\x17\x13\xb4@\xc3\x1eAA\xad\x0f\rr&\xbf\xbe\xe5\xcb\xeb{_\xd5\xf0\xcb\xd3CM\xce\\\x13bRVq\xfb\xe94\xa0\\-'}}


# ------------- 辅助：从父证书取 canister_ranges，挑一个范围的上下界 -------------
def _get_ranges_from_parent(cert_dict):
    cert = Certificate(cert_dict)
    d = cert.delegation
    assert d is not None, "样例应当包含 delegation"
    parent_cert_dict = cbor2.loads(d["certificate"])
    parent = Certificate(parent_cert_dict)
    subnet_id = bytes(d["subnet_id"])
    canister_range = parent.lookup([b"subnet", subnet_id, b"canister_ranges"])
    assert canister_range is not None, "父证书必须含有 canister_ranges"
    ranges_raw = cbor2.loads(canister_range)
    assert isinstance(ranges_raw, list) and len(ranges_raw) >= 1
    lo, hi = ranges_raw[0]
    return bytes(lo), bytes(hi)


# ========== 测试 1：check_delegation（有 blst：必须验签；无 blst：联调模式） ==========
def test_check_delegation_authorized():
    lo, _hi = _get_ranges_from_parent(CERT_SAMPLE)   # 挑下界，保证在区间内
    cert = Certificate(CERT_SAMPLE)

    if blst_available():
        der_key = cert.check_delegation(lo, must_verify=True)  # 真验签
    else:
        der_key = cert.check_delegation(lo, must_verify=False) # 无 blst 时跳过父证书验签（联调）
    assert isinstance(der_key, (bytes, bytearray, memoryview))
    assert len(der_key) == 133

    pk96 = extract_der(der_key)
    assert isinstance(pk96, (bytes, bytearray, memoryview))
    assert len(pk96) == 96


# ========== 测试 2：check_delegation 未授权路径 ==========
def test_check_delegation_unauthorized_raises():
    lo, hi = _get_ranges_from_parent(CERT_SAMPLE)
    cert = Certificate(CERT_SAMPLE)
    eff_outside = bytes(hi) + b"\x01"  # 构造一个严格大于 hi 的字节串

    if blst_available():
        with pytest.raises(ValueError, match="CertificateNotAuthorized"):
            cert.check_delegation(eff_outside, must_verify=True)
    else:
        with pytest.raises(ValueError, match="CertificateNotAuthorized"):
            cert.check_delegation(eff_outside, must_verify=False)


# ========== 测试 3：verify（有 blst：真验签；无 blst：返回材料） ==========
@pytest.mark.skipif(not blst_available(), reason="blst/pyblst not installed")
def test_verify_with_blst():
    cid_bytes = Principal.from_str('v3y75-6iaaa-aaaak-qikaa-cai').bytes
    print("cid bytes:", cid_bytes)
    materials = Certificate(CERT_SAMPLE).verify_cert(
        cid_bytes,
        backend="return_materials",
    )
    print("sig len:", len(materials["signature"]))  # 应该 48
    print("msg len:", len(materials["message"]))  # 应该 1+len("ic-state-root")+32 = 45
    print("pk len:", len(materials["bls_public_key"]))  # 应该 96
    print("msg hex:", materials["message"].hex())


    lo, _ = _get_ranges_from_parent(CERT_SAMPLE)
    cert = Certificate(CERT_SAMPLE)
    assert cert.verify_cert(cid_bytes, backend="blst") is True

def test_verify_return_materials():
    lo, _ = _get_ranges_from_parent(CERT_SAMPLE)
    cert = Certificate(CERT_SAMPLE)
    materials = cert.verify_cert(lo, backend="return_materials")
    assert set(materials.keys()) == {"signature", "message", "der_public_key", "bls_public_key"}
    assert isinstance(materials["signature"], (bytes, bytearray, memoryview)) and len(materials["signature"]) == 48
    assert isinstance(materials["message"],   (bytes, bytearray, memoryview)) and len(materials["message"]) == (1 + len(b"ic-state-root") + 32)
    assert isinstance(materials["der_public_key"], (bytes, bytearray, memoryview)) and len(materials["der_public_key"]) == 133
    assert isinstance(materials["bls_public_key"], (bytes, bytearray, memoryview)) and len(materials["bls_public_key"]) == 96

def debug_materials(cert_dict):
    cert = Certificate(cert_dict)
    lo, _ = _get_ranges_from_parent(cert_dict)
    mats = cert.verify_cert(lo, backend="return_materials")
    print("sig:", len(mats["signature"]))
    print("msg:", len(mats["message"]), mats["message"][:1], mats["message"][1:14], len(mats["message"][1:14]))
    print("pk :", len(mats["bls_public_key"]))
    print("root_hash:", mats["message"][-32:].hex())
    return mats

