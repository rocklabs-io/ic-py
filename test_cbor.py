# git: https://github.com/agronholm/cbor2
import cbor2

# result for `name` query
response = b'\xc3\x99\xc3\x99\xc3\xb7\xc2\xa2fstatusgrepliedereply\xc2\xa1cargPDIDL\x00\x01q\x08XTC Test'

# why error???
r = cbor2.loads(response)
print(r)
