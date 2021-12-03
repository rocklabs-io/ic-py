from ic.identity import Identity

iden = Identity.from_pem(open('key.pem').read())

print(iden)
print(iden.der_pubkey)

msg = b'hello'

sig = iden.sign(msg)
print(sig[1].hex())
