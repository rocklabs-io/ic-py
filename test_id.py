from ic.identity import Identity

iden = Identity.from_pem(open('identity.pem').read())

print(iden)
print(iden.der_pubkey)
