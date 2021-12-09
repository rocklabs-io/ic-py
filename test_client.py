from ic.agent import *
from ic.identity import *
from ic.client import *
from ic.candid import Types, encode

client = Client()

ret = client.status()
print(ret)
