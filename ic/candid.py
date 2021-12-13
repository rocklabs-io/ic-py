import leb128
from enum import Enum
from .principal import Principal

class Types(Enum):
    Null = -1
    Bool = -2
    Nat = -3
    Int = -4
    Nat8 = -5
    Nat16 = -6
    Nat32 = -7
    Nat64 = -8
    Int8 = -9
    Int16 = -10
    Int32 = -11
    Int64 = -12
    Float32 = -13
    Float64 = -14
    Text = -15
    Reserved = -16
    Empty = -17
    Opt = -18
    Vec = -19
    Record = -20
    Variant = -21
    Func = -22
    Service = -23
    Principal = -24

def encode_type(t, v):
    if t == Types.Nat:
        return leb128.u.encode(v)
    elif t == Types.Int:
        return leb128.i.encode(v)
    elif t == Types.Bool:
        v_ = 1 if v == True else 0
        return leb128.u.encode(v_)
    elif t == Types.Nat8:
        return leb128.u.encode(v)
    elif t == Types.Nat16:
        return int.to_bytes(v, 2, byteorder='big')
    elif t == Types.Nat32:
        return int.to_bytes(v, 4, byteorder='big')
    elif t == Types.Nat64:
        return int.to_bytes(v, 8, byteorder='big')
    elif t == Types.Principal:
        tag = int.to_bytes(1, 1, byteorder='big')
        b = v
        if isinstance(v, str):
            b = Principal.from_str(v).bytes
        elif isinstance(v, Principal):
            b = v.bytes
        l = leb128.u.encode(len(b))
        return tag + l + b
    elif t == Types.Empty:
        return b''
    # TODO: int8, int32, int64, float32, float64, text, ...

prefix = "DIDL"
# params = [{type, value}]
# data = b'DIDL' + len(params) + encoded types + encoded values
def encode(params):
    data = b''
    data += prefix.encode()
    data += int.to_bytes(len(params), 2, byteorder='big')
    ty = b''
    value = b''
    # encode types & values
    for p in params:
        ty += leb128.i.encode(p['type'].value)
        value += encode_type(p['type'], p['value'])
    # print(params, 'types:', ty, 'value:', value)
    data += ty
    data += value
    return data

# data: b'DIDL\x00\x01q\x08XTC Test'
def decode(data):
    print('candid decode')
