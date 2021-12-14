from _typeshed import Self
from ic.candid import decode
from math import trunc
from typing import AbstractSet, Any, List, Sequence
import leb128
from abc import ABC, abstractclassmethod, ABCMeta
from enum import Enum
from principal import Principal

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

prefix = "DIDL"

class Pipe :
    def __init__(self, buffer = b'', length = 0):
        self._buffer = buffer
        self._view = buffer[0:len(buffer)]

    @property
    def length(self):
        return len(self._buffer)

    def read(self, num:int):
        if len(self._view) < num:
            raise "Wrong: out of bound"
        res = self._view[:num]
        self._view = self._view[num:]
        return res

    def readbyte(self):
        res = self._view[0]
        self._view = self._view[1:]
        return res





class ConstructType: pass
class TypeTable():
    def __init__(self) -> None:
        self._typs = b''
        self._idx = {}

    def has(self, constructType_obj:ConstructType):
        return True if constructType_obj._name in self._idx else False

    def add(self, constructType, data):
        idx = len(self._typs)
        self._idx[constructType._name] = idx
        self._typs += data

    def merge(self, constructType_obj, knot:str):
        idx = self._idx[constructType_obj._name]
        knotIdx = self._idx[knot]
        if idx == 'undefined':
            raise "Missing type index for " + constructType_obj._name
        if knotIdx == 'undefined':
            raise "Missing type index for " + knot
        self._typs[idx] = self._typs[knotIdx]

        #delete the type
        self._typs.pop(knotIdx)
        del self._idx[knot]


    def encode(self) :
        length = leb128.u.encode(len(self._typs))
        return self._typs + length
    
    def indexOf(self, typeName:str) :
        if not self.has(typeName):
            raise "Missing type index for" + typeName
        return leb128.u.encode(self._idx[typeName] | 0)


 # Represents an IDL type.
class Type(metaclass=ABCMeta):
    def __init__(self) -> None:
        self._name = ''

    def display(self):
        return self._name

    def buildTypeTable(self, typeTable):
        if not typeTable.has(self):
            self._buildTypeTableImpl(typeTable)

    @abstractclassmethod
    def covariant(self, x): pass

    @abstractclassmethod
    def decodeValue(self, val, t): pass
    
    @abstractclassmethod
    def encodeType(self, typeTable): pass

    @abstractclassmethod
    def encodeValue(self, val): pass

    @abstractclassmethod
    def checkType(self, t): pass

    @abstractclassmethod
    def _buildTypeTableImpl(self, typeTable): pass


class PrimitiveType(Type):
    
    def __init__(self) -> None:
        super().__init__()

    def checkType(self, type: Type):
        if self._name != type._name :
            raise "type mismatch: type on the wire {}, expect type {}".format(type._name, self._name)
        return type

    def _buildTypeTableImpl(self, typeTable) :
        return


class ConstructType(Type, metaclass=ABCMeta):
    def __init__(self) -> None:
        super().__init__()

    def checkType(self, type: Type) -> ConstructType :
        pass

    def encodeType(self, typeTable: TypeTable):
        # No type table encoding for Primitive types.
        return typeTable.indexOf(self._name)

class EmptyClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self):
        return False
    
    def encodeValue(self, val):
        raise "Empty cannot appear as a function argument"

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Empty.value)

    def decodeValue(self, b, t: Type):
        raise "Empty cannot appear as an output"

    @property
    def name(self) -> str:
        return 'empty'

class BoolClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, bool)
    
    def encodeValue(self, val):
        return leb128.u.encode(1 if True else 0)

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Bool.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        return True if leb128.u.decode(b) == 1 else False

    @property
    def name(self) -> str:
        return 'bool'

class NullClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return x == None
    
    def encodeValue(self, val):
        return b''

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Null.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        return None

    @property
    def name(self) -> str:
        return 'null'

class ReservedClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return True
    
    def encodeValue(self, val):
        return b''

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Reserved.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        if self._name != t._name:
            t.decodeValue(b, t)
        return None

    @property
    def name(self) -> str:
        return 'reserved'

class Text(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, str)
    
    def encodeValue(self, val: str):
        buf = val.encode()
        length = leb128.u.encode(len(buf))
        return  buf + length

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Text.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        length = leb128.i.decode(b)
        return b[:length].decode()

    @property
    def name(self) -> str:
        return 'text'

class IntClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, int)
    
    def encodeValue(self, val):
        return leb128.i.encode(val)

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Int.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        return leb128.i.decode(b)

    @property
    def name(self) -> str:
        return 'int'
class NatClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return x >= 0
    
    def encodeValue(self, val):
        return leb128.u.encode(val)

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Nat.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        return leb128.i.decode(b)

    @property
    def name(self) -> str:
        return 'nat'

class PrincipalClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return True
    
    def encodeValue(self, val):
        tag = int.to_bytes(1, 1, byteorder='big')
        b = val
        if isinstance(val, str):
            b = Principal.from_str(val).bytes
        elif isinstance(val, Principal):
            b = val.bytes
        l = leb128.u.encode(len(b))
        return tag + l + b

    def encodeType(self, typeTable):
        return leb128.i.encode(Types.Principal.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        return leb128.i.decode(b)

    @property
    def name(self) -> str:
        return 'principal'       


# through Pipe to decode bytes
def safeRead(pipe: Pipe, num:int):
    if pipe.length < num:
        raise "unexpected end of buffer"
    return pipe.read(num)

def safeReadByte(pipe: Pipe):
    if pipe.length < 1:
        raise "unexpected end of buffer"
    return pipe.read(1)

def readTypeTable(pipe):
    #types length
    types = []
    while True:
        n = leb128.i.decode(safeReadByte(pipe))
        if n > -1:
            types.append[n]
        else:
            break
    for _ in range(len(types)):



# params = [{type, value}]
# data = b'DIDL' + len(params) + encoded types + encoded values
def encode(params):
    argTypes = []
    args = []
    for p in params:
        argTypes.append(p['type'])
        args.append(p['value'])
    # argTypes: List, args: List
    if len(argTypes) != len(args):
        raise "Wrong number of message arguments"
    typetable = TypeTable()
    forEach = iter(argTypes)
    for item in forEach:
        item.buildTypeTable(typetable)
    
    pre = prefix.encode()
    table = typetable.encode()
    length = leb128.u.encode(len(args))
    
    typs = b''
    vals = b''
    for i in range(len(args)):
        t = argTypes[i]
        if not t.covariant(args[i]):
            raise "Invalid {} argument: {}".format(t.display(), str(args[i]))
        typs += t.encodeType(typetable)
        vals += t.encodeValue(args[i])
    return pre + table + length + typs + vals

# data: b'DIDL\x00\x01q\x08XTC Test'
def decode(data):
    b = Pipe(data)

    if len(data) < len(prefix):
        raise "Message length smaller than prefix number"
    prefix_buffer = safeRead(b, len(prefix)).decode()
    if prefix_buffer != prefix:
        raise "Wrong prefix:" + prefix_buffer + 'expected prefix: DIDL'



if __name__ == "__main__":
    nat = NatClass()
    res1 = encode([{'type':nat, 'value':10000000000}])
    print('res1:'+ res1.hex())

    principal = PrincipalClass()
    res2 = encode([{'type': principal, 'value':'aaaaa-aa'}])
    print('res2' + res2.hex())

    res = encode([{'type': principal, 'value':'aaaaa-aa'},{'type':nat, 'value':10000000000}])
    print('res:' + res.hex())
