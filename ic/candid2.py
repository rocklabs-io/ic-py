from typing import AbstractSet, Any, List, Sequence
import leb128
from abc import abstractclassmethod, ABCMeta
from enum import Enum
import math
from .principal import Principal as P

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
    def buffer(self):
        return self._view

    @property
    def length(self):
        return len(self._view)

    @property
    def end(self) -> bool:
        return self.length == 0

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

    def write(buf):
        pass
    
    def alloc(amount):
        pass


class ConstructType: pass
class TypeTable():
    def __init__(self) -> None:
        self._typs = b''
        self._idx = {}

    def has(self, obj: ConstructType):
        return True if obj._name in self._idx else False

    def add(self, obj: ConstructType, buf):
        idx = len(self._typs)
        self._idx[obj._name] = idx
        self._typs += buf

    def merge(self, obj: ConstructType, knot:str):
        idx = self._idx[obj._name] if self.has(obj) else 'undefined'
        knotIdx = self._idx[knot] if knot in self._idx else 'undefined'
        if idx == 'undefined':
            raise "Missing type index for " + obj._name
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
        if not typeName in self._idx:
            raise "Missing type index for" + typeName
        return leb128.u.encode(self._idx[typeName] | 0)


 # Represents an IDL type.
class Type(metaclass=ABCMeta):
    def __init__(self) -> None:
        self._name = ''

    def display(self):
        return self._name

    def buildTypeTable(self, typeTable: TypeTable):
        if not typeTable.has(self):
            self._buildTypeTableImpl(typeTable)

    @abstractclassmethod
    def covariant(): pass

    @abstractclassmethod
    def decodeValue(): pass
    
    @abstractclassmethod
    def encodeType(): pass

    @abstractclassmethod
    def encodeValue(): pass

    @abstractclassmethod
    def checkType(): pass

    @abstractclassmethod
    def _buildTypeTableImpl(): pass


class PrimitiveType(Type):
    def __init__(self) -> None:
        super().__init__()

    def checkType(self, type: Type):
        if self._name != type._name :
            raise "type mismatch: type on the wire {}, expect type {}".format(type._name, self._name)
        return type

    def _buildTypeTableImpl(self, typeTable: TypeTable) :
        # No type table encoding for Primitive types.
        return

class ConstructType(Type, metaclass=ABCMeta):
    def __init__(self) -> None:
        super().__init__()

    def checkType(self, type: Type) -> ConstructType :
        if isinstance(type, RecClass):
            ty = type.getType()
            if ty == None:
                raise "type mismatch with uninitialized type"
            return ty
        else:
            raise "type mismatch: type on the wire {}, expect type {}".format(type._name, self._name)

    def encodeType(self, typeTable: TypeTable):  
        return typeTable.indexOf(self._name)

# Represents an IDL Empty, a type which has no inhabitants.
class EmptyClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self):
        return False
    
    def encodeValue(self):
        raise "Empty cannot appear as a function argument"

    def encodeType(self):
        return leb128.i.encode(Types.Empty.value)

    def decodeValue(self):
        raise "Empty cannot appear as an output"

    @property
    def name(self) -> str:
        return 'empty'

# Represents an IDL Bool
class BoolClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, bool)
    
    def encodeValue(self, val):
        return leb128.u.encode(1 if val else 0)

    def encodeType(self):
        return leb128.i.encode(Types.Bool.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        byte = safeReadByte(b)
        if leb128.u.decode(byte) == 1:
            return True
        elif leb128.u.decode(byte) == 0:
            return False
        else:
            raise "Boolean value out of range"

    @property
    def name(self) -> str:
        return 'bool'

# Represents an IDL Null
# check None == Null ?
class NullClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return x == None
    
    def encodeValue(self):
        return b''

    def encodeType(self):
        return leb128.i.encode(Types.Null.value)

    def decodeValue(self, t: Type):
        self.checkType(t)
        return None

    @property
    def name(self) -> str:
        return 'null'

# Represents an IDL Reserved
class ReservedClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return True
    
    def encodeValue(self):
        return b''

    def encodeType(self):
        return leb128.i.encode(Types.Reserved.value)

    def decodeValue(self, b: Pipe, t: Type):
        if self._name != t._name:
            t.decodeValue(b, t)
        return None

    @property
    def name(self) -> str:
        return 'reserved'

# Represents an IDL Text
class TextClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, str)
    
    def encodeValue(self, val: str):
        buf = val.encode()
        length = leb128.u.encode(len(buf))
        return  buf + length

    def encodeType(self):
        return leb128.i.encode(Types.Text.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        length = lenDecode(b)
        buf = safeRead(b, length)
        return buf.decode()

    @property
    def name(self) -> str:
        return 'text'

# Represents an IDL Int
class IntClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, int)
    
    def encodeValue(self, val):
        return leb128.i.encode(val)

    def encodeType(self):
        return leb128.i.encode(Types.Int.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        return lenDecode(b)

    @property
    def name(self) -> str:
        return 'int'

# Represents an IDL Nat
class NatClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return x >= 0
    
    def encodeValue(self, val):
        return leb128.u.encode(val)

    def encodeType(self):
        return leb128.i.encode(Types.Nat.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        return lenDecode(b)

    @property
    def name(self) -> str:
        return 'nat'

# Represents an IDL Float
# todo
class FloatClass(PrimitiveType):
    def __init__(self, _bits):
        super().__init__()
        self._bits = _bits
        if _bits != 32 and _bits != 64:
            raise "not a valid float type"

    def covariant(self, x):
        return isinstance(x, float)
    
    def encodeValue(self, val):
        pass

    def encodeType(self):
        opcode = Types.Float32.value if self._bits == 32 else Types.Float64.value
        return leb128.i.encode(opcode)

    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        return 'float' + str(self._bits)

# Represents an IDL fixed-width Int(n)
# todo
class FixedIntClass(PrimitiveType):
    def __init__(self, _bits):
        super().__init__()
        self._bits = _bits

    def covariant(self, x):
        pass
    
    def encodeValue(self, val):
        pass

    def encodeType(self):
        offset = math.log2(self._bits) -3
        return leb128.i.encode(-9 - offset)

    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        return 'int' + str(self._bits)


# Represents an IDL fixed-width Nat(n)
# todo
class FixedNatClass(PrimitiveType):
    def __init__(self, _bits):
        super().__init__()
        self._bits = _bits

    def covariant(self, x):
        pass
    
    def encodeValue(self, val):
        pass

    def encodeType(self):
        offset = math.log2(self._bits) -3
        return leb128.i.encode(-5 - offset)

    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        return 'nat' + str(self._bits)

# Represents an IDL Array
# todo
class VecClass(ConstructType):
    def __init__(self, _type: Type):
        super().__init__()
        self._type = _type
        self._blobOptimization = False
        if isinstance(_type, FixedNatClass) and _type._bits == 8:
            self._blobOptimization = True

    def covariant(self, x):
        pass
    
    def encodeValue(self, val):
        pass

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        pass


    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        return 'vec' + str(self._type.name)

    def display(self):
        return 'vec {}'.format(self._type.display())

# Represents an IDL Option
# todo
class OptClass(ConstructType):
    def __init__(self, _type: Type):
        super().__init__()
        self._type = _type


    def covariant(self, x):
        pass
    
    def encodeValue(self, val):
        pass

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        pass


    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        return 'opt' + str(self._type.name)

    def display(self):
        return 'opt {}'.format(self._type.display())

# Represents an IDL Record
# todo
class OptClass(ConstructType):
    def __init__(self, filed):
        super().__init__()
        self._fields = []
        pass

    def tryAsTuple(self):
        pass

    def covariant(self, x):
        pass
    
    def encodeValue(self, val):
        pass

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        pass


    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        pass

    def display(self):
        pass

# Represents Tuple, a syntactic sugar for Record.
# todo
class TupleClass(ConstructType):
    def __init__(self, _components):
        super().__init__()
        self._components = _components
        pass

    def covariant(self, x):
        pass
    
    def encodeValue(self, val):
        pass

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        pass


    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        pass

    def display(self):
        pass

# Represents an IDL Variant
# todo
class VariantClass(ConstructType):
    def __init__(self, filed):
        super().__init__()
        self._fields = []
        pass

    def covariant(self, x):
        pass
    
    def encodeValue(self, val):
        pass

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        pass


    def decodeValue(self, b: Pipe, t: Type):
        pass

    @property
    def name(self) -> str:
        pass

    def display(self):
        pass

# Represents a reference to an IDL type, used for defining recursive data types.
class RecClass(ConstructType):
    def __init__(self):
        super().__init__()
        self._counter = 0
        self._id = self._counter + 1
        self._type = None

    def fill(self, t: ConstructType):
        self._type = t
    
    def getType(self):
        return self._type
    
    def covariant(self, x):
        return self._type if self._type.covariant(x) else False
    
    def encodeValue(self, val):
        if self._type == None:
            raise "Recursive type uninitialized"
        else:
            return self._type.encodeValue(val)

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        if self._type == None:
            raise "Recursive type uninitialized"
        else:
            typeTable.add(self, b'')
            self._type.buildTypeTable(typeTable)
            typeTable.merge(self, self._type._name)


    def decodeValue(self, b: Pipe, t: Type):
        if self._type == None:
            raise "Recursive type uninitialized"
        else:
            return self._type.decodeValue(b, t)

    @property
    def name(self) -> str:
        return 'rec_{}'.format(self._id)

    def display(self):
        if self._type == None:
            raise "Recursive type uninitialized"
        else:
            return 'μ{}.{}'.format(self.name, self._type._name)
        
# Represents an IDL principal reference
class PrincipalClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return True
    
    def encodeValue(self, val):
        tag = int.to_bytes(1, 1, byteorder='big')
        if isinstance(val, str):
            buf = P.from_str(val).bytes
        elif isinstance(val, bytes):
            buf = val
        else:
            raise "Principal should be string or bytes."
        l = leb128.u.encode(len(buf))
        return tag + l + buf

    def encodeType(self):
        return leb128.i.encode(Types.Principal.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        res = safeReadByte(b)
        if leb128.u.decode(res) != 1:
            raise "Cannot decode principal"
        length = lenDecode(b)
        return P.from_hex(safeRead(b, length).hex())

    @property
    def name(self) -> str:
        return 'principal'       


# through Pipe to decode bytes
def lenDecode(pipe: Pipe):
    weight = 1
    value = 0
    while True:
        byte = safeReadByte(pipe)
        value += (leb128.u.decode(byte) & 0x7f) * weight
        weight = weight << 7
        if byte < b'\x80' or pipe.length == 0:
            break
    return value
            
        
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
    typeTable = []
    typeTable_len = lenDecode(pipe)
    # contruct type todo
    for _ in range(typeTable_len):
        pass
    rawList = []
    types_len = lenDecode(pipe)
    for _ in range(types_len):
        rawList.append(leb128.i.decode(safeReadByte(pipe)))
    return typeTable, rawList

# todo
def getType(t:int) -> Type :
    idl = Interface_IDL()
    if t < -24: 
        raise "not supported type"
    if   t == -1:
        return idl.Null
    elif t == -2:
        return idl.Bool
    elif t == -3:
        return idl.Nat
    elif t == -4:
        return idl.Int
    # elif t == -5:
    #     return idl.Nat8
    # elif t == -6:
    #     return idl.Nat16
    # elif t == -7:
    #     return idl.Nat32
    # elif t == -8:
    #     return idl.Nat64
    # elif t == -9:
    #     return idl.Int8
    # elif t == -10:
    #     return idl.Int16
    # elif t == -11:
    #     return idl.Int32
    # elif t == -12:
    #     return idl.Int64
    # elif t == -13:
    #     return idl.Float32
    # elif t == -14:
    #     return idl.Float64
    elif t == -15:
        return idl.Text
    elif t == -16:
        return idl.Reserved
    elif t == -17:
        return idl.Empty
    elif t == -24:
        return idl.Principal
    else:
        raise "not supported yet"


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
        typs += t.encodeType()
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
    rawTable, rawTypes = readTypeTable(b)
    # todo parse rawTable
    types = map(getType, rawTypes)
    outputs = {}
    for i in types:
        outputs[i.name] = i.decodeValue(b, i)
    return outputs

class Interface_IDL():
    Null = NullClass()
    Empty = EmptyClass()
    Bool = BoolClass()
    Int = IntClass()
    Reserved = ReservedClass()
    Nat = NatClass()
    Text = TextClass()
    Principal = PrincipalClass()
    # not supported yet
    


if __name__ == "__main__":
    # nat = NatClass()
    # res1 = encode([{'type':nat, 'value':10000000000}])
    # print('res1:'+ res1.hex())

    # principal = PrincipalClass()
    # res2 = encode([{'type': principal, 'value':'aaaaa-aa'}])
    # print('res2' + res2.hex())

    # res = encode([{'type': principal, 'value':'aaaaa-aa'},{'type':nat, 'value':10000000000}])
    # print('res:' + res.hex())

    data = b'DIDL\x00\x01q\x08XTC Test'
    print('decode data: {}'.format(data))
    out = decode(data)
    print(out)

    data = b'DIDL\x00\x01}\xe2\x82\xac\xe2\x82\xac\xe2\x80'
    print('decode data: {}'.format(data))
    out = decode(data)
    print(out)

