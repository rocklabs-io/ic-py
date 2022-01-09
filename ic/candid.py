# candid.example.py shows how to use candid's en/decode

import leb128
from struct import pack,unpack
from abc import abstractclassmethod, ABCMeta
from enum import Enum
import math
from .principal import Principal as P
from .utils import labelHash

class TypeIds(Enum):
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
            raise ValueError("Wrong: out of bound")
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
        self._typs = []
        self._idx = {}

    def has(self, obj: ConstructType):
        return True if obj.name in self._idx else False

    def add(self, obj: ConstructType, buf):
        idx = len(self._typs)
        self._idx[obj.name] = idx
        self._typs.append(buf)

    def merge(self, obj: ConstructType, knot:str):
        idx = self._idx[obj.name] if self.has(obj) else None
        knotIdx = self._idx[knot] if knot in self._idx else None
        if idx == None:
            raise ValueError("Missing type index for " + obj.name)
        if knotIdx == None:
            raise ValueError("Missing type index for " + knot)
        self._typs[idx] = self._typs[knotIdx]

        #delete the type
        self._typs.remove(knotIdx)
        del self._idx[knot]

    def encode(self) :
        length = leb128.u.encode(len(self._typs))
        buf = b''.join(self._typs)
        return length + buf
    
    def indexOf(self, typeName:str) :
        if not typeName in self._idx:
            raise ValueError("Missing type index for" + typeName)
        return leb128.i.encode(self._idx[typeName] | 0)


 # Represents an IDL type.
class Type(metaclass=ABCMeta):

    def display(self):
        return self.name

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

    def checkType(self, t: Type):
        if self.name != t.name :
            raise ValueError("type mismatch: type on the wire {}, expect type {}".format(t.name, self.name))
        return t

    def _buildTypeTableImpl(self, typeTable: TypeTable) :
        # No type table encoding for Primitive types.
        return

class ConstructType(Type, metaclass=ABCMeta):
    def __init__(self) -> None:
        super().__init__()

    def checkType(self, t: Type) -> ConstructType :
        if isinstance(t, RecClass):
            ty = t.getType()
            if ty == None:
                raise ValueError("type mismatch with uninitialized type")
            return ty
        else:
            raise ValueError("type mismatch: type on the wire {}, expect type {}".format(type.name, self.name))

    def encodeType(self, typeTable: TypeTable):  
        return typeTable.indexOf(self.name)

# Represents an IDL Empty, a type which has no inhabitants.
class EmptyClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return False
    
    def encodeValue(self, val):
        raise ValueError("Empty cannot appear as a function argument")

    def encodeType(self, typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Empty.value)

    def decodeValue(self, b: Pipe, t: Type):
        raise ValueError("Empty cannot appear as an output")

    @property
    def name(self) -> str:
        return 'empty'

    @property
    def id(self) -> int:
        return TypeIds.Empty.value

# Represents an IDL Bool
class BoolClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, bool)
    
    def encodeValue(self, val):
        return leb128.u.encode(1 if val else 0)

    def encodeType(self, typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Bool.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        byte = safeReadByte(b)
        if leb128.u.decode(byte) == 1:
            return True
        elif leb128.u.decode(byte) == 0:
            return False
        else:
            raise ValueError("Boolean value out of range")

    @property
    def name(self) -> str:
        return 'bool'

    @property
    def id(self) -> int:
        return TypeIds.Bool.value

# Represents an IDL Null
# check None == Null ?
class NullClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return x == None
    
    def encodeValue(self, val):
        return b''

    def encodeType(self, typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Null.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        return None

    @property
    def name(self) -> str:
        return 'null'

    @property
    def id(self) -> int:
        return TypeIds.Null.value

# Represents an IDL Reserved
class ReservedClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return True
    
    def encodeValue(self):
        return b''

    def encodeType(self, typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Reserved.value)

    def decodeValue(self, b: Pipe, t: Type):
        if self.name != t.name:
            t.decodeValue(b, t)
        return None

    @property
    def name(self) -> str:
        return 'reserved'

    @property
    def id(self) -> int:
        return TypeIds.Reserved.value

# Represents an IDL Text
class TextClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, str)
    
    def encodeValue(self, val: str):
        buf = val.encode()
        length = leb128.u.encode(len(buf))
        return  length + buf

    def encodeType(self, typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Text.value)

    def decodeValue(self, b, t: Type):
        self.checkType(t)
        length = leb128uDecode(b)
        buf = safeRead(b, length)
        return buf.decode()

    @property
    def name(self) -> str:
        return 'text'

    @property
    def id(self) -> int:
        return TypeIds.Text.value

# Represents an IDL Int
class IntClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return isinstance(x, int)
    
    def encodeValue(self, val):
        return leb128.i.encode(val)

    def encodeType(self, typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Int.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        return leb128iDecode(b)

    @property
    def name(self) -> str:
        return 'int'

    @property
    def id(self) -> int:
        return TypeIds.Int.value

# Represents an IDL Nat
class NatClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        return x >= 0
    
    def encodeValue(self, val):
        return leb128.u.encode(val)

    def encodeType(self, typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Nat.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        return leb128uDecode(b)

    @property
    def name(self) -> str:
        return 'nat'

    @property
    def id(self) -> int:
        return TypeIds.Nat.value

# Represents an IDL Float
class FloatClass(PrimitiveType):
    def __init__(self, _bits):
        super().__init__()
        self._bits = _bits
        if _bits != 32 and _bits != 64:
            raise ValueError("not a valid float type")

    def covariant(self, x):
        return isinstance(x, float)
    
    def encodeValue(self, val):
        if self._bits == 32:
            buf = pack('f', val)
        elif self._bits == 64:
            buf = pack('d', val)
        else:
            raise ValueError("The length of float have to be 32 bits or 64 bits ")
        return buf

    def encodeType(self, typeTable: TypeTable):
        opcode = TypeIds.Float32.value if self._bits == 32 else TypeIds.Float64.value
        return leb128.i.encode(opcode)

    def decodeValue(self, b: Pipe, t: Type) -> float:
        self.checkType(t)
        by = safeRead(b, self._bits // 8)
        if self._bits == 32:
            return  unpack('f', by)[0]
        elif self._bits == 64:
            return unpack('d', by)[0]
        else:
            raise ValueError("The length of float have to be 32 bits or 64 bits ")

    @property
    def name(self) -> str:
        return 'float' + str(self._bits)

    @property
    def id(self) -> int:
        return TypeIds.Float32.value if self._bits == 32 else TypeIds.Float64.value

# Represents an IDL fixed-width Int(n)
class FixedIntClass(PrimitiveType):
    def __init__(self, _bits):
        super().__init__()
        self._bits = _bits
        if _bits != 8 and _bits != 16 and \
           _bits != 32 and _bits != 64 :
           raise ValueError("bits only support 8, 16, 32, 64")

    def covariant(self, x):
        minVal = -1 * 2 ** (self._bits - 1) 
        maxVal = -1 + 2 ** (self._bits - 1) 
        if x >= minVal and x <= maxVal:
            return True
        else:
            return False
    
    def encodeValue(self, val):
        if self._bits == 8:
            buf = pack('b', val) # signed char -> Int8
        elif self._bits == 16:
            buf = pack('h', val) # short -> Int16
        elif self._bits == 32:
            buf = pack('i', val) # int -> Int32
        elif self._bits == 64:
            buf = pack('q', val) # long long -> Int64
        else:
            raise ValueError("bits only support 8, 16, 32, 64")
        return buf

    def encodeType(self, typeTable: TypeTable):
        offset = int(math.log2(self._bits) - 3)
        return leb128.i.encode(-9 - offset)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        by = safeRead(b, self._bits // 8) 
        if self._bits == 8:
            return unpack('b', by)[0] # signed char -> Int8
        elif self._bits == 16:
            return unpack('h', by)[0] # short -> Int16
        elif self._bits == 32:
            return unpack('i', by)[0] # int -> Int32
        elif self._bits == 64:
            return unpack('q', by)[0] # long long -> Int64
        else:
            raise ValueError("bits only support 8, 16, 32, 64")

    @property
    def name(self) -> str:
        return 'int' + str(self._bits)

    @property
    def id(self) -> int:
        if self._bits == 8:
            return TypeIds.Int8.value
        if self._bits == 16:
            return TypeIds.Int16.value
        if self._bits == 32:
            return TypeIds.Int32.value
        if self._bits == 64:
            return TypeIds.Int64.value

# Represents an IDL fixed-width Nat(n)
class FixedNatClass(PrimitiveType):
    def __init__(self, _bits):
        super().__init__()
        self._bits = _bits
        if _bits != 8 and _bits != 16 and \
           _bits != 32 and _bits != 64 :
           raise ValueError("bits only support 8, 16, 32, 64")

    def covariant(self, x):
        maxVal = -1 + 2 ** self._bits
        if x >= 0 and x <= maxVal:
            return True
        else:
            return False
    
    def encodeValue(self, val):
        if self._bits == 8:
            buf = pack('B', val) # unsigned char -> Nat8
        elif self._bits == 16:
            buf = pack('H', val) # unsigned short -> Nat16
        elif self._bits == 32:
            buf = pack('I', val) # unsigned int -> Nat32
        elif self._bits == 64:
            buf = pack('Q', val) # unsigned long long -> Nat64
        else:
            raise ValueError("bits only support 8, 16, 32, 64")
        return buf

    def encodeType(self, typeTable: TypeTable):
        offset = int(math.log2(self._bits) - 3)
        return leb128.i.encode(-5 - offset)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        by = safeRead(b, self._bits // 8) 
        if self._bits == 8:
            return unpack('B', by)[0] # unsigned char -> Nat8
        elif self._bits == 16:
            return unpack('H', by)[0] # unsigned short -> Nat16
        elif self._bits == 32:
            return unpack('I', by)[0] # unsigned int -> Nat32
        elif self._bits == 64:
            return unpack('Q', by)[0] # unsigned long long -> Nat64
        else:
            raise ValueError("bits only support 8, 16, 32, 64")

    @property
    def name(self) -> str:
        return 'nat' + str(self._bits)

    @property
    def id(self) -> int:
        if self._bits == 8:
            return TypeIds.Nat8.value
        if self._bits == 16:
            return TypeIds.Nat16.value
        if self._bits == 32:
            return TypeIds.Nat32.value
        if self._bits == 64:
            return TypeIds.Nat64.value

# Represents an IDL Array
class VecClass(ConstructType):
    def __init__(self, _type: Type):
        super().__init__()
        self._type = _type

    def covariant(self, x):
        return type(x) == list and not False in list(map(self._type.covariant, x))
    
    def encodeValue(self, val):
        length = leb128.u.encode(len(val))
        vec = list(map(self._type.encodeValue, val))
        return length + b''.join(vec)
        
    def _buildTypeTableImpl(self, typeTable: TypeTable):
        self._type.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Vec.value)
        buffer = self._type.encodeType(typeTable)
        typeTable.add(self, opCode + buffer)

    def decodeValue(self, b: Pipe, t: Type):
        vec = self.checkType(t)
        if not isinstance(vec, VecClass):
            raise ValueError("Not a vector type")
        length = leb128uDecode(b)
        rets = []
        for _ in range(length):
            rets.append(self._type.decodeValue(b, vec._type))
        return rets

    @property
    def name(self) -> str:
        return 'vec ({})'.format(str(self._type.name))

    @property
    def id(self) -> int:
        return TypeIds.Vec.value

    def display(self):
        return 'vec {}'.format(self._type.display())

# Represents an IDL Option
class OptClass(ConstructType):
    def __init__(self, _type: Type):
        super().__init__()
        self._type = _type

    def covariant(self, x):
        return type(x) == list and (len(x) == 0 | (len(x) == 1 and self._type.covariant(x[0])))
    
    def encodeValue(self, val):
        if len(val) == 0:
            return b'\x00'
        else:
            return b'\x01' + self._type.encodeValue(val[0])

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        self._type.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Opt.value)
        buffer = self._type.encodeType(typeTable)
        typeTable.add(self, opCode + buffer)

    def decodeValue(self, b: Pipe, t: Type):
        opt = self.checkType(t)
        if not isinstance(opt, OptClass):
            raise ValueError("Not an option type")
        flag = safeReadByte(b)
        if flag == b'\x00':
            return []
        elif flag == b'\x01':
            return [self._type.decodeValue(b, opt._type)]
        else:
            raise ValueError("Not an option value")

    @property
    def name(self) -> str:
        return 'opt ({})'.format(str(self._type.name))

    @property
    def id(self) -> int:
        return TypeIds.Opt.value

    def display(self):
        return 'opt ({})'.format(self._type.display())

# Represents an IDL Record
class RecordClass(ConstructType):
    def __init__(self, field: dict):
        super().__init__()
        self._fields = dict(sorted(field.items(), key=lambda kv: labelHash(kv[0]))) # check

    def tryAsTuple(self):
        res = []
        idx = 0
        for k, v in self._fields.items():
            if k != "_" + str(idx):
                return None
            res.append(v)
            idx += 1
        return res

    def covariant(self, x: dict):
        if type(x) != dict:
            raise ValueError("Expected dict type input.")
        for k, v in self._fields.items():
            if not k in x:
                raise ValueError("Record is missing key {}".format(k))
            if v.covariant(x[k]):
                continue
            else:
                return False
        return True
    
    def encodeValue(self, val):
        bufs = []
        for k,v in self._fields.items():
            bufs.append(v.encodeValue(val[k]))
        return b''.join(bufs)


    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for _, v in self._fields.items():
            v.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Record.value)
        length = leb128.u.encode(len(self._fields))
        fields = b''
        for k, v in self._fields.items():
            fields += (leb128.u.encode(labelHash(k)) + v.encodeType(typeTable))
        typeTable.add(self, opCode + length + fields)


    def decodeValue(self, b: Pipe, t: Type):
        record = self.checkType(t)
        if not isinstance(record, RecordClass):
            raise ValueError("Not a record type")
        
        x = {}
        idx = 0
        keys = list(self._fields.keys())
        for k, v in record._fields.items() :
            if idx >= len(self._fields) or ( labelHash(keys[idx]) != labelHash(k) ):
                # skip field
                v.decodeValue(b, v)
                continue
            expectKey = keys[idx]
            exceptValue = self._fields[expectKey]
            x[expectKey] = exceptValue.decodeValue(b, v)
            idx += 1
        if idx < len(self._fields):
            raise ValueError("Cannot find field {}".format(keys[idx]))
        return x

    @property
    def name(self) -> str:
        return "record"

    @property
    def id(self) -> int:
        return TypeIds.Record.value

    def display(self):
        d = {}
        for k, v in self._fields.items():
            d[v] = v.display()
        return "record {}".format(d)

# Represents Tuple, a syntactic sugar for Record.
class TupleClass(RecordClass):
    def __init__(self, *_components):
        x = {}
        for i, v in enumerate(_components):
            x['_' + str(i)] = v
        super().__init__(x)
        self._components = _components
    

    def covariant(self, x):
        if type(x) != tuple:
            raise ValueError("Expected tuple type input.")
        for idx, v in enumerate(self._components):
            if v.covariant(x[idx]):
                continue
            else:
                return False
        if len(x) < len(self._fields):
            return False
        return True
    
    def encodeValue(self, val:list):
        bufs = b''
        for i in range(len(self._components)):
            bufs += self._components[i].encodeValue(val[i])
        return bufs


    def decodeValue(self, b: Pipe, t: Type):
        tup = self.checkType(t)
        if not isinstance(tup, TupleClass):
            raise ValueError("not a tuple type")
        if len(tup._components) != len(self._components):
            raise ValueError("tuple mismatch")
        res = []
        for i, wireType in enumerate(tup._components):
            if i >= len(self._components):
                wireType.decodeValue(b, wireType)
            else:
                res.append(self._components[i].decodeValue(b, wireType))
        return res

    @property
    def id(self) -> int:
        return TypeIds.Tuple.value

    def display(self):
        d = []
        for item in self._components:
            d.append(item.display())
        return "record {" + '{}'.format(';'.join(d)) + '}'

# Represents an IDL Variant
class VariantClass(ConstructType):
    def __init__(self, field):
        super().__init__()
        self._fields = dict(sorted(field.items(), key=lambda kv: labelHash(kv[0]))) # check
        

    def covariant(self, x):
        if len(x) != 1:
            return False
        for k, v in self._fields.items():
            if not k in x or v.covariant(x[k]):
                continue
            else:
                return False
        return True
    
    def encodeValue(self, val):
        idx = 0
        for name, ty in self._fields.items():
            if name in val:
                count = leb128.i.encode(idx)
                buf = ty.encodeValue(val[name])
                return count + buf
            idx += 1
        raise ValueError("Variant has no data: {}".format(val))

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for _, v in self._fields.items():
            v.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Variant.value)
        length = leb128.u.encode(len(self._fields))
        fields = b''
        for k, v in self._fields.items():
            fields += leb128.u.encode(labelHash(k)) + v.encodeType(typeTable)
        typeTable.add(self, opCode + length + fields)


    def decodeValue(self, b: Pipe, t: Type):
        variant = self.checkType(t)
        if not isinstance(variant, VariantClass):
            raise ValueError("Not a variant type")
        idx = leb128uDecode(b)
        if idx >= len(variant._fields):
            raise ValueError("Invalid variant index: {}".format(idx))
        keys = list(variant._fields.keys())
        wireHash = keys[idx]
        wireType = variant._fields[wireHash]

        for key, expectType in self._fields.items():
            if labelHash(wireHash) == labelHash(key):
                ret = {}
                value = expectType.decodeValue(b, wireType)
                ret[key] = value
                return ret
        raise ValueError("Cannot find field hash {}".format(wireHash))


    @property
    def name(self) -> str:
        # return 'variant {}'.format(self._fields)
        return 'variant'

    @property
    def id(self) -> int:
        return TypeIds.Variant.value

    def display(self):
        d = {}
        for k, v in self._fields.items():
            d[k] = '' if v.name == None else v.name
        return 'variant {}'.format(d)

# Represents a reference to an IDL type, used for defining recursive data types.
class RecClass(ConstructType):
    _counter = 0
    def __init__(self):
        super().__init__()
        self._id = RecClass._counter
        RecClass._counter += 1
        self._type = None

    def fill(self, t: ConstructType):
        self._type = t
    
    def getType(self):
        return self._type
    
    def covariant(self, x):
        return self._type if self._type.covariant(x) else False
    
    def encodeValue(self, val):
        if self._type == None:
            raise ValueError("Recursive type uninitialized")
        else:
            return self._type.encodeValue(val)

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        if self._type == None:
            raise ValueError("Recursive type uninitialized")
        else:
            typeTable.add(self, b'') # check b'' or []
            self._type.buildTypeTable(typeTable)
            typeTable.merge(self, self._type.name)


    def decodeValue(self, b: Pipe, t: Type):
        if self._type == None:
            raise ValueError("Recursive type uninitialized")
        else:
            return self._type.decodeValue(b, t)

    @property
    def name(self) -> str:
        return labelHash('rec_{}'.format(self._id))


    def display(self):
        if self._type == None:
            raise ValueError("Recursive type uninitialized")
        else:
            return 'μ{}.{}'.format(self.name, self._type.name)
        
# Represents an IDL principal reference
class PrincipalClass(PrimitiveType):
    def __init__(self) -> None:
        super().__init__()

    def covariant(self, x):
        if isinstance(x,str):
            p = P.from_str(x)
        elif isinstance(x, bytes):
            p = P.from_hex(x.hex())
        else:
            raise ValueError("only support string or bytes format")
        return p.isPrincipal

    
    def encodeValue(self, val):
        tag = int.to_bytes(1, 1, byteorder='big')
        if isinstance(val, str):
            buf = P.from_str(val).bytes
        elif isinstance(val, bytes):
            buf = val
        else:
            raise ValueError("Principal should be string or bytes.")
        l = leb128.u.encode(len(buf))
        return tag + l + buf

    def encodeType(self,typeTable: TypeTable):
        return leb128.i.encode(TypeIds.Principal.value)

    def decodeValue(self, b: Pipe, t: Type):
        self.checkType(t)
        res = safeReadByte(b)
        if leb128.u.decode(res) != 1:
            raise ValueError("Cannot decode principal")
        length = leb128uDecode(b)
        return P.from_hex(safeRead(b, length).hex())

    @property
    def name(self) -> str:
        return 'principal'       

    @property
    def id(self) -> int:
        return TypeIds.Principal.value

#Represents an IDL Func reference
class FuncClass(ConstructType):
    def __init__(self, argTypes: list, retTypes: list, annotations: list):
        super().__init__()
        self.argTypes = argTypes
        self.retTypes = argTypes
        self.annotations = annotations

    def covariant(self, x):
        return type(x) == list and len(x) == 2 and x[0] and \
            (P.from_str(x[0]) if type(x[0]) == str else P.from_hex(x[0].hex())).isPrincipal \
            and type(x[1]) == str
 
    def encodeValue(self, vals):
        principal = vals[0]
        methodName = vals[1]
        tag = int.to_bytes(1, 1, byteorder='big')
        if isinstance(principal, str):
            buf = P.from_str(principal).bytes
        elif isinstance(principal, bytes):
            buf = principal
        else:
            raise ValueError("Principal should be string or bytes.")
        l = leb128.u.encode(len(buf))
        canister = tag + l + buf

        method = methodName.encode()
        methodLen = leb128.u.encode(len(method))
        return tag + canister + methodLen + method

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for arg in self.argTypes:
            arg.buildTypeTable(typeTable)
        for ret in self.retTypes:
            ret.buildTypeTable(typeTable)
        
        opCode = leb128.i.encode(TypeIds.Func.value)
        argLen = leb128.u.encode(len(self.argTypes))
        args = b''
        for arg in self.argTypes:
            args += arg.encodeType(typeTable)
        retLen = leb128.u.encode(len(self.retTypes))
        rets = b''
        for ret in self.retTypes:
            rets += ret.encodeType(typeTable)
        annLen = leb128.u.encode(len(self.annotations))
        anns = b''
        for a in self.annotations:
            anns += self._encodeAnnotation(a)
        typeTable.add(self, opCode + argLen + args + retLen + rets + annLen + anns)

    def decodeValue(self, b: Pipe, t: Type):
        x = safeReadByte(b)
        if leb128.u.decode(x) != 1:
            raise ValueError('Cannot decode function reference')
        res = safeReadByte(b)
        if leb128.u.decode(res) != 1:
            raise ValueError("Cannot decode principal")
        length = leb128uDecode(b)
        canister = P.from_hex(safeRead(b, length).hex())
        mLen = leb128uDecode(b)
        buf = safeRead(b, mLen)
        method = buf.decode('utf-8')

        return [canister, method]

    @property
    def name(self) -> str:
        args = ', '.join(arg.name for arg in self.argTypes)       
        rets = ', '.join(ret.name for ret in self.retTypes)
        anns = ' '.join(self.annotations)
        return '({}) → ({}) {}'.format(args, rets, anns)

    @property
    def id(self) -> int:
        return TypeIds.Func.value

    def display(self):
        args = ', '.join(arg.display() for arg in self.argTypes)       
        rets = ', '.join(ret.display() for ret in self.retTypes)
        anns = ' '.join(self.annotations)
        return '({}) → ({}) {}'.format(args, rets, anns)

    def _encodeAnnotation(self, ann: str):
        if ann == 'query':
            return int.to_bytes(1, 1, byteorder='big')
        elif ann == 'oneway':
            return int.to_bytes(2, 1, byteorder='big')
        else:
            raise ValueError('Illeagal function annotation')

# Represents an IDL Service reference
class ServiceClass(ConstructType):
    def __init__(self, field):
        super().__init__()
        self._fields = dict(sorted(field.items(), key=lambda kv: labelHash(kv[0]))) # check

    def covariant(self, x):
        if isinstance(x,str):
            p = P.from_str(x)
        elif isinstance(x, bytes):
            p = P.from_hex(x.hex())
        else:
            raise ValueError("only support string or bytes format")
        return p.isPrincipal

    
    def encodeValue(self, val):
        tag = int.to_bytes(1, 1, byteorder='big')
        if isinstance(val, str):
            buf = P.from_str(val).bytes
        elif isinstance(val, bytes):
            buf = val
        else:
            raise ValueError("Principal should be string or bytes.")
        l = leb128.u.encode(len(buf))
        return tag + l + buf

    def _buildTypeTableImpl(self, typeTable: TypeTable):
        for _, v in self._fields.items():
            v.buildTypeTable(typeTable)
        opCode = leb128.i.encode(TypeIds.Service.value)
        length = leb128.u.encode(len(self._fields))
        fields = b''
        for k, v in self._fields.items():
            fields += leb128.u.encode(len(k.encode())) +  k.encode() + v.encodeType(typeTable)
        typeTable.add(self, opCode + length + fields)

    def decodeValue(self, b: Pipe, t: Type):
        res = safeReadByte(b)
        if leb128.u.decode(res) != 1:
            raise ValueError("Cannot decode principal")
        length = leb128uDecode(b)
        return P.from_hex(safeRead(b, length).hex())

    @property
    def name(self) -> str:
        fields = ''
        for k, v in self._fields.items():
            fields += k + ' : ' + v.name
        return 'service {}'.format(fields)       

    @property
    def id(self) -> int:
        return TypeIds.Service.value

# through Pipe to decode bytes
def leb128uDecode(pipe: Pipe):
    res = b''
    while True:
        byte = safeReadByte(pipe)
        res += byte
        if byte < b'\x80' or pipe.length == 0:
            break
    return leb128.u.decode(res)

def leb128iDecode(pipe: Pipe):
    length = len(pipe._view)
    for i in range(length):
        if pipe._view[i:i+1] < b'\x80':
            if pipe._view[i:i+1] < b'\x40':
                return leb128uDecode(pipe)
            break
    res = safeRead(pipe, i + 1)
    return leb128.i.decode(res)          
        
def safeRead(pipe: Pipe, num:int):
    if pipe.length < num:
        raise ValueError("unexpected end of buffer")
    return pipe.read(num)

def safeReadByte(pipe: Pipe):
    if pipe.length < 1:
        raise ValueError("unexpected end of buffer")
    return pipe.read(1)

def readTypeTable(pipe):
    #types length
    typeTable = []
    typeTable_len = leb128uDecode(pipe)
    for _ in range(typeTable_len):
        ty = leb128iDecode(pipe)
        if ty == TypeIds.Opt.value or ty == TypeIds.Vec.value:
            t = leb128iDecode(pipe)
            typeTable.append([ty, t])
        elif ty == TypeIds.Record.value or ty == TypeIds.Variant.value:
            fields = []
            objLength = leb128uDecode(pipe)
            prevHash = -1
            for _ in range(objLength):
                hash = leb128uDecode(pipe)
                if hash >= math.pow(2, 32):
                    raise ValueError("field id out of 32-bit range")
                if type(prevHash) == int and prevHash >= hash:
                    raise ValueError("field id collision or not sorted")
                prevHash = hash
                t = leb128iDecode(pipe)
                fields.append([hash, t])
            typeTable.append([ty, fields])
        elif ty == TypeIds.Func.value:
            for _ in range(2):
                funLen = leb128uDecode(pipe)
                for _ in range(funLen): leb128iDecode(pipe)
            annLen = leb128uDecode(pipe)
            safeRead(pipe, annLen)
            typeTable.append([ty, None])
        elif ty == TypeIds.Service.value:
            servLen = leb128uDecode(pipe)
            for _ in range(servLen):
                l = leb128uDecode(pipe)
                safeRead(pipe, l)
                leb128iDecode(pipe)
            typeTable.append([ty, None])

        else:
            raise ValueError("Illegal op_code: {}".format(ty))
        
    rawList = []
    types_len = leb128uDecode(pipe)
    for _ in range(types_len):
        rawList.append(leb128iDecode(pipe))
    return typeTable, rawList

def getType(rawTable, table, t:int) -> Type :
    idl = Types()
    if t < -24: 
        raise ValueError("not supported type")
    if t < 0:
        if   t == -1:
            return idl.Null
        elif t == -2:
            return idl.Bool
        elif t == -3:
            return idl.Nat
        elif t == -4:
            return idl.Int
        elif t == -5:
            return idl.Nat8
        elif t == -6:
            return idl.Nat16
        elif t == -7:
            return idl.Nat32
        elif t == -8:
            return idl.Nat64
        elif t == -9:
            return idl.Int8
        elif t == -10:
            return idl.Int16
        elif t == -11:
            return idl.Int32
        elif t == -12:
            return idl.Int64
        elif t == -13:
            return idl.Float32
        elif t == -14:
            return idl.Float64
        elif t == -15:
            return idl.Text
        elif t == -16:
            return idl.Reserved
        elif t == -17:
            return idl.Empty
        elif t == -24:
            return idl.Principal
        else:
            raise ValueError("Illegal op_code:{}".format(t))
    if t >= len(rawTable):
        raise ValueError("type index out of range" )
    return table[t]


def buildType(rawTable, table, entry):
    ty = entry[0]
    if ty == TypeIds.Vec.value:
        if ty >= len(rawTable):
            raise ValueError("type index out of range")
        t = getType(rawTable, table, entry[1])
        if t == None:
            t = table[t]
        return Types.Vec(t)
    elif ty == TypeIds.Opt.value:
        if ty >= len(rawTable):
            raise ValueError("type index out of range")
        t = getType(rawTable, table, entry[1])
        if t == None:
            t = table[t]
        return Types.Opt(t)
    elif ty == TypeIds.Record.value:
        fields = {}
        for hash , t in entry[1]:
            name = '_' + str(hash)
            if t >= len(rawTable):
                raise ValueError("type index out of range")
            temp = getType(rawTable, table, t)
            fields[name] = temp
        record = Types.Record(fields)
        tup = record.tryAsTuple()
        if type(tup) == list:
            return Types.Tuple(*tup)
        else:
            return record
    elif ty == TypeIds.Variant.value:
        fields = {}
        for hash , t in entry[1]:
            name = '_' + str(hash)
            if t >= len(rawTable):
                raise ValueError("type index out of range")
            temp = getType(rawTable, table, t)
            fields[name] = temp
        return Types.Variant(fields)
    elif ty == TypeIds.Func.value:
        return Types.Func([], [], [])
    elif ty == TypeIds.Service.value:
        return Types.Service({})
    else:
        raise ValueError("Illegal op_code: {}".format(ty))
    


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
        raise ValueError("Wrong number of message arguments")
    typetable = TypeTable()
    for item in argTypes:
        item.buildTypeTable(typetable)
    
    pre = prefix.encode()
    table = typetable.encode()
    length = leb128.u.encode(len(args))
    
    typs = b''
    for t in argTypes:
        typs += t.encodeType(typetable)
    vals = b''
    for i in range(len(args)):
        t = argTypes[i]
        if not t.covariant(args[i]):
            raise TypeError("Invalid {} argument: {}".format(t.display(), str(args[i])))
        vals += t.encodeValue(args[i])
    return pre + table + length + typs + vals

# decode a bytes value
# def decode(retTypes, data):
def decode(data, retTypes=None):
    b = Pipe(data)
    if len(data) < len(prefix):
        raise ValueError("Message length smaller than prefix number")
    prefix_buffer = safeRead(b, len(prefix)).decode()
    if prefix_buffer != prefix:
        raise ValueError("Wrong prefix:" + prefix_buffer + 'expected prefix: DIDL')
    rawTable, rawTypes = readTypeTable(b)
    if retTypes:
        if type(retTypes) != list:
            retTypes = [retTypes]
        if len(rawTypes) < len(retTypes):
            raise ValueError("Wrong number of return value")
    
    table = []
    for _ in range(len(rawTable)):
        table.append(Types.Rec())

    for i, entry in enumerate(rawTable):
        t = buildType(rawTable, table, entry)
        table[i].fill(t)

    types = []
    for t in rawTypes:
        types.append(getType(rawTable, table, t))
    outputs = []
    for i, t in enumerate(types if retTypes == None else retTypes):
        outputs.append({
            'type': t.name,
            'value': t.decodeValue(b, types[i])
            })

    return outputs

class Types():
    Null = NullClass()
    Empty = EmptyClass()
    Bool = BoolClass()
    Int = IntClass()
    Reserved = ReservedClass()
    Nat = NatClass()
    Text = TextClass()
    Principal = PrincipalClass()
    Float32 =  FloatClass(32)
    Float64 =  FloatClass(64)
    Int8 =  FixedIntClass(8)
    Int16 =  FixedIntClass(16)
    Int32 =  FixedIntClass(32)
    Int64 =  FixedIntClass(64)
    Nat8 =  FixedNatClass(8)
    Nat16 =  FixedNatClass(16)
    Nat32 =  FixedNatClass(32)
    Nat64 =  FixedNatClass(64)

    def Tuple(*types):
        return TupleClass(*types)

    def Vec(t):
        return VecClass(t)

    def Opt(t):
        return OptClass(t)

    def Record(t):
        return RecordClass(t)

    def Variant(fields):
        return VariantClass(fields)
    
    def Rec():
        return RecClass()

    def Func(args, ret, annotations):
        return FuncClass(args, ret, annotations)

    def Service(t):
        return ServiceClass(t)
