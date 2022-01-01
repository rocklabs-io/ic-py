'''

  test candid encode/decode
  include: Null, Nat, Int, Text, Variant, Record, ....

'''

from ic.candid import Types, encode, decode


'''
  @param: Required
      format for example: [{'type': Types.Nat, 'value': 0}, ...]
  @rawTypes: Optional
      if rawTypes is None, decode return 
      However, if you specific return types, it will return what you want.
      rawType accosiated with your did files. In future, we will auto parse
      return types once you provides did file. 
'''
def test(params, rawTypes =  None):
    print('------------------------------------------')
    print('input params:', params)
    res = encode(params)
    print('encode: ', res.hex())
    if rawTypes:
        print('specific return type:', rawTypes)
        print('    decode:', decode(res, rawTypes))
    else:
        print('There is no specific return type:')
        print('    decode:', decode(res))

# Empty Test
types = Types.Empty
val = None
params = [
    {'type': types, 'value': val}
]
# TypeError: Invalid empty argument: None
try:
    encode(params)
except:
    print('Empty encode error: Invalid empty argument: None')

# ValueError: Empty cannot appear as an output
try:
    decode(bytes.fromhex('4449444c00016f'))
except:
    print('Empty decode error: Empty cannot appear as an output')



# Null Test
types = Types.Null
val = None
params = [
    {'type': types, 'value': val}
]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Bool Test
types = Types.Bool
val = True
params = [
    {'type': types, 'value': val}
]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)

# Text Test
types = Types.Text
val1 = 'Rocklabs!'
val2 = "icpy is a good SDK for ic developers"
params = [
    {'type': types, 'value': val1},
    {'type': types, 'value': val2},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=[types, types])

# Int Test
types = Types.Int
val1 = 12345
val2 = -12345
params = [
    {'type': types, 'value': val1},
    {'type': types, 'value': val2},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=[types, types])


# Nat Test
types = Types.Nat
val1 = 12345
val2 = 6789
params = [
    {'type': types, 'value': val1},
    {'type': types, 'value': val2},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=[types, types])

# Float32 and Float64 Test
type1 = Types.Float32
type2 = Types.Float64
val1 = 12.34
val2 = 56.789
params = [
    {'type': type1, 'value': val1},
    {'type': type2, 'value': val2},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=[type1, type2])


# Int8,16,32,64 and Nat8,16,32,64 Test
type1 = Types.Int8
type2 = Types.Int16
type3 = Types.Int32
type4 = Types.Int64

type5 = Types.Nat8
type6 = Types.Nat16
type7 = Types.Nat32
type8 = Types.Nat64

val1 = -113
val2 = -12455
val3 = 13454
val4 = 346745456

val5 = 12
val6 = 35654
val7 = 456787656
val8 = 56789876567654567
params = [
    {'type': type1, 'value': val1},
    {'type': type2, 'value': val2},
    {'type': type3, 'value': val3},
    {'type': type4, 'value': val4},
    {'type': type5, 'value': val5},
    {'type': type6, 'value': val6},
    {'type': type7, 'value': val7},
    {'type': type8, 'value': val8},

]
# There is no specific return type
test(params=params)
# Sepecific return types (part of returns)
test(params=params, rawTypes=[type1, type2, type3])


# Tuple Test
types = Types.Tuple(Types.Nat, Types.Text)
vals = (123456, 'rocklabs')
params = [
    {'type': types, 'value': vals},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Opt Test
types = Types.Opt(Types.Text)
val = ['rocklabs']
params = [
    {'type': types, 'value': val},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Vec Test
types = Types.Vec(Types.Nat)
vals = [1, 2, 3, 4]
params = [
    {'type': types, 'value': vals},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Vec + Tuple Test
types = Types.Vec(Types.Tuple(Types.Nat, Types.Text))
vals = [(123, 'rocklabs')]
params = [
    {'type': types, 'value': vals},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Record Test
types = Types.Record({'name':Types.Text, 'assets': Types.Int})
vals = {'name': 'rocklabs', 'assets': 888888888}
params = [
    {'type': types, 'value': vals},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Tuple(Vec, Record) Test
types = Types.Tuple(Types.Vec(Types.Text), Types.Record({'name':Types.Text, 'assets': Types.Int}))
vals = (['rocklabs'], {'name': 'rocklabs', 'assets': 888888888})
params = [
    {'type': types, 'value': vals},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Variant Test
types = Types.Variant({'ok': Types.Text, 'err': Types.Text})
val = {'ok': 'rocklabs!'}
params = [
    {'type': types, 'value': val},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Tuple(Variant) Test
types = Types.Tuple(Types.Variant({'ok': Types.Text, 'err': Types.Text}))
val = ({'ok': 'rocklabs!'},)
params = [
    {'type': types, 'value': val},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)


# Principle Test
types = Types.Principal
val = 'expmt-gtxsw-inftj-ttabj-qhp5s-nozup-n3bbo-k7zvn-dg4he-knac3-lae'
params = [
    {'type': types, 'value': val},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)

# Opt(Principle Test)
types = Types.Opt(Types.Principal)
val = ['expmt-gtxsw-inftj-ttabj-qhp5s-nozup-n3bbo-k7zvn-dg4he-knac3-lae']
params = [
    {'type': types, 'value': val},

]
# There is no specific return type
test(params=params)
# Sepecific return types
test(params=params, rawTypes=types)
