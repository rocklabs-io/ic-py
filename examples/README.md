# Candid type - Python type

|Candid|Python|Example|
|------|------|-------|
|bool|bool|True, False|
|int|int|-1|
|int8|int [-128, 127]|-128|
|int16|int [-32768, 32767]|-32768|
|int32|int [-2147483648, 2147483647]|-2147483648|
|int64|int [-922337203685477580, 922337203685477579]|-922337203685477580|
|nat|int >= 0|0|
|nat8|int [0, 255]|255|
|nat16|int [0, 65535]|65535|
|nat32|int [0, 4294967295]|4294967295|
|nat64|int [0, 18446744073709551615]|18446744073709551615|
|float32|float0.1|
|float64|float|3.1415|
|text|str|"hello world"|
|opt|list with length <= 1|Null:[], Some:[1]|
|principal|str, bytes or Principal|"aaaaa-aa"|
|vec|list|[1,2,3]|
|record|dict|{"key": "val"}|
|variant|dict|{"ok": 1}|
|null|None|None|

# Encode parameters:

```python
from ic.candid import encode, decode, Types
# params is an array, return value is encoded bytes
params = [{'type': Types.Nat, 'value': 10}]
data = encode(params)
```

# Decode parameters:

```python
# data is bytes, return value is an parameter array
params = decode(data)
```