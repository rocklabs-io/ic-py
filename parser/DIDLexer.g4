lexer grammar DIDLexer;

BlockComment: '/*' .*? '*/' -> skip;

LineComment: '//' ~[\r\n]* -> skip;

S: [ \t\r\n] -> skip;

Type: 'type';

Query: 'query';

Oneway: 'oneway';

PrimType:
	NumType
	| 'bool'
	| 'text'
	| 'null'
	| 'reserved'
	| 'empty'
	| 'principal';

NumType:
	'nat'
	| 'nat8'
	| 'nat16'
	| 'nat32'
	| 'nat64'
	| 'int'
	| 'int8'
	| 'int16'
	| 'int32'
	| 'int64'
	| 'float32'
	| 'float64';

OPT: 'opt';

VEC: 'vec';

RECORD: 'record';

VARIANT: 'variant';

Service: 'service';

FUNC: 'func';

fragment Letter: [A-Za-z];

fragment DIGIT: [0-9];

fragment NameChar: NameStartChar | '_' | DIGIT;

fragment NameStartChar: [_a-zA-Z];

Name: NameStartChar NameChar*;

LeftP: '(';

RightP: ')';

LeftB: '{';

RightB: '}';

Arrow: '->';

Colon: ':';

Semicolon: ';';

Eq: '=';

Comma: ',';
