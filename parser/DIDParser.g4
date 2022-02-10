parser grammar DIDParser;

options {
	tokenVocab = DIDLexer;
}

program: defination* actor?;

defination: Type Name Eq datatype Semicolon;

actor: Service Name? Colon (tuptype Arrow)? (actortype | Name);

actortype: LeftB (methodtype Semicolon)* RightB;

datatype: Name | PrimType | comptype;

comptype: constype | reftype;

constype:
	OPT datatype
	| VEC datatype
	| RECORD LeftB (recordfield Semicolon)* RightB
	| VARIANT LeftB (variantfield Semicolon)* RightB;

recordfield: Name Colon datatype;

variantfield: recordfield | Name;

reftype: FUNC functype | Service actortype;

functype: tuptype Arrow tuptype funcann*;

tuptype: LeftP RightP | LeftP argtypes RightP;

argtypes: datatype (Comma datatype)*;

funcann: Query | Oneway;

methodtype: Name Colon functype;