parser grammar DIDParser;

options {
	tokenVocab = DIDLexer;
}

program: defination* actor?;

defination: Type Name Eq datatype Semicolon;

actor: Service Name? Colon (tuptype Arrow)? (actortype | Name);

actortype: LeftB (methodtype Semicolon)* RightB;

datatype:
	Name		# Name
	| PrimType	# Primitive
	| comptype	# Component;

comptype: constype | reftype;

constype:
	OPT datatype																# Option
	| VEC datatype																# Vector
	| RECORD LeftB RightB														# EmptyRecord
	| RECORD LeftB recordfield (Semicolon recordfield)* Semicolon? RightB		# Record
	| VARIANT LeftB RightB														# EmptyVariant
	| VARIANT LeftB variantfield (Semicolon variantfield)* Semicolon? RightB	# Variant;

recordfield:
	Name Colon datatype	# RecordKV
	| datatype			# RecordData;

variantfield:
	Name Colon datatype	# VariantKV
	| Name				# VariantName;

reftype: FUNC functype | Service actortype;

functype: tuptype Arrow tuptype funcann?;

tuptype:
	LeftP RightP			# EmptyTuple
	| LeftP argtypes RightP	# Tuple;

argtypes: datatype (Comma datatype)* Comma?;

funcann: Query # Query | Oneway # Oneway;

methodtype: Name Colon functype;