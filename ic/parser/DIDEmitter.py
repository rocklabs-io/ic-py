from ic.candid import Types
from .DIDLexer import DIDLexer
from .DIDParser import DIDParser
from .DIDParserListener import DIDParserListener

class DIDEmitter(DIDParserListener):
    def __init__(self):
        self.data = {
            "nat": Types.Nat,
            "nat8": Types.Nat8,
            'nat16': Types.Nat16,
            'nat32': Types.Nat32,
            'nat64': Types.Nat64,
            'int': Types.Int,
            'int8': Types.Int8,
            'int16': Types.Int16,
            'int32': Types.Int32,
            'int64': Types.Int64,
            'float32': Types.Float32,
	        'float64': Types.Float64,
            'bool': Types.Bool,
            'text': Types.Text,
            'null': Types.Null,
            'reserved': Types.Reserved,
            'empty': Types.Empty,
            'principal': Types.Principal,
            'blob': Types.Vec(Types.Nat8)
        }
        self.rec = {}
        self.datatype = None
        self.datalist = []
        self.cache = {}
        self.argmode = False

    def getParsedData(self, name: str):
        return self.data[name]

    def getDataType(self):
        return self.datatype
    
    def getActor(self):
        try:
            return self.data['actor']
        except:
            raise KeyError("Actor not exist")

    # Exit a parse tree produced by DIDParser#program.
    def exitProgram(self, ctx:DIDParser.ProgramContext):
        self.cache.clear()
        if len(self.rec) != 0:
            raise ValueError("Some type undefined:" + str(self.rec))


    # Exit a parse tree produced by DIDParser#defination.
    def exitDefination(self, ctx:DIDParser.DefinationContext):
        typename = ctx.Name().getText()
        if typename in self.data:
            raise ValueError("Duplicated defination " + typename)
        if typename in self.rec:
            ref = self.rec[typename]
            ref.fill(self.datatype)
            self.data[typename] = ref
            del self.rec[typename]
        else:
            self.data[typename] = self.datatype


    # Exit a parse tree produced by DIDParser#actor.
    def exitActor(self, ctx:DIDParser.ActorContext):
        if ctx.tuptype() != None:
            args = self.cache[ctx.tuptype()]
        else:
            args = []
        if ctx.actortype() != None:
            actor = self.cache[ctx.actortype()]
        else:
            num = len(ctx.Name())
            name = ctx.Name(num - 1)
            actor = self.data[name.getText()]
        self.datatype = {
            "arguments": args,
            "methods": actor
        }
        self.data["actor"] = self.datatype 


    # Exit a parse tree produced by DIDParser#actortype.
    def exitActortype(self, ctx:DIDParser.ActortypeContext):
        actor = {}
        for method in ctx.methodtype():
            m = self.cache[method]
            actor[m[0]] = m[1]
        self.datatype = actor
        self.cache[ctx] = self.datatype


    # Exit a parse tree produced by DIDParser#Name.
    def exitName(self, ctx:DIDParser.NameContext):
        typename = ctx.Name().getText()
        if typename in self.data:
            # already in defined list
            self.datatype = self.data[typename]
        elif typename in self.rec:
            # already in rec list
            self.datatype = self.rec[typename]
        else:
            # new recursive type
            self.rec[typename] = Types.Rec()
            self.datatype = self.rec[typename]
        
        if self.argmode:
            self.cache[ctx] = self.datatype


    # Exit a parse tree produced by DIDParser#Primitive.
    def exitPrimitive(self, ctx:DIDParser.PrimitiveContext):
        prim = ctx.PrimType().getText()
        self.datatype = self.data[prim]

        if self.argmode:
            self.cache[ctx] = self.datatype

    # Exit a parse tree produced by DIDParser#Component.
    def exitComponent(self, ctx:DIDParser.ComponentContext):
        if self.argmode:
            self.cache[ctx] = self.datatype


    # Exit a parse tree produced by DIDParser#Option.
    def exitOption(self, ctx:DIDParser.OptionContext):
        self.datatype = Types.Opt(self.datatype)


    # Exit a parse tree produced by DIDParser#Vector.
    def exitVector(self, ctx:DIDParser.VectorContext):
        self.datatype = Types.Vec(self.datatype)


    # Exit a parse tree produced by DIDParser#EmptyRecord.
    def exitEmptyRecord(self, ctx:DIDParser.EmptyRecordContext):
        self.datatype = Types.Record({})


    # Exit a parse tree produced by DIDParser#Record.
    def exitRecord(self, ctx:DIDParser.RecordContext):
        isTuple = False
        isObject = False
        k = 0
        record = {}
        for field in ctx.recordfield():
            val = self.cache[field]
            if val[0] == None:
                key = "_" + str(k)
                k += 1
                isTuple = True
            else:
                key = val[0]
                isObject = True
            record[key] = val[1]
        if isTuple and isObject:
            raise ValueError("Anonymous record field not support")
        if isTuple:
            self.datatype = Types.Tuple(*record.values())
        else:
            self.datatype = Types.Record(record)

    # Exit a parse tree produced by DIDParser#EmptyVariant.
    def exitEmptyVariant(self, ctx:DIDParser.EmptyVariantContext):
        self.datatype = Types.Variant({})


    # Exit a parse tree produced by DIDParser#Variant.
    def exitVariant(self, ctx:DIDParser.VariantContext):
        variant = {}
        for field in ctx.variantfield():
            val = self.cache[field]
            variant[val[0]] = val[1]
        self.datatype = Types.Variant(variant)


    # Exit a parse tree produced by DIDParser#RecordKV.
    def exitRecordKV(self, ctx:DIDParser.RecordKVContext):
        key = ctx.Name().getText()
        key = key.strip('"')
        self.cache[ctx] = (key, self.datatype)


    # Exit a parse tree produced by DIDParser#RecordData.
    def exitRecordData(self, ctx:DIDParser.RecordDataContext):
        self.cache[ctx] = (None, self.datatype)


    # Exit a parse tree produced by DIDParser#VariantKV.
    def exitVariantKV(self, ctx:DIDParser.VariantKVContext):
        key = ctx.Name().getText()
        key = key.strip('"')
        self.cache[ctx] = (key, self.datatype)


    # Exit a parse tree produced by DIDParser#VariantName.
    def exitVariantName(self, ctx:DIDParser.VariantNameContext):
        key = ctx.Name().getText()
        key = key.strip('"')
        self.cache[ctx] = (key, Types.Null)
    

    # Exit a parse tree produced by DIDParser#functype.
    def exitFunctype(self, ctx:DIDParser.FunctypeContext):
        argCtx = ctx.getChild(0, ttype=DIDParser.TuptypeContext)
        args = self.cache[argCtx]
        retCtx = ctx.getChild(1, ttype=DIDParser.TuptypeContext)
        rets = self.cache[retCtx]
        if ctx.funcann() == None:
            anno = []
        else:
            anno = [ctx.funcann().getText()]
        self.datatype = Types.Func(args, rets, anno)

    # Exit a parse tree produced by DIDParser#EmptyTuple.
    def exitEmptyTuple(self, ctx:DIDParser.EmptyTupleContext):
        self.datatype = []
        self.cache[ctx] = self.datatype


    # Enter a parse tree produced by DIDParser#Tuple.
    def enterTuple(self, ctx:DIDParser.TupleContext):
        self.datalist = []

    # Exit a parse tree produced by DIDParser#Tuple.
    def exitTuple(self, ctx:DIDParser.TupleContext):
        self.datatype = self.datalist
        self.cache[ctx] = self.datatype


    def enterArgtypes(self, ctx: DIDParser.ArgtypesContext):
        self.argmode = True

    # Exit a parse tree produced by DIDParser#argtypes.
    def exitArgtypes(self, ctx:DIDParser.ArgtypesContext):
        for arg in ctx.datatype():
            self.datalist.append(self.cache[arg])
        self.argmode = False


    # Exit a parse tree produced by DIDParser#methodtype.
    def exitMethodtype(self, ctx:DIDParser.MethodtypeContext):
        name = ctx.Name().getText()
        self.datatype = (name, self.datatype)
        self.cache[ctx] = self.datatype