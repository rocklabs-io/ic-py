from ic.parser.DIDEmitter import *;
from antlr4 import *
from antlr4.InputStream import InputStream
from ic.candid import encode

class Canister:
    def __init__(self, agent, canister_id, candid):
        self.agent = agent
        self.canister_id = canister_id
        self.candid = candid

        input_stream = InputStream(candid)
        lexer = DIDLexer(input_stream)
        token_stream = CommonTokenStream(lexer)
        parser = DIDParser(token_stream)
        tree = parser.program()

        emitter = DIDEmitter()
        walker =  ParseTreeWalker()
        walker.walk(emitter, tree)

        self.actor = emitter.getActor()

        for name, method in self.actor["methods"].items():
            anno = None if len(method[2]) == 0 else method[2][0]
            setattr(self, name, CaniterMethod(agent, canister_id, name, method[0], method[1], anno))


class CaniterMethod:
    def __init__(self, agent, canister_id, name, args, rets, anno = None):
        self.agent = agent
        self.canister_id = canister_id
        self.name = name
        self.args = args
        self.rets = rets

        self.anno = anno

    def __call__(self, *args, **kwargs):
        if len(args) != len(self.args):
            raise ValueError("Arguments length not match")
        arguments = []
        for i, arg in enumerate(args):
            arguments.append({"type": self.args[i], "value": arg})

        if self.anno == 'query':
            res = self.agent.query_raw(
                self.canister_id,
                self.name, 
                encode(arguments),
                self.rets
                )
        else:
            res = self.agent.update_raw(
                self.canister_id,
                self.name, 
                encode(arguments),
                self.rets
            )
        return res