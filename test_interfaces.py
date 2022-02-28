from ic.canister import Canister
from ic.client import Client
from ic.identity import Identity
from ic.agent import Agent

iden = Identity()
client = Client()
agent = Agent(iden, client)

interfaces = Interfaces(agent)

candidContext = interfaces.candid.candid
print(candidContext)
"""type HttpRequest = record {
  url : text;
  method : text;
  body : vec nat8;
  headers : vec record { text; text };
};
type HttpResponse = record {
  body : vec nat8;
  headers : vec record { text; text };
  status_code : nat16;
};
type Result = variant { Ok; Err : text };
service : {
  binding : (text, text) -> (opt text) query;
  did_to_js : (text) -> (opt text) query;
  http_request : (HttpRequest) -> (HttpResponse) query;
  subtype : (text, text) -> (Result) query;
}"""

candidToJs = interfaces.candid.did_to_js(candidContext)
print(candidToJs)
"""[{'type': 'opt (text)', 'value': ["export const idlFactory = ({ IDL }) => {\n  const HttpRequest = IDL.Record({\n    'url' : IDL.Text,\n    'method' : IDL.Text,\n    'body' : IDL.Vec(IDL.Nat8),\n    'headers' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Text)),\n  });\n  const HttpResponse = IDL.Record({\n    'body' : IDL.Vec(IDL.Nat8),\n    'headers' : IDL.Vec(IDL.Tuple(IDL.Text, IDL.Text)),\n    'status_code' : IDL.Nat16,\n  });\n  const Result = IDL.Variant({ 'Ok' : IDL.Null, 'Err' : IDL.Text });\n  return IDL.Service({\n    'binding' : IDL.Func([IDL.Text, IDL.Text], [IDL.Opt(IDL.Text)], ['query']),\n    'did_to_js' : IDL.Func([IDL.Text], [IDL.Opt(IDL.Text)], ['query']),\n    'http_request' : IDL.Func([HttpRequest], [HttpResponse], ['query']),\n    'subtype' : IDL.Func([IDL.Text, IDL.Text], [Result], ['query']),\n  });\n};\nexport const init = ({ IDL }) => { return []; };"]}]"""
