#/bin/bash

ROOT_DIR=$(cd $(dirname $0); pwd)

java -jar antlr-4.9.3-complete.jar -Dlanguage=Python3 DIDLexer.g4 DIDParser.g4 -o dist