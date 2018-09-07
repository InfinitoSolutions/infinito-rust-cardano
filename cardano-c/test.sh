#!/bin/sh

gcc -o test-cardano-c.$$ -I . ./test/test.c ./dist/cardano-c/x86_64-apple-darwin/debug/libcardano_c.a -lpthread -lm -ldl
echo "######################################################################"
./test-cardano-c.$$
echo ""
echo "######################################################################"
rm test-cardano-c.$$
