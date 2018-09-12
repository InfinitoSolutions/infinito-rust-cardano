#!/bin/sh

# if [ ! -d target/debug ]; then
#   exit 1
# fi

gcc -o test-cardano-c.$$ -I ./ ./test/test_ibl.c target/debug/libcardano_c.a -lpthread -lm -ldl
echo "######################################################################"
./test-cardano-c.$$
echo ""
echo "######################################################################"
rm test-cardano-c.$$
