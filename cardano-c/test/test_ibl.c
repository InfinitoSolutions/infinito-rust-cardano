#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "ibl.h"

int wallet_test_ibl(void) {
    static char *address;
    static char *rootkey;

    const char* mnemonics = "abandon abandon abandon abandon abandon address abandon abandon abandon abandon abandon address";
    const char* password  = "password";

    // rootkey = create_rootkey_from_entropy(mnemonics, password, strlen(password));
    rootkey = create_rootkey(mnemonics, password);
    if (!rootkey) {
        return -1;
    }

    printf("rootkey: %s\n", rootkey);

    address = generate_address(rootkey, 0, 0, 0, 1);

    printf("address generated: %s\n", address);

    printf("address is valid: %s\n", validate_address(address));

    const char *utxos = "[{\"id\": \"364c1e11f5c33d1e49c239a097a4a5f5dec40a03928d9a8db1d6c2604e200927\", \"index\": 0, \"value\": 280000}]";
    const char *to_addrs = "[{\"addr\": \"Ae2tdPwUPEZ3to1tD3ovyREAN5AajAPWuehHRSd5kNkTqgv2zkk4W4v14cS\",\"value\": 100000}]";
    static char *signed_trx;
    signed_trx = new_transaction(rootkey, utxos, address, to_addrs);
    if (signed_trx) {
        printf("Signed trx: %s\n", signed_trx);
    } else {
        printf("Failed to create new transaction\n");
    }

    const char * fee = transaction_fee(rootkey, utxos, address, to_addrs);
    
    printf("Trx Fee: %s\n", fee);

    return 0;
}

int main(int argc, char* argv[]) {
    if (wallet_test_ibl()) exit(35);
    return 0;
}
