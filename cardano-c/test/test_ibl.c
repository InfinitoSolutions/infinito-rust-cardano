#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "ibl.h"

int wallet_test_ibl(void) {
    static const char* alias = "Test Wallet";
    static char *address;
    static char *rootkey;

    const char* mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    const char* password  = "password";

    create_rootkey(mnemonics, password, &rootkey);
    if (!rootkey) {
        return -1;
    }

    printf("rootkey: %s\n", rootkey);

    cardano_wallet *wallet = generate_address(rootkey, alias, 0, 0, 0, 1, &address);

    printf("address generated: %s\n", address);

    printf("address is valid: %s\n", cardano_address_is_valid(address) ? "NO" : "YES");

    const char *utxos = "[{\"id\": \"e28c7bf914c855a9ceaf1741a251ab3cc001bd6ccac874b02bacf2f3a40e13c4\", \"index\": 0, \"value\": 9000000}]";
    const char *to_addrs = "[{\"addr\": \"Ae2tdPwUPEZ3to1tD3ovyREAN5AajAPWuehHRSd5kNkTqgv2zkk4W4v14cS\",\"value\": 100000}]";
    static char *signed_trx;
    bool result = new_transaction(rootkey, utxos, address, to_addrs, &signed_trx);
    printf("Signed trx: %s\n", signed_trx);
    int fee = transaction_fee(rootkey, utxos, address, to_addrs);
    printf("Trx Fee: %d\n", fee);

    return 0;
}

int main(int argc, char* argv[]) {
    if (wallet_test_ibl()) exit(35);
    return 0;
}
