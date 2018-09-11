#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "ibl.h"

int wallet_test_ibl(void) {
    static char *address;
    static char *rootkey;

    const char* mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* password  = "password";

    create_rootkey_from_entropy(mnemonics, password, strlen(password), &rootkey);
    if (!rootkey) {
        return -1;
    }

    printf("rootkey: %s\n", rootkey);

    cardano_wallet *wallet = generate_address(rootkey, 0, 0, 0, 1, &address);

    printf("address generated: %s\n", address);

    printf("address is valid: %s\n", cardano_address_is_valid(address) ? "NO" : "YES");

    const char *utxos = "[{\"id\": \"e28c7bf914c855a9ceaf1741a251ab3cc001bd6ccac874b02bacf2f3a40e13c4\", \"index\": 1, \"value\": 731962}]";
    const char *to_addrs = "[{\"addr\": \"Ae2tdPwUPEYxuoq9NbrPB9VodNUmhdBQz9nJBk7UPisyXmPyGje3i9k3x82\",\"value\": 100000}]";
    static char *signed_trx;
    bool result = new_transaction(rootkey, utxos, address, to_addrs, &signed_trx);
    if (result) {
        printf("Signed trx: %s\n", signed_trx);
    } else {
        printf("Failed to create new transaction\n");
    }

    int fee = transaction_fee(rootkey, utxos, address, to_addrs);
    if (fee != 0) {
        printf("Trx Fee: %d\n", fee);
    }

    return 0;
}

int main(int argc, char* argv[]) {
    if (wallet_test_ibl()) exit(35);
    return 0;
}
