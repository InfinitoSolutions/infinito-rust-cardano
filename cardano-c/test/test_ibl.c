#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "ibl.h"

int wallet_test_ibl(void) {
    static char *address;
    static char *rootkey;

    const char* mnemonics = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    const char* password  = "password";

    // rootkey = create_rootkey_from_entropy(mnemonics, password, strlen(password));
    rootkey = create_rootkey(mnemonics, password);
    if (!rootkey) {
        return -1;
    }

    printf("rootkey: %s\n", rootkey);

    address = generate_address(rootkey, 0, 0, 0, 1);

    printf("address generated: %s\n", address);

    printf("address is valid: %s\n", cardano_address_is_valid(address) ? "NO" : "YES");

    const char *utxos = "[{\"id\": \"ef81b5ce3628fff9e996acfebd613148171471f2f8a7f486b394d560b08a501c\", \"index\": 1, \"value\": 98731962}]";
    const char *to_addrs = "[{\"addr\": \"Ae2tdPwUPEYzqxHEMBtphXwpCjYoKytf42tC9F3wruqNSkr5hYD6r5eoyas\",\"value\": 10000000}]";
    
    static char *signed_trx;
    signed_trx = new_transaction(rootkey, utxos, address, to_addrs);
    if (signed_trx) {
        printf("Signed trx success\n");
    } else {
        printf("Failed to create new transaction\n");
    }

    int fee = transaction_fee(rootkey, utxos, address, to_addrs);
    if (fee != 0) {
        printf("Trx Fee: %d\n", fee);
    }

    static char *txid;
    txid = get_txid(rootkey, utxos, address, to_addrs);
    if (txid) {
        printf("txid: %s\n", txid);
    } else {
        printf("Failed to get txid\n");
    }

    decode_raw(signed_trx);

    return 0;
}

int main(int argc, char* argv[]) {
    if (wallet_test_ibl()) exit(35);
    return 0;
}
