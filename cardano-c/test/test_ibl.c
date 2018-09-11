#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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

    return 0;
}

int main(int argc, char* argv[]) {
    if (wallet_test_ibl()) exit(35);
    return 0;
}
