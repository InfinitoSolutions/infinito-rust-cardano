#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "cardano.h"

static const uint8_t static_wallet_entropy[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };

int wallet_test(void) {
	static const char* alias = "Test Wallet";
	static char *address;

	const char* mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	cardano_wallet *wallet = cardano_wallet_new_from_mnemonics(mnemonics);
	if (!wallet) goto error;

	cardano_account *account = cardano_account_create(wallet, alias, 0);
	if (!account) goto error;

	cardano_account_generate_addresses(account, 1, 0, 1, &address);

	printf("address generated: %s\n", address);

	printf("address is valid: %s\n", cardano_address_is_valid(address) ? "NO" : "YES");

	cardano_account_delete(account);

	cardano_wallet_delete(wallet);

	return 0;
error:
	return -1;
}

int main(int argc, char* argv[]) {

	if (wallet_test()) exit(35);

	const char* mnemonics = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon yes";
	static const char* alias = "address one";
	init_wallet(mnemonics);
	char *address;
	address = new_address(alias);
	printf("address generated: %s\n", address);
	return 0;
}
