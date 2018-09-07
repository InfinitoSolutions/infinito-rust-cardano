#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "cardano.h"

static const uint8_t static_wallet_entropy[20] = {42,21,249,243,17,19,171,131,205,63,200,229,123,24,181,200,119,234,25,60};

int wallet_test(void) {
	printf("===============Test 01===============\n");
	static const char* alias = "Test Wallet";
	static char *address;

	cardano_wallet *wallet = cardano_wallet_new(static_wallet_entropy, 20, "", 0);
	if (!wallet) goto error;

	cardano_account *account = cardano_account_create(wallet, alias, 0);
	if (!account) goto error;

	cardano_account_generate_addresses(account, 0, 0, 1, &address);

	printf("address generated: %s\n", address);

	printf("address is valid: %s\n", cardano_address_is_valid(address) ? "NO" : "YES");

	cardano_account_delete(account);

	cardano_wallet_delete(wallet);

	return 0;
error:
	return -1;
}

int wallet_test2(void) {
	printf("===============Test 02===============\n");
	static const char* alias = "Test Wallet";
	static char *address;

	cardano_wallet *wallet = cardano_wallet_new_mnemonics("", 0);
	if (!wallet) goto error;

	cardano_account *account = cardano_account_create(wallet, alias, 0);
	if (!account) goto error;

	cardano_account_generate_addresses(account, 0, 0, 1, &address);

	printf("address generated: %s\n", address);

	printf("address is valid: %s\n", cardano_address_is_valid(address) ? "NO" : "YES");

	cardano_account_delete(account);

	cardano_wallet_delete(wallet);

	return 0;
error:
	return -1;
}

int wallet_test3(void) {
	printf("===============Test 03===============\n");
	static const char* alias = "Test Wallet";
	static char *address;

	cardano_wallet *wallet = cardano_wallet_new_mnemonics_2("", 0);
	if (!wallet) goto error;

	cardano_account *account = cardano_account_create(wallet, alias, 0);
	if (!account) goto error;

	cardano_account_generate_addresses(account, 0, 0, 1, &address);

	printf("address generated: %s\n", address);

	printf("address is valid: %s\n", cardano_address_is_valid(address) ? "NO" : "YES");

	cardano_account_delete(account);

	cardano_wallet_delete(wallet);

	return 0;
error:
	return -1;
}

int wallet_test4(void) {
	printf("===============Test 04===============\n");
	static const char* alias = "Test Wallet";
	static char *address;

	cardano_wallet *wallet = cardano_wallet_new_mnemonics_3("claw quit lamp captain deny sea crunch weekend tornado sugar coin movie leaf arrive vanish", "", 0);
	if (!wallet) goto error;

	cardano_account *account = cardano_account_create(wallet, alias, 0);
	if (!account) goto error;

	cardano_account_generate_addresses(account, 0, 0, 1, &address);

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
	if (wallet_test2()) exit(35);
	if (wallet_test3()) exit(35);
	if (wallet_test4()) exit(35);
	return 0;
}
