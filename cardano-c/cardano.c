#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "cardano.h"

static cardano_wallet *wallet = NULL;

/*
 * Create new wallet from a mnemonics
 *
 */

bool init_wallet(const char* mnemonics) {
	if (mnemonics == NULL) {
		return false;
	}

	if (wallet != NULL) {
		printf("Warn: Old wallet is destroyed to create new wallet\n");
		cardano_wallet_delete(wallet);
	}

	wallet = cardano_wallet_new_from_mnemonics(mnemonics);
	if (wallet) {
		return true;
	}

	return false;
}

/*
 * create a new account, the account is given an alias and an index,
 * the index is the derivation index, we do not check if there is already
 * an account with this given index. The alias here is only an handy tool
 * to retrieve a created account from a wallet.
 */

char* new_address(const char* alias) {
	if (wallet == NULL) {
		return NULL;
	}

	cardano_account *account = cardano_account_create(wallet, alias, 0);
	if (!account) {
		return NULL;
	}

	char *address = NULL;
	int internal = 0;
	unsigned int from_index = 0;
	unsigned int num_indices = 1;
	cardano_account_generate_addresses(account, internal, from_index, num_indices, &address);
	if (!address) {
		return NULL;
	}

	return address;
}