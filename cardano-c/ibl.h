#ifndef CARDANO_IBL_RUST_H
#define CARDANO_IBL_RUST_H

/***********/
/* IBL  */
/***********/

typedef struct cardano_wallet cardano_wallet;
typedef struct cardano_account cardano_account;

char *create_rootkey(const char* mnemonics, const char* password);
char *create_rootkey_from_entropy(const char* mnemonics, const char* password, unsigned int password_size);

cardano_wallet *create_wallet(const char *key);
void delete_wallet(cardano_wallet *wallet);
void delete_account(cardano_account *account);

char *generate_address( const char *key, unsigned int index, int internal, 
                        unsigned int from_index, unsigned long num_indices );

int cardano_address_is_valid(const char *address);

char *new_transaction( const char *root_key, const char *utxos, const char *from_addr, const char *to_addrs );
int transaction_fee( const char *root_key, const char *utxos, const char *from_addr, const char *to_addrs);

#endif
