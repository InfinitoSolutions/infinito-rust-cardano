#ifndef CARDANO_IBL_RUST_H
#define CARDANO_IBL_RUST_H

/***********/
/* IBL  */
/***********/

typedef struct cardano_wallet cardano_wallet;
typedef struct cardano_account cardano_account;

void create_rootkey(const char* mnemonics, const char* password, char *root_key[]);
// void create_rootkey2(const char* mnemonics, const char* password, char *root_key[]);

cardano_wallet *create_wallet(const char *key);
void delete_wallet(cardano_wallet *wallet);

cardano_account *create_account(const char *key, const char *alias, unsigned int index);
void delete_account(cardano_account *account);

cardano_wallet *generate_address(const char *key, const char *alias, unsigned int index, int internal, 
                                 unsigned int from_index, unsigned long num_indices, char *address_ptr[]);

int cardano_address_is_valid(const char *address);

#endif
