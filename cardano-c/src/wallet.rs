use cardano::wallet::scheme::{Wallet, Account};
use cardano::wallet::bip44;
use cardano::hdwallet;
use cardano::bip;
use cardano::address;
use cardano::util;

use std::os::raw::{c_char};
use std::{ffi, slice, ptr};

use cardano::wallet::bip44::{AddrType};
use cardano::bip::bip39::{MnemonicString, dictionary::ENGLISH};
use cardano::address::ExtendedAddr;
use cardano::util::base58;
use cardano::util::hex;

use cardano::{config::ProtocolMagic, fee, txutils, tx, coin};

const HOST: &'static str = "172.104.88.233:8100";
const PROTOCOL_MAGIC : u32 = 764824073;
/* ******************************************************************************* *
 *                                  Wallet object                                  *
 * ******************************************************************************* */

/// handy type alias for pointer to a heap allocated wallet
type WalletPtr  = *mut bip44::Wallet;
/// handy type alias for pointer to a heap allocated account
type AccountPtr = *mut bip44::Account<hdwallet::XPub>;

// TODO: one of the major missing element is a proper clean error handling

/// Create a HD BIP44 compliant Wallet from the given entropy and a password
///
/// Password can be empty
///
/// use the function `cardano_wallet_delete` to free all the memory associated to the returned
/// object. This function may fail if:
///
/// - panic: if there is no more memory to allocate the object to return
/// - panic or return 0 (nullptr or NULL) if the given seed_ptr is of invalid length
///
#[no_mangle]
pub extern "C"
fn cardano_wallet_new( entropy_ptr: *const u8 /* expecting entropy ptr ... */
                     , entropy_size: usize    /* entropy size */
                     , password_ptr: *const u8 /* password ptr */
                     , password_size: usize    /* password size */
                     ) -> WalletPtr
{
    let entropy_slice = unsafe { slice::from_raw_parts(entropy_ptr, entropy_size) };
    let password = unsafe { slice::from_raw_parts(password_ptr, password_size) };

    let entropy = match bip::bip39::Entropy::from_slice(entropy_slice) {
        Err(_) => return ptr::null_mut(),
        Ok(e) => e,
    };

    let wallet = bip44::Wallet::from_entropy(&entropy, &password, hdwallet::DerivationScheme::V2);

    let wallet_box = Box::new(wallet);
    Box::into_raw(wallet_box)
}

// Create a HD BIP44 compliant Wallet from the given mnemonics
///
/// use the function `cardano_wallet_delete` to free all the memory associated to the returned
/// object. This function may fail if:
///
/// - panic: if there is no more memory to allocate the object to return
/// - panic or return 0 (nullptr or NULL) if the given seed_ptr is of invalid length
///
#[no_mangle]
pub extern "C"
fn cardano_wallet_new_from_mnemonics( mnemonics    : *mut c_char
                     ) -> WalletPtr
{
    let mnemonics = unsafe { ffi::CStr::from_ptr(mnemonics) };
    let mnemonics_str = mnemonics.to_str().unwrap();

    let mnemonics = MnemonicString::new(&ENGLISH, mnemonics_str.to_string()).unwrap();
    let wallet = bip44::Wallet::from_bip39_mnemonics(&mnemonics, b"password", Default::default());

    let wallet_box = Box::new(wallet);
    Box::into_raw(wallet_box)
}

/// take ownership of the given pointer and free the associated data
///
/// The data must be a valid Wallet created by `cardano_wallet_new`.
#[no_mangle]
pub extern "C"
fn cardano_wallet_delete(wallet_ptr: WalletPtr)
{
    unsafe {
        Box::from_raw(wallet_ptr)
    };
}

/* ******************************************************************************* *
 *                                 Account object                                  *
 * ******************************************************************************* */

/// create a new account, the account is given an alias and an index,
/// the index is the derivation index, we do not check if there is already
/// an account with this given index. The alias here is only an handy tool
/// to retrieve a created account from a wallet.
///
/// The returned object is not owned by any smart pointer or garbage collector.
/// To avoid memory leak, use `cardano_account_delete`
///
#[no_mangle]
pub extern "C"
fn cardano_account_create( wallet_ptr: WalletPtr
                         , account_alias: *mut c_char
                         , account_index: u32
                         )
    -> AccountPtr
{
    let wallet = unsafe { wallet_ptr.as_mut() }.expect("Not a NULL PTR");
    let account_alias = unsafe {
        ffi::CStr::from_ptr(account_alias).to_string_lossy()
    };

    let account = wallet.create_account(&account_alias, account_index);
    let account = Box::new(account.public());

    Box::into_raw(account)
}

/// take ownership of the given pointer and free the memory associated
#[no_mangle]
pub extern "C"
fn cardano_account_delete(account_ptr: AccountPtr)
{
    unsafe {
        Box::from_raw(account_ptr)
    };
}

#[no_mangle]
pub extern "C"
fn cardano_account_generate_addresses( account_ptr:  AccountPtr
                                     , internal:     bool
                                     , from_index: u32
                                     , num_indices: usize
                                     , addresses_ptr: *mut *mut c_char
                                     )
    -> usize
{
    let account = unsafe { account_ptr.as_mut() }
        .expect("Not a NULL PTR");

    let addr_type = if internal {
        bip44::AddrType::Internal
    } else {
        bip44::AddrType::External
    };

    account.address_generator(addr_type, from_index)
        .expect("we expect the derivation to happen successfully")
        .take(num_indices)
        .enumerate()
        .map(|(idx, xpub)| {
            let address = address::ExtendedAddr::new_simple(*xpub.unwrap());
            let address = format!("{}", util::base58::encode(&address.to_bytes()));
            // generate a C String (null byte terminated string)
            let c_address = ffi::CString::new(address)
                .expect("base58 strings only contains ASCII chars");
            // make sure the ptr is stored at the right place with alignments and all
            unsafe {
                ptr::write(addresses_ptr.wrapping_offset(idx as isize), c_address.into_raw())
            };
        }).count()
}


/// create a new account, the account is given an alias and an index,
/// the index is the derivation index, we do not check if there is already
/// an account with this given index. The alias here is only an handy tool
/// to retrieve a created account from a wallet.
///
/// The returned object is not owned by any smart pointer or garbage collector.
/// To avoid memory leak, use `cardano_account_delete`
///
#[no_mangle]
pub extern "C"
fn cardano_new_transaction( wallet_ptr: WalletPtr
                            , account_ptr:  AccountPtr
                         )
{
    let wallet = unsafe { wallet_ptr.as_mut() }.expect("Not a NULL PTR");
    let account = unsafe { account_ptr.as_mut() }
        .expect("Not a NULL PTR");

    // 2. create a valid transaction
    let account_number = 0;
    let input_index = 0;
    let input_addr = account.generate_addresses(
        [(bip44::AddrType::External, input_index)].iter()).pop().unwrap();
    let output_addr = account.generate_addresses(
        [(bip44::AddrType::External, input_index + 1)].iter()).pop().unwrap();
    let change_addr = account.generate_addresses(
        [(bip44::AddrType::Internal, input_index + 2)].iter()).pop().unwrap();

    let txin = tx::TxIn::new(tx::TxId::from_slice(&hex::decode("4acd64fbf0950312ac8e75d09bb01a3c7f15c8714643b28c9c3a75b781949fee").unwrap()).unwrap(), 0);
    let addressing = bip44::Addressing::new(account_number, bip44::AddrType::External, input_index).unwrap();
    let txout = tx::TxOut::new(input_addr.clone(), coin::Coin::new(600_000).unwrap());
    let inputs = vec![txutils::Input::new(txin, txout, addressing)];

    let outputs = vec![tx::TxOut::new(output_addr.clone(), coin::Coin::new(400_000).unwrap())];

    let (txaux, fee) = wallet.new_transaction(
        ProtocolMagic::new(PROTOCOL_MAGIC),
        fee::SelectionPolicy::default(),
        inputs.iter(),
        outputs,
        &txutils::OutputPolicy::One(change_addr.clone())).unwrap();

    println!("############## transaction prepared");
    println!("  txaux {}", txaux);
    println!("  tx id {}", txaux.tx.id());
    println!("  from address {}", base58::encode(&input_addr.to_bytes()));
    println!("  to address {}", base58::encode(&output_addr.to_bytes()));
    println!("  change to address {}", base58::encode(&change_addr.to_bytes()));
    println!("  fee: {:?}", fee);
}
