use cardano::address;
use cardano::wallet::bip44;
use cardano::util::{self, hex};
use cardano::hdwallet::{self, XPrv};
use cardano::wallet::scheme::{Wallet};
use cardano::bip::bip39::{self, MnemonicString, dictionary::ENGLISH};

use std::{ffi, ptr};
use std::os::raw::{c_char};

type WalletPtr  = *mut bip44::Wallet;
type AccountPtr = *mut bip44::Account<hdwallet::XPub>;

#[no_mangle]
pub extern "C"
fn create_rootkey( mnemonics: *mut c_char
                 , password:  *mut c_char
                 , root_key:  *mut *mut c_char)
{
    let mnemonics     = unsafe {ffi::CStr::from_ptr(mnemonics)};
    let mnemonics_str = mnemonics.to_str().unwrap();
    let mnemonics     = MnemonicString::new(&ENGLISH, mnemonics_str.to_string()).unwrap();

    let password      = unsafe {ffi::CStr::from_ptr(password)};
    let password_str  = password.to_str().unwrap();
    let password      = password_str.as_bytes();

    let seed = bip39::Seed::from_mnemonic_string(&mnemonics, &password);
    let xprv = XPrv::generate_from_bip39(&seed);

    let xprv_ptr = ffi::CString::new(xprv.to_string()).expect("base58 strings only contains ASCII chars");
    unsafe {
        ptr::write(root_key, xprv_ptr.into_raw())
    };
}

// fn create_rootkey2( mnemonics: *mut c_char
//                  , password:  *mut c_char
//                  , root_key:  *mut *mut c_char)
// {
//     let mnemonics     = unsafe {ffi::CStr::from_ptr(mnemonics)};
//     let mnemonics_str = mnemonics.to_str().unwrap();
//     let mnemonics     = MnemonicString::new(&ENGLISH, mnemonics_str.to_string()).unwrap();

//     let password      = unsafe {ffi::CStr::from_ptr(password)};
//     let password_str  = password.to_str().unwrap();
//     let password      = password_str.as_bytes();

//     let entropy = match Entropy::from_mnemonics(&mnemonics) { 
//         Err(_) => return ptr::null_mut(), 
//         Ok(e) => e, 
//     };
//     let mut seed = [0u8; XPRV_SIZE];
//     keygen::generate_seed(&entropy, &password, &mut seed);
//     let xprv = XPrv::normalize_bytes(seed);


//     // let seed = bip39::Seed::from_mnemonic_string(&mnemonics, &password);
//     // let xprv = XPrv::generate_from_bip39(&seed);

//     let xprv_ptr = ffi::CString::new(xprv.to_string()).expect("base58 strings only contains ASCII chars");
//     unsafe {
//         ptr::write(root_key, xprv_ptr.into_raw())
//     };
// }

#[no_mangle]
pub extern "C"
fn create_wallet(root_key: *mut c_char)
    -> WalletPtr
{
    let root_key = unsafe {
        ffi::CStr::from_ptr(root_key).to_string_lossy()
    };

    let xprv_vec = hex::decode(&root_key).unwrap();
    let mut xprv_bytes = [0; hdwallet::XPRV_SIZE];
    xprv_bytes.copy_from_slice(&xprv_vec[..]);

    let root_xprv  = hdwallet::XPrv::from_bytes_verified(xprv_bytes).unwrap();
    let wallet     = bip44::Wallet::from_root_key(root_xprv, Default::default());
    let wallet_box = Box::new(wallet);

    Box::into_raw(wallet_box)
}

#[no_mangle]
pub extern "C"
fn delete_wallet(wallet_ptr: WalletPtr) 
{
    unsafe {
        Box::from_raw(wallet_ptr)
    };
}

// #[no_mangle]
// pub extern "C"
// fn create_account( root_key: *mut c_char
//                  , account_alias: *mut c_char
//                  , account_index: u32)
//     -> AccountPtr
// {
//     let wallet_ptr = create_wallet(root_key);
//     let wallet     = unsafe {wallet_ptr.as_mut()}.expect("Not a NULL PTR");

//     let account_alias = unsafe {
//         ffi::CStr::from_ptr(account_alias).to_string_lossy()
//     };

//     let account     = wallet.create_account(&account_alias, account_index);
//     let account_box = Box::new(account.public()); 

//     delete_wallet(wallet_ptr);

//     Box::into_raw(account_box)
// }

#[no_mangle]
pub extern "C"
fn delete_account(account_ptr: AccountPtr)
{
    unsafe {
        Box::from_raw(account_ptr)
    };
}

#[no_mangle]
pub extern "C"
fn generate_address( root_key: *mut c_char
                   , account_alias: *mut c_char
                   , account_index: u32
                   , internal: bool
                   , from_index: u32
                   , num_indices: usize
                   , address_ptr: *mut *mut c_char)
    -> WalletPtr
{
    let wallet_ptr = create_wallet(root_key);
    let wallet     = unsafe {wallet_ptr.as_mut()}.expect("Not a NULL PTR");
    // let account_ptr = create_account(root_key, account_alias, account_index);
    // let account     = unsafe {account_ptr.as_mut()}.expect("Not a NULL PTR");

    let account_alias = unsafe {
        ffi::CStr::from_ptr(account_alias).to_string_lossy()
    };


    let account     = wallet.create_account(&account_alias, account_index);
    let account_box = Box::new(account.public()); 
    let account_ptr = Box::into_raw(account_box);
    let account     = unsafe {account_ptr.as_mut()}.expect("Not a NULL PTR");

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

            let c_address = ffi::CString::new(address).expect("base58 strings only contains ASCII chars");

            unsafe {
                ptr::write(address_ptr.wrapping_offset(idx as isize), c_address.into_raw())
            };
        }).count();

    delete_account(account_ptr);
    wallet_ptr
}
