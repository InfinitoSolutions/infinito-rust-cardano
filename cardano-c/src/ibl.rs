extern crate cbor_event;
extern crate rustc_serialize;
extern crate serde_json;

use cardano::address;
use cardano::wallet::bip44;
use cardano::util::{self, hex};
use cardano::hdwallet::{self, XPrv};
use cardano::wallet::scheme::{Wallet};
use cardano::bip::bip39::{self, MnemonicString, dictionary::ENGLISH};
use cardano::{config::ProtocolMagic, fee, txutils, tx, coin};
use cardano::util::base58;
use cardano::address::ExtendedAddr;
use cardano::tx::{txaux_serialize};

use std::{ffi, ptr};
use std::os::raw::{c_char};

use rustc_serialize::base64::{self, ToBase64};
use serde_json::{Value, Error, error::ErrorCode};

const PROTOCOL_MAGIC : u32 = 764824073;
const DEBUG: bool = true;
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

    // delete_account(account_ptr);
    wallet_ptr
}

fn cardano_new_transaction  ( root_key  : *mut c_char
                            , utxos     : *mut c_char
                            , from_addr : *mut c_char
                            , to_addrs  : *mut c_char
                            , fee_only  : bool
                            , signed_trx: *mut *mut c_char )
-> Result<fee::Fee, Error> 
{
    // parse input c_char to string
    let utxos = unsafe { ffi::CStr::from_ptr(utxos) };
    let addrs = unsafe { ffi::CStr::from_ptr(to_addrs) };

    let utxos_str = utxos.to_str().unwrap();
    let addrs_str = addrs.to_str().unwrap();

    // Parse the string of data into json
    let utxos_json: Value = serde_json::from_str(&utxos_str.to_string())?;
    let addrs_json: Value = serde_json::from_str(&addrs_str.to_string())?;

    if !utxos_json.is_array() || !addrs_json.is_array() {
        return Err(Error::syntax(ErrorCode::ExpectedObjectOrArray, 1, 1));
    }

    // get input array length
    let utxos_arr_len = utxos_json.as_array().unwrap().len();
    let addrs_arr_len = addrs_json.as_array().unwrap().len();

    if utxos_arr_len <= 0 || addrs_arr_len <= 0 {
        return Err(Error::syntax(ErrorCode::ExpectedObjectOrArray, 1, 1));
    }

    // init wallet from root key
    let mut addr_pointer: *mut c_char = 0 as *mut c_char;
    let address_ptr: *mut *mut i8 = &mut addr_pointer;

    let wallet_ptr = generate_address(root_key, 0, false, 0, 1, address_ptr);
    let wallet     = unsafe {wallet_ptr.as_mut()}.expect("Not a NULL PTR");

    // init input & output of transaction
    let mut inputs = vec![];
    let mut outputs = vec![];

    // convert from_addr from string to ExtendedAddr 
    let from_addr = unsafe {
        ffi::CStr::from_ptr(from_addr).to_string_lossy()
    };

    let from_addr_bytes = base58::decode_bytes(from_addr.as_bytes()).unwrap();
    let from = ExtendedAddr::from_bytes(&from_addr_bytes[..]).unwrap();

    // init transaction input from utxos
    for x in 0..utxos_arr_len {
        let trx_id = &utxos_json[x]["id"].as_str().unwrap();        
        let txin = tx::TxIn::new(tx::TxId::from_slice(&hex::decode(trx_id).unwrap()).unwrap(), utxos_json[x]["index"].to_string().parse::<u32>().unwrap());
        
        let addressing = bip44::Addressing::new(0, bip44::AddrType::External, 0).unwrap();
        let txout = tx::TxOut::new(from.clone(), coin::Coin::new(utxos_json[x]["value"].to_string().parse::<u64>().unwrap()).unwrap());

        inputs.push(txutils::Input::new(txin, txout, addressing));
    }

    // init transaction output from to_address
    for x in 0..addrs_arr_len {
        let to_raw = base58::decode_bytes(addrs_json[x]["addr"].as_str().unwrap().as_bytes()).unwrap();
        let to = ExtendedAddr::from_bytes(&to_raw[..]).unwrap();

        outputs.push(tx::TxOut::new(to.clone(), coin::Coin::new(addrs_json[x]["value"].to_string().parse::<u64>().unwrap()).unwrap()))
    }

    let (txaux, fee) = wallet.new_transaction(
        ProtocolMagic::new(PROTOCOL_MAGIC),
        fee::SelectionPolicy::default(),
        inputs.iter(),
        outputs,
        &txutils::OutputPolicy::One(from.clone())).unwrap();

    if DEBUG {
        println!("############## Transaction prepared #############");
        println!("  txaux {}", txaux);
        println!("  tx id {}", txaux.tx.id());
        println!("  from address {}", from);
        println!("  fee: {:?}", fee);
        println!("###################### End ######################");
    }

    delete_wallet(wallet_ptr);

    if fee_only {
        return Ok(fee);
    }

    // convert raw transaction to string, base64
    let ser = cbor_event::se::Serializer::new_vec();
    let txbytes = txaux_serialize(&txaux.tx, &txaux.witness, ser).unwrap().finalize();
    
    let result = txbytes.to_base64(base64::STANDARD);
    let c_signed_trx = ffi::CString::new(result)
        .expect("Strings only contains ASCII chars");
    // make sure the ptr is stored at the right place with alignments and all
    unsafe {
        ptr::write(signed_trx.wrapping_offset(0 as isize), c_signed_trx.into_raw())
    };

    Ok(fee)
}

#[no_mangle]
pub extern "C"
fn new_transaction( root_key : *mut c_char, utxos : *mut c_char, from_addr : *mut c_char, to_addrs: *mut c_char, signed_trx: *mut *mut c_char )
-> bool
{
    let result = cardano_new_transaction(root_key, utxos, from_addr, to_addrs, false, signed_trx);
    match result {
        Ok(_v) => true,
        Err(_e) => false,
    }
}

#[no_mangle]
pub extern "C"
fn transaction_fee( root_key : *mut c_char, utxos : *mut c_char, from_addr : *mut c_char, to_addrs: *mut c_char ) -> u64
{
    // unusage pointer
    let mut signed_trx_pointer: *mut c_char = 0 as *mut c_char;
    let signed_trx_ptr: *mut *mut i8 = &mut signed_trx_pointer;

    let result = cardano_new_transaction(root_key, utxos, from_addr, to_addrs, true, signed_trx_ptr);
    match result {
        Ok(v) => v.to_coin().to_integral(),
        Err(_e) => 0,
    }
}

