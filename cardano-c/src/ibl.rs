extern crate cbor_event;
extern crate rustc_serialize;
extern crate serde_json;
extern crate base64;

use cardano::address;
use cardano::wallet::{bip44, keygen};
use cardano::util::{self, hex};
use cardano::hdwallet::{self, XPrv, XPRV_SIZE};
use cardano::wallet::scheme::{Wallet};
use cardano::bip::bip39::{self, Mnemonics, MnemonicString, dictionary};
use cardano::{config::ProtocolMagic, fee, txutils, tx, coin};
use cardano::util::base58;
use cardano::address::ExtendedAddr;
use cardano::tx::{txaux_serialize};

use cardano::bip;

use std::{ffi, slice, ptr};
use std::os::raw::{c_char};

use rustc_serialize::base64::{ToBase64};
use base64::{encode, decode};
use serde_json::{Value, Error, error::ErrorCode};

const PROTOCOL_MAGIC : u32 = 764824073;
const DEBUG: bool = true;
type WalletPtr  = *mut bip44::Wallet;

#[no_mangle]
pub extern "C"
fn create_rootkey( mnemonics: *const c_char
                 , password:  *const c_char )
-> *mut c_char
{
    let mnemonics     = unsafe {ffi::CStr::from_ptr(mnemonics)};
    let mnemonics_str = mnemonics.to_str().unwrap();
    let mnemonics     = MnemonicString::new(&dictionary::ENGLISH, mnemonics_str.to_string()).unwrap();

    let password      = unsafe {ffi::CStr::from_ptr(password)};
    let password_str  = password.to_str().unwrap();
    let password      = password_str.as_bytes();

    let seed = bip39::Seed::from_mnemonic_string(&mnemonics, &password);
    let xprv = XPrv::generate_from_bip39(&seed);

    ffi::CString::new(xprv.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C"
fn create_rootkey_from_entropy( mnemonics       : *const c_char
                              , password_ptr    : *const u8
                              , password_size   : usize )
-> *mut c_char
{
    let password = unsafe {slice::from_raw_parts(password_ptr, password_size)};
    
    let mnemonics = unsafe {ffi::CStr::from_ptr(mnemonics)};
    let mnemonics_str = mnemonics.to_str().unwrap();
    let mnemonics = match Mnemonics::from_string(&dictionary::ENGLISH, mnemonics_str) {
        Err(_) => return ptr::null_mut(),
        Ok(e) => e,
    };

    let entropy = match bip::bip39::Entropy::from_mnemonics(&mnemonics) {
        Err(_) => return ptr::null_mut(),
        Ok(e) => e,
    };

    let mut seed = [0u8; XPRV_SIZE];
    keygen::generate_seed(&entropy, password, &mut seed);
    let xprv = XPrv::normalize_bytes(seed);

    ffi::CString::new(xprv.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C"
fn create_wallet(root_key: *const c_char)
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

#[derive(Debug)]
struct Address {
    wallet  : WalletPtr,
    address : *mut c_char
}

fn cardano_generate_address ( root_key       : *const c_char
                           , account_index  : u32
                           , internal       : bool
                           , from_index     : u32
                           , num_indices    : usize)
    -> Address
{
    let wallet_ptr = create_wallet(root_key);
    let wallet     = unsafe {wallet_ptr.as_mut()}.expect("Not a NULL PTR");

    let account     = wallet.create_account("", account_index).public();

    let addr_type = if internal {
        bip44::AddrType::Internal
    } else {
        bip44::AddrType::External
    };

    let mut c_address = "".to_owned();
    account.address_generator(addr_type, from_index)
        .expect("we expect the derivation to happen successfully")
        .take(num_indices)
        .enumerate()
        .map(|(_idx, xpub)| {
            let address = address::ExtendedAddr::new_simple(*xpub.unwrap());
            let address = format!("{}", util::base58::encode(&address.to_bytes()));
            c_address   = format!("{}",address);
        }).count();

    Address {
        wallet  : wallet_ptr,
        address : ffi::CString::new(c_address).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C"
fn generate_address ( root_key       : *const c_char
                    , account_index  : u32
                    , internal       : bool
                    , from_index     : u32
                    , num_indices    : usize)
-> *mut c_char
{
    let result = cardano_generate_address(root_key, account_index, internal, from_index, num_indices);
    delete_wallet(result.wallet);
    result.address
}

#[derive(Debug)]
struct Transaction {
    txaux   : tx::TxAux,
    fee     : fee::Fee,
    txid    : *mut c_char
}

fn cardano_new_transaction  ( root_key  : *const c_char
                            , utxos     : *const c_char
                            , from_addr : *const c_char
                            , to_addrs  : *const c_char )
-> Result<Transaction, Error> 
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

    let wallet_ptr = cardano_generate_address(root_key, 0, false, 0, 1).wallet;
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

    let txid = format!("{}", txaux.tx.id());

    delete_wallet(wallet_ptr);
    return Ok(Transaction {
        txaux   : txaux,
        fee     : fee,
        txid    : ffi::CString::new(txid).unwrap().into_raw()
    })
}

#[no_mangle]
pub extern "C"
fn new_transaction( root_key : *const c_char, utxos : *const c_char, from_addr : *const c_char, to_addrs: *const c_char )
-> *mut c_char
{
    let result = cardano_new_transaction(root_key, utxos, from_addr, to_addrs);
    match result {
        Ok(v) => {
            // convert raw transaction to string, base64
            let ser = cbor_event::se::Serializer::new_vec();
            let txbytes = txaux_serialize(&v.txaux.tx, &v.txaux.witness, ser).unwrap().finalize();
            
            let result = txbytes.to_base64(rustc_serialize::base64::STANDARD);
            ffi::CString::new(result).unwrap().into_raw()
        },
        Err(_e) => return ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C"
fn transaction_fee( root_key : *const c_char, utxos : *const c_char, from_addr : *const c_char, to_addrs: *const c_char ) -> u64
{
    let result = cardano_new_transaction(root_key, utxos, from_addr, to_addrs);
    match result {
        Ok(v) => *v.fee.to_coin() as u64,
        Err(_e) => 0,
    }
}

#[no_mangle]
pub extern "C"
fn get_txid( root_key : *const c_char, utxos : *const c_char, from_addr : *const c_char, to_addrs: *const c_char ) -> *mut c_char
{
    let result = cardano_new_transaction(root_key, utxos, from_addr, to_addrs);
    match result {
        Ok(v) => {
            let txid = unsafe { ffi::CStr::from_ptr(v.txid).to_str().unwrap() };
            ffi::CString::new(txid).unwrap().into_raw()
        },
        Err(_e) => return ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C"
fn decode_raw( raw : *const c_char)
{
        // let raw = "goOfggDYGFgkglgg6MUQEk27Jp6YYnQSyYp8ZFyT0b0xEnSTOqxhhvhSY2sB/5+CgtgYWEKDWBzUi80URjMCiZ2tTIOD4MGyALnd4HW109rswwqdoQFYHlgcxdlJsC4jIxzHH/ppHenN2yDvmwjmLrLF6FeJLAAaI6X2cho7i4fAgoLYGFghg1gcjSloNa0rJR3Kg3hoH8p8nUva7ctQCzcjSDqu/KAAGqjQ9W0bAAAAA0KDuDD/oIGCANgYWIWCWEDV82rY3Tcl9dMrAOEBGOecgVamwUppCh0DpzNZKO7x+9NK7ywQAb260xRx9qDJ4jXfa6BxBsZHlp8BWEEaOmzZWECsDHPwjKRgJ1ENI8hDjs5E6ps4WoApM1JXrYen+hx8Z54yWFWBf7wo77a/YM+idUd2fVHmdNiJ38lrqJBU6uoH";
    let rawtx = unsafe { ffi::CStr::from_ptr(raw) };
    let raw_str = rawtx.to_str().unwrap();
    let raw_bytes = &decode(raw_str).unwrap()[..];

    let _txaux : tx::TxAux = cbor_event::de::RawCbor::from(raw_bytes).deserialize().expect("to decode a TxAux");
    let mut raw = cbor_event::de::RawCbor::from(raw_bytes);
    let _txaux : tx::TxAux = cbor_event::de::Deserialize::deserialize(&mut raw).unwrap();
    
    println!("############## Transaction Decode #############");
    println!("  raw_bytes {}", raw_bytes.len());
    println!("  txaux {}", _txaux);
    println!("  tx id {}", _txaux.tx.id());
    println!("###################### End ######################");
}


