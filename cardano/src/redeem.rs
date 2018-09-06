//! Redeem keys
//!
//! The Redeem was a one off to bootstrap the initial funds of the blockchain.
//! You should not need to create new redeem keys unless you are starting
//! a new hardfork of the main network.
//!
//! On the **mainnet** you can use the redeem keys to claim redeem addresses.
//!

use cryptoxide::{ed25519};
use util::{hex};
use cbor_event::{self, de::RawCbor, se::{Serializer}};
use serde;

use std::{fmt, result, cmp};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Error {
    InvalidPublicKeySize(usize),
    InvalidPrivateKeySize(usize),
    InvalidSignatureSize(usize),
    HexadecimalError(hex::Error)
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::InvalidPublicKeySize(sz) => {
                write!(f, "invalid PublicKey size, expected {} but received {} bytes.", PUBLICKEY_SIZE, sz)
            },
            &Error::InvalidPrivateKeySize(sz) => {
                write!(f, "invalid PrivateKey size, expected {} but received {} bytes.", PRIVATEKEY_SIZE, sz)
            },
            &Error::InvalidSignatureSize(sz) => {
                write!(f, "invalid Signature size, expected {} but received {} bytes.", SIGNATURE_SIZE, sz)
            },
            &Error::HexadecimalError(err) => {
                write!(f, "Invalid hexadecimal input: {}", err)
            }
        }
    }
}
impl From<hex::Error> for Error {
    fn from(e: hex::Error) -> Error { Error::HexadecimalError(e) }
}

pub type Result<T> = result::Result<T, Error>;

pub const PUBLICKEY_SIZE : usize = 32;

#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
pub struct PublicKey([u8;PUBLICKEY_SIZE]);
impl PublicKey {
    pub fn from_bytes(bytes: [u8; PUBLICKEY_SIZE]) -> Self {
        PublicKey(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLICKEY_SIZE { return Err(Error::InvalidPublicKeySize(bytes.len())); }
        let mut buf = [0;PUBLICKEY_SIZE];
        buf[0..PUBLICKEY_SIZE].clone_from_slice(bytes);
        Ok(Self::from_bytes(buf))
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_slice(&bytes)
    }

    pub fn verify(&self, signature: &Signature, bytes: &[u8]) -> bool {
        ed25519::verify(bytes, &self.0, signature.as_ref())
    }
}
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}

pub const PRIVATEKEY_SIZE : usize = 64;

pub struct PrivateKey([u8;PRIVATEKEY_SIZE]);
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl PrivateKey {
    pub fn from_bytes(bytes: [u8; PRIVATEKEY_SIZE]) -> Self {
        PrivateKey(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PRIVATEKEY_SIZE { return Err(Error::InvalidPrivateKeySize(bytes.len())); }
        let mut buf = [0;PRIVATEKEY_SIZE];
        buf[0..PRIVATEKEY_SIZE].clone_from_slice(bytes);
        Ok(Self::from_bytes(buf))
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_slice(&bytes)
    }

    pub fn generate(seed: &[u8]) -> Self {
        let (sk, _) = ed25519::keypair(seed);
        Self::from_bytes(sk)
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::from_bytes(ed25519::to_public(&self.0))
    }

    pub fn sign(&self, bytes: &[u8]) -> Signature {
        Signature::from_bytes(ed25519::signature(bytes, &self.0))
    }
}

const SIGNATURE_SIZE : usize = 64;

pub struct Signature([u8;SIGNATURE_SIZE]);
impl Signature {
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Signature(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_SIZE { return Err(Error::InvalidSignatureSize(bytes.len())); }
        let mut buf = [0;SIGNATURE_SIZE];
        buf[0..SIGNATURE_SIZE].clone_from_slice(bytes);
        Ok(Self::from_bytes(buf))
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex)?;
        Self::from_slice(&bytes)
    }
}
impl Clone for Signature {
    fn clone(&self) -> Self {
        let mut bytes = [0;SIGNATURE_SIZE];
        bytes.copy_from_slice(&self.0);
        Signature(bytes)
    }
}
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] { &self.0 }
}
impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool { PartialEq::eq(&self.0[..], &other.0[..]) }
}
impl Eq for Signature {}
impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        PartialOrd::partial_cmp(&self.0[..], &other.0[..])
    }
}
impl Ord for Signature {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        Ord::cmp(&self.0[..], &other.0[..])
    }
}

// ---------------------------------------------------------------------------
//                                      CBOR
// ---------------------------------------------------------------------------

impl cbor_event::se::Serialize for PublicKey {
    fn serialize<W: ::std::io::Write>(&self, serializer: Serializer<W>) -> cbor_event::Result<Serializer<W>> {
        serializer.write_bytes(self.0.as_ref())
    }
}
impl cbor_event::de::Deserialize for PublicKey {
    fn deserialize<'a>(raw: &mut RawCbor<'a>) -> cbor_event::Result<Self> {
        match PublicKey::from_slice(&raw.bytes()?) {
            Ok(digest) => Ok(digest),
            Err(Error::InvalidPublicKeySize(sz)) => Err(cbor_event::Error::NotEnough(sz, PUBLICKEY_SIZE)),
            Err(err) => Err(cbor_event::Error::CustomError(format!("unexpected error: {:?}", err))),
        }
    }
}

impl cbor_event::se::Serialize for PrivateKey {
    fn serialize<W: ::std::io::Write>(&self, serializer: Serializer<W>) -> cbor_event::Result<Serializer<W>> {
        serializer.write_bytes(self.0.as_ref())
    }
}
impl cbor_event::de::Deserialize for PrivateKey {
    fn deserialize<'a>(raw: &mut RawCbor<'a>) -> cbor_event::Result<Self> {
        match PrivateKey::from_slice(&raw.bytes()?) {
            Ok(digest) => Ok(digest),
            Err(Error::InvalidPrivateKeySize(sz)) => Err(cbor_event::Error::NotEnough(sz, PRIVATEKEY_SIZE)),
            Err(err) => Err(cbor_event::Error::CustomError(format!("unexpected error: {:?}", err))),
        }
    }
}

impl cbor_event::se::Serialize for Signature {
    fn serialize<W: ::std::io::Write>(&self, serializer: Serializer<W>) -> cbor_event::Result<Serializer<W>> {
        serializer.write_bytes(self.0.as_ref())
    }
}
impl cbor_event::de::Deserialize for Signature {
    fn deserialize<'a>(raw: &mut RawCbor<'a>) -> cbor_event::Result<Self> {
        match Signature::from_slice(&raw.bytes()?) {
            Ok(digest) => Ok(digest),
            Err(Error::InvalidSignatureSize(sz)) => Err(cbor_event::Error::NotEnough(sz, SIGNATURE_SIZE)),
            Err(err) => Err(cbor_event::Error::CustomError(format!("unexpected error: {:?}", err))),
        }
    }
}

// ---------------------------------------------------------------------------
//                                      Serde
// ---------------------------------------------------------------------------

impl serde::Serialize for PublicKey
{
    #[inline]
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.as_ref()))
        } else {
            serializer.serialize_bytes(&self.as_ref())
        }
    }
}
struct PublicKeyVisitor();
impl PublicKeyVisitor { fn new() -> Self { PublicKeyVisitor {} } }
impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Expecting a Ed25519 public key (`PublicKey`)")
    }

    fn visit_str<'a, E>(self, v: &'a str) -> result::Result<Self::Value, E>
        where E: serde::de::Error
    {
        match Self::Value::from_hex(v) {
            Err(Error::HexadecimalError(err))    => Err(E::custom(format!("{}", err))),
            Err(Error::InvalidPublicKeySize(sz)) => Err(E::invalid_length(sz, &"32 bytes")),
            Err(err) => Err(E::custom(format!("unexpected error: {}", err))),
            Ok(h) => Ok(h)
        }
    }

    fn visit_bytes<'a, E>(self, v: &'a [u8]) -> result::Result<Self::Value, E>
        where E: serde::de::Error
    {
        match Self::Value::from_slice(v) {
            Err(Error::InvalidPublicKeySize(sz)) => Err(E::invalid_length(sz, &"32 bytes")),
            Err(err) => Err(E::custom(format!("unexpected error: {}", err))),
            Ok(h) => Ok(h)
        }
    }
}
impl<'de> serde::Deserialize<'de> for PublicKey
{
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
        where D: serde::Deserializer<'de>
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(PublicKeyVisitor::new())
        } else {
            deserializer.deserialize_bytes(PublicKeyVisitor::new())
        }
    }
}

impl serde::Serialize for PrivateKey
{
    #[inline]
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.as_ref()))
        } else {
            serializer.serialize_bytes(&self.as_ref())
        }
    }
}
struct PrivateKeyVisitor();
impl PrivateKeyVisitor { fn new() -> Self { PrivateKeyVisitor {} } }
impl<'de> serde::de::Visitor<'de> for PrivateKeyVisitor {
    type Value = PrivateKey;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Expecting a Ed25519 public key (`PrivateKey`)")
    }

    fn visit_str<'a, E>(self, v: &'a str) -> result::Result<Self::Value, E>
        where E: serde::de::Error
    {
        match Self::Value::from_hex(v) {
            Err(Error::HexadecimalError(err))    => Err(E::custom(format!("{}", err))),
            Err(Error::InvalidPrivateKeySize(sz)) => Err(E::invalid_length(sz, &"64 bytes")),
            Err(err) => Err(E::custom(format!("unexpected error: {}", err))),
            Ok(h) => Ok(h)
        }
    }

    fn visit_bytes<'a, E>(self, v: &'a [u8]) -> result::Result<Self::Value, E>
        where E: serde::de::Error
    {
        match Self::Value::from_slice(v) {
            Err(Error::InvalidPrivateKeySize(sz)) => Err(E::invalid_length(sz, &"64 bytes")),
            Err(err) => Err(E::custom(format!("unexpected error: {}", err))),
            Ok(h) => Ok(h)
        }
    }
}
impl<'de> serde::Deserialize<'de> for PrivateKey
{
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
        where D: serde::Deserializer<'de>
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(PrivateKeyVisitor::new())
        } else {
            deserializer.deserialize_bytes(PrivateKeyVisitor::new())
        }
    }
}

impl serde::Serialize for Signature
{
    #[inline]
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
        where S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.as_ref()))
        } else {
            serializer.serialize_bytes(&self.as_ref())
        }
    }
}
struct SignatureVisitor();
impl SignatureVisitor { fn new() -> Self { SignatureVisitor {} } }
impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
    type Value = Signature;

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Expecting a Ed25519 public key (`Signature`)")
    }

    fn visit_str<'a, E>(self, v: &'a str) -> result::Result<Self::Value, E>
        where E: serde::de::Error
    {
        match Self::Value::from_hex(v) {
            Err(Error::HexadecimalError(err))    => Err(E::custom(format!("{}", err))),
            Err(Error::InvalidSignatureSize(sz)) => Err(E::invalid_length(sz, &"64 bytes")),
            Err(err) => Err(E::custom(format!("unexpected error: {}", err))),
            Ok(h) => Ok(h)
        }
    }

    fn visit_bytes<'a, E>(self, v: &'a [u8]) -> result::Result<Self::Value, E>
        where E: serde::de::Error
    {
        match Self::Value::from_slice(v) {
            Err(Error::InvalidSignatureSize(sz)) => Err(E::invalid_length(sz, &"64 bytes")),
            Err(err) => Err(E::custom(format!("unexpected error: {}", err))),
            Ok(h) => Ok(h)
        }
    }
}
impl<'de> serde::Deserialize<'de> for Signature
{
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
        where D: serde::Deserializer<'de>
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(SignatureVisitor::new())
        } else {
            deserializer.deserialize_bytes(SignatureVisitor::new())
        }
    }
}
