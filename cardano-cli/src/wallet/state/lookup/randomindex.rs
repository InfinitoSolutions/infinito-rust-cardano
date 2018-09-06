use cardano::hdwallet;
use cardano::{address::ExtendedAddr, hdwallet::XPrv};
use cardano::wallet::rindex;

use super::{AddressLookup, Address};
use super::super::{utxo::{UTxO}};

pub struct RandomIndexLookup {
    generator: rindex::AddressGenerator<hdwallet::XPrv>
}
impl From<rindex::Wallet> for RandomIndexLookup {
    fn from(wallet: rindex::Wallet) -> Self {
        RandomIndexLookup {
            generator: wallet.address_generator()
        }
    }
}
impl RandomIndexLookup {
    pub fn new(generator: rindex::AddressGenerator<hdwallet::XPrv>) -> Self {
        RandomIndexLookup {
            generator
        }
    }

    pub fn get_private_key(&self, addr: &rindex::Addressing) -> XPrv {
        self.generator.key(addr)
    }

    pub fn get_address(&self, addr: &rindex::Addressing) -> ExtendedAddr {
        self.generator.address(addr)
    }
}
impl AddressLookup for RandomIndexLookup {
    type Error = rindex::Error;

    /// Random index lookup is more a random index decryption and reconstruction method
    ///
    /// 1. we check if the input address contains a derivation_path (see cardano::address's ExtendedAddress);
    /// 2. we reconstruct the address with the derivation path and check it is actually one of ours;
    ///
    fn lookup(&mut self, utxo: UTxO<ExtendedAddr>) -> Result<Option<UTxO<Address>>, Self::Error> {
        let opt_addressing = self.generator.try_get_addressing(&utxo.credited_address)?;

        match opt_addressing {
            None => Ok(None),
            Some(addressing) => {
                match self.generator.compare_address(&utxo.credited_address, &addressing) {
                    Err(rindex::Error::CannotReconstructAddress) => {
                        // we were not able to reconstruct the wallet's address
                        // it could be due to that:
                        //
                        // 1. this address is using a different derivation scheme;
                        // 2. the address has been falsified (someone copied
                        //    an HDPayload from another of the wallet's addresses and
                        //    put it in one of its address);
                        // 3. that the software needs to be updated.
                        //
                        error!("the address at {} cannot be reconstructed. We managed to actually decode it, but cannot reconstruct the address.", utxo);
                        Err(rindex::Error::CannotReconstructAddress)
                    },
                    Err(err) => {
                        error!("error with the address at `{:?}'", err);
                        Err(err)
                    },
                    Ok(()) => { Ok(Some(utxo.map(|_| addressing.into()))) }
                }
            }
        }
    }

    /// in the case of random index lookup there is nothing to acknowledge
    /// the addresses are self descriptive and we don't need to keep metadata
    /// or state to update.
    ///
    /// This function does nothing and always succeeds
    fn acknowledge<A: Into<Address>>(&mut self, _: A) -> Result<(), Self::Error> {
        Ok(())
    }
}
