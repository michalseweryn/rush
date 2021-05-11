use codec::{Decode, Encode, Input, Error};
use crate::{Index, KeyBox};

pub trait Signable {
    fn bytes_to_sign(&self) -> Vec<u8>;
}

#[derive(Clone, Debug, Decode, Encode)]
pub struct UncheckedSigned<T: Signable + Index, S> {
    pub signable: T,
    pub signature: S
}

#[derive(Debug)]
pub struct Signed<'a, T: Signable + Index, S, KB: KeyBox<S>> {
    pub unchecked: UncheckedSigned<T, S>,
    pub key_box: &'a KB,
}

impl<'a, T: Signable + Index + Clone, S: Clone, KB: KeyBox<S>> Clone for Signed<'a, T, S, KB> {
    fn clone(&self) -> Self {
        Signed {
            unchecked: self.unchecked.clone(),
            key_box: self.key_box,
        }
    }
}

impl<'a, T: Signable + Index, S, KB: KeyBox<S>> Signed<'a, T, S, KB> {
    pub fn sign(key_box: &'a KB, signable: T) -> Self {
        let signature = key_box.sign(&signable.bytes_to_sign());
        let signed = signable;
        Signed {
            unchecked: UncheckedSigned { signable: signed, signature },
            key_box,
        }
    }

    pub fn from(unchecked: UncheckedSigned<T, S>, key_box: &'a KB) -> Option<Self> {
        let index = unchecked.signable.index();
        let signed = Signed { unchecked, key_box };
        if !signed.verify() {
            return None
        }
        Some(signed)
    }

    pub(crate) fn verify(&self) -> bool {
        let signed = &self.unchecked.signable;
        let index = signed.index().unwrap();
        self.key_box.verify(&signed.bytes_to_sign(), &self.unchecked.signature, index)
    }

    pub(crate) fn hash<H>(&self, hashing: impl Fn(&[u8]) -> H) -> H {
        hashing(&self.signed().bytes_to_sign())
    }

    pub(crate) fn signed(&self) -> &T {
        &self.unchecked.signable
    }

    pub(crate) fn signature(&self) -> &S {
        &self.unchecked.signature
    }
}

impl<'a, T: Signable + Index, S, KB: KeyBox<S> + 'a> From<Signed<'a, T, S, KB>> for
    UncheckedSigned<T, S> {
    fn from(signed: Signed<'a, T, S, KB>) -> Self {
        signed.unchecked
    }
}

