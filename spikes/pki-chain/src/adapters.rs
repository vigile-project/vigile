// SPDX-License-Identifier: AGPL-3.0-or-later
//! Adaptateur Ed25519 (ed25519-dalek) vers les traits exigés par
//! `x509-cert 0.3` (spki 0.8 + signature 3.0, alors que dalek implémente
//! les versions précédentes via sa feature pkcs8).
//!
//! La signature est portée par valeur ([u8; 64]) car celle de dalek
//! n'expose pas d'emprunt &[u8] : Repr = Self exige AsRef<[u8]>.

use signature::{Error, Keypair, SignatureEncoding, Signer};
use x509_cert::der::asn1::BitString;
use x509_cert::spki::{
    AlgorithmIdentifierOwned, Document, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    ObjectIdentifier, Result as SpkiResult, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

pub const ID_ED25519: &str = "1.3.101.112";

fn ed25519_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap(ID_ED25519),
        parameters: None,
    }
}

/// Signature Ed25519 (64 octets) satisfaisant signature 3.0 / spki 0.8.
#[derive(Clone)]
pub struct Ed25519Sig(pub [u8; 64]);

impl Ed25519Sig {
    pub fn from_dalek(sig: ed25519_dalek::Signature) -> Self {
        Self(sig.to_bytes())
    }
}

impl AsRef<[u8]> for Ed25519Sig {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for Ed25519Sig {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 64] = bytes.try_into().map_err(|_| Error::new())?;
        Ok(Self(arr))
    }
}

impl SignatureEncoding for Ed25519Sig {
    type Repr = Self;
}

impl SignatureBitStringEncoding for Ed25519Sig {
    fn to_bitstring(&self) -> x509_cert::der::Result<BitString> {
        BitString::from_bytes(&self.0)
    }
}

/// Clé publique Ed25519 satisfaisant spki 0.8.
#[derive(Clone)]
pub struct Ed25519Pub(pub ed25519_dalek::VerifyingKey);

impl EncodePublicKey for Ed25519Pub {
    fn to_public_key_der(&self) -> SpkiResult<Document> {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: ed25519_alg_id(),
            subject_public_key: BitString::from_bytes(&self.0.to_bytes())?,
        };
        Document::encode_msg(&spki).map_err(x509_cert::spki::Error::from)
    }
}

/// Signeur Ed25519 satisfaisant les bornes du CrlBuilder.
pub struct Ed25519Signer(pub ed25519_dalek::SigningKey);

impl Signer<Ed25519Sig> for Ed25519Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Sig, Error> {
        use ed25519_dalek::Signer as _;
        self.0
            .try_sign(msg)
            .map(Ed25519Sig::from_dalek)
            .map_err(|_| Error::new())
    }
}

impl Keypair for Ed25519Signer {
    type VerifyingKey = Ed25519Pub;
    fn verifying_key(&self) -> Self::VerifyingKey {
        Ed25519Pub(ed25519_dalek::VerifyingKey::from(&self.0))
    }
}

impl DynSignatureAlgorithmIdentifier for Ed25519Signer {
    fn signature_algorithm_identifier(&self) -> SpkiResult<AlgorithmIdentifierOwned> {
        Ok(ed25519_alg_id())
    }
}
