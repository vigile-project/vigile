// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ed25519 (ed25519-dalek) adapters towards the trait versions required by
//! `x509-cert 0.3` (spki 0.8 + signature 3.0), which dalek does not
//! implement itself (it only provides spki 0.7 / signature 2.x via its
//! `pkcs8` feature).
//!
//! The signature is carried by value (`[u8; 64]`) because dalek's type
//! exposes no `&[u8]` borrow, and `SignatureEncoding::Repr = Self`
//! requires `AsRef<[u8]>`.

use signature::{Error, Keypair, SignatureEncoding, Signer};
use x509_cert::der::asn1::BitString;
use x509_cert::spki::{
    AlgorithmIdentifierOwned, Document, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    ObjectIdentifier, Result as SpkiResult, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

/// Ed25519 signature algorithm OID (RFC 8410), parameters MUST be absent.
pub const ID_ED25519: &str = "1.3.101.112";

fn ed25519_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap(ID_ED25519),
        parameters: None,
    }
}

/// Ed25519 signature (64 bytes) satisfying signature 3.0 / spki 0.8.
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

impl TryFrom<&[u8]> for Ed25519Sig {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
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

/// Ed25519 public key satisfying spki 0.8.
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

/// Ed25519 signer satisfying the `CrlBuilder` bounds.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // tests: fail fast is acceptable
    use super::*;

    #[test]
    fn signature_roundtrip_from_bytes() {
        let bytes = [7u8; 64];
        let sig = Ed25519Sig::try_from(&bytes[..]).expect("64 bytes accepted");
        assert_eq!(sig.as_ref(), &bytes[..]);
        let too_short = Ed25519Sig::try_from(&bytes[..63]);
        assert!(too_short.is_err());
    }
}
