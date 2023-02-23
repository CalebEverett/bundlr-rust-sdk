use crate::error::BundlrError;
use crate::Signer as SignerTrait;
use crate::Verifier as VerifierTrait;

use bytes::Bytes;
// use ed25519_dalek::ed25519::signature::Keypair;
use ed25519_dalek::{Signer, SigningKey, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

pub struct Ed25519Signer {
    keypair: SigningKey,
}

impl Ed25519Signer {
    pub fn new(keypair: SigningKey) -> Ed25519Signer {
        Ed25519Signer { keypair }
    }

    pub fn from_base58(s: &str) -> Self {
        let k = bs58::decode(s).into_vec().expect("Invalid base58 encoding");
        let key: &[u8; 64] = k
            .as_slice()
            .try_into()
            .expect("Couldn't convert base58 key to bytes");

        Self {
            keypair: SigningKey::from_keypair_bytes(key).unwrap(),
        }
    }
}

impl SignerTrait for Ed25519Signer {
    const SIG_TYPE: u16 = 2;
    const SIG_LENGTH: u16 = SIGNATURE_LENGTH as u16;
    const PUB_LENGTH: u16 = PUBLIC_KEY_LENGTH as u16;

    fn sign(&self, message: bytes::Bytes) -> Result<bytes::Bytes, crate::error::BundlrError> {
        Ok(Bytes::copy_from_slice(
            &self.keypair.sign(&message).to_bytes(),
        ))
    }

    fn pub_key(&self) -> bytes::Bytes {
        Bytes::copy_from_slice(&self.keypair.verifying_key().to_bytes())
    }
}

impl VerifierTrait for Ed25519Signer {
    fn verify(
        pk: Bytes,
        message: Bytes,
        signature: Bytes,
    ) -> Result<bool, crate::error::BundlrError> {
        println!(
            "pk:{:?}\nmsg:{:?}\nsig:{:?}",
            &pk[..],
            &message[..],
            &signature[..]
        );
        let mut pk_bytes: [u8; 32] = [0; 32];
        pk.into_iter()
            .enumerate()
            .for_each(|(i, b)| pk_bytes[i] = b);
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap_or_else(|_| {
            panic!(
                "ED25519 public keys must be {} bytes long",
                ed25519_dalek::PUBLIC_KEY_LENGTH
            )
        });

        let mut sig_bytes: [u8; 64] = [0; 64];
        if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
            panic!(
                "ED25519 signature must be {} bytes long",
                ed25519_dalek::SIGNATURE_LENGTH
            )
        }
        signature
            .into_iter()
            .enumerate()
            .for_each(|(i, b)| sig_bytes[i] = b);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        public_key
            .verify(&message, &sig)
            .map(|_| true)
            .map_err(|_| BundlrError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Ed25519Signer, Signer, Verifier};
    use bytes::Bytes;
    use ed25519_dalek::SigningKey;

    #[test]
    fn should_sign_and_verify() {
        let msg = Bytes::from(b"Message".to_vec());

        let base58_secret_key = "kNykCXNxgePDjFbDWjPNvXQRa8U12Ywc19dFVaQ7tebUj3m7H4sF4KKdJwM7yxxb3rqxchdjezX9Szh8bLcQAjb";
        let signer = Ed25519Signer::from_base58(base58_secret_key);
        let sig = signer.sign(msg.clone()).unwrap();
        let pub_key = signer.pub_key();
        assert!(Ed25519Signer::verify(pub_key, msg.clone(), sig).unwrap());

        let keypair = SigningKey::from_keypair_bytes(&[
            237, 158, 92, 107, 132, 192, 1, 57, 8, 20, 213, 108, 29, 227, 37, 8, 3, 105, 196, 244,
            8, 221, 184, 199, 62, 253, 98, 131, 33, 165, 165, 215, 14, 7, 46, 23, 221, 242, 240,
            226, 94, 79, 161, 31, 192, 163, 13, 25, 106, 53, 34, 215, 83, 124, 162, 156, 8, 97,
            194, 180, 213, 179, 33, 68,
        ])
        .unwrap();
        let signer = Ed25519Signer::new(keypair);
        let sig = signer.sign(msg.clone()).unwrap();
        let pub_key = signer.pub_key();

        assert!(Ed25519Signer::verify(pub_key, msg, sig).unwrap());
    }
}
