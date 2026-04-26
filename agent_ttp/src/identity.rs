use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub struct Identity {
    sk: SigningKey,
    vk: VerifyingKey,
}

impl Drop for Identity {
    fn drop(&mut self) {
        let mut bytes = self.sk.to_bytes();
        bytes.zeroize();
    }
}

impl Identity {
    pub fn generate_ephemeral() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        Self { sk, vk }
    }

    pub fn get_vk_bytes(&self) -> [u8; 32] {
        self.vk.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.sk.sign(message).to_bytes()
    }

    pub fn verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let pubkey_bytes: [u8; 32] = match pubkey.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let vk = match VerifyingKey::from_bytes(&pubkey_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let sig = Signature::from_bytes(&sig_bytes);

        vk.verify_strict(message, &sig).is_ok()
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}