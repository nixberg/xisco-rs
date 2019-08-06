use rand_os::OsRng;
use rand_os::rand_core::RngCore;

use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use crate::symmetric_state::SymmetricState;
use crate::xisco::{Xisco, Role};

struct KeyPair {
    scalar: Scalar,
    public_key: PublicKey
}

struct PublicKey {
    point: RistrettoPoint,
    bytes: [u8; 32]
}

impl KeyPair {
    fn new() -> KeyPair {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        let point = &scalar * &constants::RISTRETTO_BASEPOINT_TABLE;
        KeyPair {
            scalar: scalar,
            public_key: PublicKey::new(&point)
        }
    }

    fn pk_bytes<'a>(&'a self) -> &'a [u8] {
        &self.public_key.bytes
    }

    fn dh(&self, public_key: &PublicKey) -> [u8; 32] {
        (&self.scalar * &public_key.point).compress().to_bytes()
    }
}

impl PublicKey {
    fn new(point: &RistrettoPoint) -> PublicKey {
        PublicKey {
            point: *point,
            bytes: point.compress().to_bytes()
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<PublicKey> {
        let compressed = CompressedRistretto::from_slice(bytes);
        match compressed.decompress() {
            Some(point) => Some(PublicKey {
                point: point,
                bytes: compressed.to_bytes()
            }),
            None => None
        }
    }
}

pub struct InitiatorNX {
    e: KeyPair,
    symmetric_state: SymmetricState
}

impl InitiatorNX {
    pub fn new() -> InitiatorNX {
        let pattern = [0u8];
        InitiatorNX {
            e: KeyPair::new(),
            symmetric_state: SymmetricState::new(&pattern)
        }
    }

    pub fn write(&mut self, buffer: &mut [u8]) {
        buffer[..32].copy_from_slice(self.e.pk_bytes());
        self.symmetric_state.mix_hash_kp(&self.e);
    }

    pub fn read(&mut self, buffer: &[u8]) {
        let re = PublicKey::from_bytes(&buffer[..32]).unwrap();
        self.symmetric_state.mix_hash_pk(&re);
        self.symmetric_state.mix_key(&self.e.dh(&re));

        let rs = self.symmetric_state.decrypt_pk(&buffer[32..80]).unwrap();
        self.symmetric_state.mix_key(&self.e.dh(&rs));
    }

    pub fn finalize(&mut self) -> Xisco {

        let mut key = vec![0u8; 32];
        self.symmetric_state.xoodyak.squeeze_to(&mut key);
        Xisco::new(&key, Role::Initiator)
    }
}

pub struct ResponderNX {
    s: KeyPair,
    e: KeyPair,
    re: Option<PublicKey>,
    symmetric_state: SymmetricState
}

impl ResponderNX {
    pub fn new() -> ResponderNX {
        let pattern = [0u8];
        ResponderNX {
            e: KeyPair::new(),
            s: KeyPair::new(),
            re: None,
            symmetric_state: SymmetricState::new(&pattern)
        }
    }

    pub fn read(&mut self, buffer: &[u8]) {
        self.re = PublicKey::from_bytes(&buffer[..32]);
        self.symmetric_state.mix_hash_pk(self.re.as_ref().unwrap());
    }

    pub fn write(&mut self, buffer: &mut [u8]) {
        buffer[..32].copy_from_slice(self.e.pk_bytes());
        self.symmetric_state.mix_hash_kp(&self.e);
        self.symmetric_state.mix_key(&self.e.dh(self.re.as_ref().unwrap()));

        self.symmetric_state.encrypt_pk(&self.s, &mut buffer[32..80]);
        self.symmetric_state.mix_key(&self.s.dh(self.re.as_ref().unwrap()));
    }

    pub fn finalize(&mut self) -> Xisco {
        let mut key = vec![0u8; 32];
        self.symmetric_state.xoodyak.squeeze_to(&mut key);
        Xisco::new(&key, Role::Responder)
    }
}

trait SymmetricStateHelpers {
    fn mix_hash_kp(&mut self, key_pair: &KeyPair);
    fn mix_hash_pk(&mut self, public_key: &PublicKey);
    fn encrypt_pk(&mut self, key_pair: &KeyPair, buffer: &mut [u8]);
    fn decrypt_pk(&mut self, buffer: &[u8]) -> Option<PublicKey>;
}

impl SymmetricStateHelpers for SymmetricState {
    fn mix_hash_kp(&mut self, key_pair: &KeyPair) {
        self.mix_hash(&key_pair.public_key.bytes)
    }

    fn mix_hash_pk(&mut self, public_key: &PublicKey) {
        self.mix_hash(&public_key.bytes)
    }

    fn encrypt_pk(&mut self, key_pair: &KeyPair, buffer: &mut [u8]) {
        self.encrypt(&key_pair.public_key.bytes, buffer)
    }

    fn decrypt_pk(&mut self, buffer: &[u8]) -> Option<PublicKey> {
        let mut pk_bytes = [0u8; 32];
        self.decrypt(&buffer, &mut pk_bytes);
        PublicKey::from_bytes(&pk_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{InitiatorNX, ResponderNX};
    use crate::xisco::Xisco;

    #[test]
    fn nx() {
        let mut buffer = vec![0u8; 1024];
        let mut initiator = InitiatorNX::new();
        let mut responder = ResponderNX::new();

        initiator.write(&mut buffer);
        responder.read(&buffer);
        responder.write(&mut buffer);
        initiator.read(&buffer);

        let mut a = initiator.finalize();
        let mut b = responder.finalize();

        let m1 = "Lorem".to_owned().into_bytes();
        let m2 = "ipsum dolor".to_owned().into_bytes();
        let mut e1 = vec![0u8; m1.len() + Xisco::TAG_LENGTH];
        let mut e2 = vec![0u8; m2.len() + Xisco::TAG_LENGTH];
        let mut d1 = vec![0u8; m1.len()];
        let mut d2 = vec![0u8; m2.len()];

        a.encrypt(&m1, &[], &mut e1);
        a.encrypt(&m2, &[], &mut e2);
        b.decrypt(&e1, &[], &mut d1);
        b.decrypt(&e2, &[], &mut d2);

        assert_eq!(m1, d1);
        assert_eq!(m2, d2);

        b.encrypt(&m1, &[], &mut e1);
        a.decrypt(&e1, &[], &mut d1);
        b.encrypt(&m2, &[], &mut e2);
        a.decrypt(&e2, &[], &mut d2);

        assert_eq!(m1, d1);
        assert_eq!(m2, d2);
    }
}
