use subtle::ConstantTimeEq;
use xoodyak::Xoodyak;

pub(crate) enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn value(&self) -> u8 {
        match self {
            Role::Initiator => 0x00,
            Role::Responder => 0xff,
        }
    }
}

pub struct Xisco {
    aborted: bool,
    sender: Xoodyak,
    sender_nonce: u64,
    receiver: Xoodyak,
    receiver_nonce: u64,
}

impl Xisco {
    pub const VERSION: usize = 0;
    pub const TAG_LENGTH: usize = 16;
    pub const MAX_MESSAGE_LENGTH: usize = 65535;

    pub(crate) fn new(key: &[u8], role: Role) -> Xisco {
        Xisco {
            aborted: false,
            sender: Xoodyak::keyed(key, &[role.value()], &[]),
            sender_nonce: 0,
            receiver: Xoodyak::keyed(key, &[!role.value()], &[]),
            receiver_nonce: 0,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8], ciphertext: &mut [u8]) {
        assert!(!self.aborted);
        assert!(plaintext.len() + Xisco::TAG_LENGTH == ciphertext.len());
        assert!(ciphertext.len() + ad.len() <= Xisco::MAX_MESSAGE_LENGTH);
        assert!(self.sender_nonce < std::u64::MAX);

        let mut ephemeral = self.sender.clone();
        ephemeral.absorb(&self.sender_nonce.to_bytes());
        if ad.len() > 0 {
            ephemeral.absorb(ad);
        }
        let (ct_only, tag) = ciphertext.split_at_mut(plaintext.len());
        ephemeral.encrypt(plaintext, ct_only);
        ephemeral.squeeze_to(tag);
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], ad: &[u8], plaintext: &mut [u8]) -> bool {
        assert!(!self.aborted);
        assert!(plaintext.len() + Xisco::TAG_LENGTH == ciphertext.len());
        assert!(ciphertext.len() + ad.len() <= Xisco::MAX_MESSAGE_LENGTH);
        assert!(self.receiver_nonce < std::u64::MAX);

        let mut ephemeral = self.receiver.clone();
        ephemeral.absorb(&self.receiver_nonce.to_bytes());
        if ad.len() > 0 {
            ephemeral.absorb(ad);
        }
        let (ct_only, tag) = ciphertext.split_at(plaintext.len());
        ephemeral.decrypt(ct_only, plaintext);
        let mut new_tag = [0u8; Xisco::TAG_LENGTH];
        ephemeral.squeeze_to(&mut new_tag);

        if bool::from(tag.ct_eq(&new_tag)) {
            return true;
        } else {
            for byte in plaintext.iter_mut() {
                *byte = 0;
            }
            self.aborted = true;
            return false;
        }
    }
}

trait Bytes {
    fn to_bytes(&self) -> Vec<u8>;
}

impl Bytes for u64 {
    fn to_bytes(&self) -> Vec<u8> {
        let le = self.to_le();
        vec![
            (le >> 56 & 0xff) as u8,
            (le >> 48 & 0xff) as u8,
            (le >> 40 & 0xff) as u8,
            (le >> 32 & 0xff) as u8,
            (le >> 24 & 0xff) as u8,
            (le >> 16 & 0xff) as u8,
            (le >> 8 & 0xff) as u8,
            (le >> 0 & 0xff) as u8,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{Role, Xisco};

    #[test]
    fn it_works() {
        let pt = vec![1, 2, 3];

        let mut sender = Xisco::new(&[], Role::Initiator);
        let mut ct = vec![0; pt.len() + Xisco::TAG_LENGTH];
        sender.encrypt(&pt, &[], &mut ct);

        let mut receiver = Xisco::new(&[], Role::Responder);
        let mut new_pt = vec![0; pt.len()];
        receiver.decrypt(&ct, &[], &mut new_pt);
        assert_eq!(pt, new_pt);
    }
}
