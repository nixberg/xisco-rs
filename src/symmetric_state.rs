use subtle::ConstantTimeEq;
use xoodyak::Xoodyak;

pub struct SymmetricState {
    pub(crate) xoodyak: Xoodyak,
    is_keyed: bool,
}

impl SymmetricState {
    pub fn new(id: &[u8]) -> SymmetricState {
        SymmetricState {
            xoodyak: Xoodyak::keyed(&[], id, &[]),
            is_keyed: false,
        }
    }

    pub fn mix_key(&mut self, key: &[u8]) {
        self.xoodyak.absorb(key);
        self.is_keyed = true;
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.xoodyak.absorb(data);
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) {
        assert!(self.is_keyed);
        assert!(ciphertext.len() == plaintext.len() + 16);
        let (ct_only, tag) = ciphertext.split_at_mut(plaintext.len());
        self.xoodyak.encrypt(plaintext, ct_only);
        self.xoodyak.squeeze_to(tag);
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> bool {
        assert!(self.is_keyed);
        assert!(ciphertext.len() == plaintext.len() + 16);
        let (ct_only, tag) = ciphertext.split_at(plaintext.len());
        self.xoodyak.decrypt(ct_only, plaintext);
        let mut new_tag = [0u8; 16];
        self.xoodyak.squeeze_to(&mut new_tag);

        assert_eq!(tag, &new_tag);

        if !bool::from(tag.ct_eq(&new_tag)) {
            for byte in plaintext.iter_mut() {
                *byte = 0;
            }
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
