use sha2::digest::Update;
use sha2::Sha256;

pub trait Feeder {
    fn feed(self, hasher: &mut Sha256);
}

impl <const N: usize> Feeder for &[u8; N] {
    fn feed(self, hasher: &mut Sha256) {
        hasher.update(&self[..]);
    }
}

impl <const N: usize> Feeder for [u8; N] {
    fn feed(self, hasher: &mut Sha256) {
        self.as_ref().feed(hasher);
    }
}

impl Feeder for &str {
    fn feed(self, hasher: &mut Sha256) {
        self.as_bytes().feed(hasher);
    }
}

impl Feeder for &[u8] {
    fn feed(self, hasher: &mut Sha256) {
        hasher.update(self.as_ref());
    }
}

impl Feeder for Vec<[u8;32]> {
    fn feed(self, hasher: &mut Sha256) {
        for part in self.into_iter() {
            part.feed(hasher);
        }
    }
}

#[macro_export]
macro_rules! hash {
    ( $( $hash_part:expr ),* ) => {{
        let mut hasher = <::sha2::Sha256 as ::sha2::Digest>::new();

        $(
            $crate::crypto::hash::Feeder::feed($hash_part, &mut hasher);
        )*

        <::sha2::Sha256 as ::sha2::Digest>::finalize(hasher).into()
    }};
}