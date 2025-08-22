pub trait PrivateSignatureKey<const N: usize> {
    const SIGNATURE_BYTES_LENGTH: usize;
    fn sign(&self, data: &[u8]) -> [u8; N];
}