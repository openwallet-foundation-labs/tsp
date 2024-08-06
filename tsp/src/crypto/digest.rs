/// Calculate the SHA2-256 of a piece of arbitrary data
pub fn sha256(content: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(content).into()
}

#[cfg(feature = "nacl")]
pub fn blake2b256(content: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    type Blake2b256 = blake2::Blake2b<typenum::U32>;
    Blake2b256::digest(content).into()
}
