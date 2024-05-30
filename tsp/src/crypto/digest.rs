/// Calculate the SHA2-256 of a piece of arbitrary data
pub fn sha256(content: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(content).into()
}
