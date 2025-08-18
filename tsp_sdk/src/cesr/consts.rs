/// A function for more easy encoding of CESR constants
pub const fn cesr(x: &str) -> u64 {
    let x = x.as_bytes();
    let mut acc = 0;
    let mut i = 0;
    while i < x.len() {
        let ch = x[i];
        acc = acc << 6
            | match ch {
                ch if ch.is_ascii_uppercase() => ch - b'A',
                ch if ch.is_ascii_lowercase() => ch - b'a' + 26,
                ch if ch.is_ascii_digit() => ch - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => panic!("not a base64url character"),
            } as u64;
        i += 1;
    }

    acc
}

/// A function for giving the contents of "TSP_TYPECODE" fields
pub const fn cesr_data<const N: usize>(x: &str) -> [u8; N] {
    let val = cesr(x);
    assert!(val < (1u64 << (8 * N)));
    // we canot use 'try_into().unwrap()' here
    let src = u64::to_be_bytes(val);
    let start = src.len() - N;
    let mut result = [0; N];
    let mut i = start;
    while i < src.len() {
        result[i - start] = src[i];
        i += 1
    }

    result
}
