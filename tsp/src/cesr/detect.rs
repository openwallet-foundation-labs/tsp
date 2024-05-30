use base64ct::{Base64UrlUnpadded, Encoding};

pub fn to_binary(data: &mut [u8]) -> Option<&[u8]> {
    let first_byte = data.first()?;

    match first_byte >> 5 {
        0b001 => Base64UrlUnpadded::decode_in_place(data).ok(), // CESR in the T domain
        0b111 => Some(data),                                    // CESR in the B domain
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::to_binary;
    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn test_binary() {
        let base64 = *b"-FAB";
        let binary = Base64UrlUnpadded::decode_vec(std::str::from_utf8(&base64).unwrap()).unwrap();
        assert_eq!(to_binary(&mut binary.clone()).unwrap(), binary);
        assert_eq!(to_binary(&mut base64.clone()).unwrap(), binary);

        assert!(to_binary(b"AAAA").is_none());
        assert!(to_binary([0, 0, 0]).is_none());
    }
}
