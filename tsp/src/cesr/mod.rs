mod decode;
#[cfg(feature = "cesr-t")]
mod detect;
mod encode;
pub mod error;
mod packet;
pub use packet::*;

#[cfg(feature = "cesr-t")]
pub use detect::to_binary;

/// Safely restrict value to a certain number of bits
fn bits(value: impl Into<u32>, bits: u8) -> u32 {
    let value = value.into();
    let mask = (1 << bits as u32) - 1;
    assert!(value <= mask, "{value} <= {mask}");

    value & mask
}

/// Produce a bitmask of n bits
const fn mask(n: u8) -> u32 {
    (1 << n) - 1
}

/// Converts a "quadlet" into a u32 (big-endian)
const fn extract_triplet(quadlet: &[u8; 3]) -> u32 {
    u32::from_be_bytes([0, quadlet[0], quadlet[1], quadlet[2]])
}

/// Checks if the header bytes in a CESR encoding line up;
/// In strict mode, this has to be an exact match, i.e. padding bits have to be 0
fn header_match(input: &[u8], target: &[u8]) -> bool {
    if cfg!(feature = "strict") {
        input == target
    } else {
        let mask = !mask(2 * (input.len() as u8 % 3)) as u8;

        input[..input.len() - 1] == target[..target.len() - 1]
            && input[input.len() - 1] & mask == target[target.len() - 1]
    }
}

/// Constants for CESR selectors
mod selector {
    pub const D0: u32 = 52;
    pub const D1: u32 = D0 + 1;
    pub const D4: u32 = D0 + 4;
    pub const D5: u32 = D0 + 5;
    pub const D6: u32 = D0 + 6;
    pub const D7: u32 = D0 + 7;
    pub const D8: u32 = D0 + 8;
    pub const D9: u32 = D0 + 9;
    pub const DASH: u32 = 62;
}

/// (Temporary) interface to get Sender/Receiver VIDs information from a CESR-encoded message
pub fn get_sender_receiver(message: &[u8]) -> Result<(&[u8], Option<&[u8]>), error::DecodeError> {
    let mut stream = message;
    let (sender, receiver, _) = decode_sender_receiver(&mut stream)?;

    Ok((sender, receiver))
}

#[derive(Debug)]
pub enum EnvelopeType<'a> {
    EncryptedMessage {
        sender: &'a [u8],
        receiver: &'a [u8],
    },
    SignedMessage {
        sender: &'a [u8],
        receiver: Option<&'a [u8]>,
    },
}

pub fn probe(stream: &mut [u8]) -> Result<EnvelopeType, error::DecodeError> {
    let (_, has_confidential_part) =
        detected_tsp_header_size_and_confidentiality(&mut (stream as &[u8]))?;

    let envelope = decode_envelope_mut(stream)?
        .into_opened()
        .expect("Infallible")
        .envelope;

    Ok(if has_confidential_part {
        EnvelopeType::EncryptedMessage {
            sender: envelope.sender,
            receiver: envelope.receiver.expect("Infallible"),
        }
    } else {
        EnvelopeType::SignedMessage {
            sender: envelope.sender,
            receiver: envelope.receiver,
        }
    })
}

#[cfg(test)]
mod test {
    use super::{decode::*, encode::*, *};

    #[test]
    fn test_primitives() {
        assert_eq!(mask(0), 0x0);
        assert_eq!(mask(1), 0x1);
        assert_eq!(mask(3), 0x7);
        assert_eq!(mask(5), 0x1F);
        assert_eq!(bits(15u8, 6), 15);
        assert_eq!(extract_triplet(&[1, 2, 3]), 0x00010203);
        assert!(header_match(&[1, 2, 3], &[1, 2, 3]));
        assert!(header_match(&[0xFF, 0xF0], &[0xFF, 0xF0]));
        assert!(header_match(&[0xFC], &[0xFC]));
        #[cfg(not(feature = "strict"))]
        assert!(header_match(&[0xFF, 0xF3], &[0xFF, 0xF0]));
        #[cfg(not(feature = "strict"))]
        assert!(header_match(&[0xFF], &[0xFC]));
    }

    #[test]
    fn encode_and_decode() {
        let mut data = vec![];
        encode_genus([1, 2, 3], (4, 5, 6), &mut data);
        encode_fixed_data(2323, b"Hello world!", &mut data); // 0 lead bytes
        encode_fixed_data(42, b"TrustSpanP!", &mut data); // 1 lead byte
        encode_fixed_data(57, b"TrustSpanP", &mut data); // 2 lead byte
        encode_variable_data(3, b"Where there is power, there is resistance.", &mut data); // 0 lead bytes
        encode_variable_data(
            122,
            b"To pretend, I actually do the thing: I have therefore only pretended to pretend.",
            &mut data,
        ); // 1 lead byte
        encode_variable_data(42,  b"I always speak the truth. Not the whole truth, because there's no way, to say it all.", &mut data); // 2 lead bytes
        encode_count(7, 2, &mut data);
        encode_indexed_data(5, 57, b"DON'T PANIC!", &mut data); // 0 lead bytes
        encode_indexed_data(5, 0, b"SECRET KEY", &mut data); // 2 lead bytes

        let mut input = &data[..];
        decode_genus([1, 2, 3], (4, 5, 6), &mut input).unwrap();
        assert_eq!(
            decode_fixed_data(2323, &mut input).unwrap(),
            b"Hello world!"
        );
        assert_eq!(decode_fixed_data(42, &mut input).unwrap(), b"TrustSpanP!");
        assert_eq!(decode_fixed_data(57, &mut input).unwrap(), b"TrustSpanP");
        assert_eq!(
            decode_variable_data(3, &mut input).unwrap(),
            b"Where there is power, there is resistance."
        );
        assert_eq!(
            decode_variable_data(122, &mut input).unwrap(),
            b"To pretend, I actually do the thing: I have therefore only pretended to pretend."
        );
        assert_eq!(decode_variable_data(42, &mut input).unwrap(), b"I always speak the truth. Not the whole truth, because there's no way, to say it all.");
        assert_eq!(decode_count(7, &mut input).unwrap(), 2);
        assert_eq!(
            decode_indexed_data(5, &mut input).unwrap(),
            (57, b"DON'T PANIC!")
        );
        assert_eq!(
            decode_indexed_data(5, &mut input).unwrap(),
            (0, b"SECRET KEY")
        );
    }

    #[test]
    fn long_variable_data() {
        let mut data1 = vec![];
        let mut data2 = vec![];
        let mut data3 = vec![];
        encode_variable_data(0, &[0u8; 4095], &mut data1);
        encode_variable_data(0, &[0u8; 4096], &mut data2);
        encode_variable_data(0, &[0u8; 4097], &mut data3);
        assert!(data1[0] != data2[0]);
        assert!(data2[0] == data2[0]);
    }

    #[should_panic]
    #[test]
    fn identifier_failure_1() {
        encode_fixed_data(64, b"TrustSpanP!", &mut vec![]); // 1 lead byte
    }

    #[should_panic]
    #[test]
    fn identifier_failure_2() {
        encode_fixed_data(64, b"TrustSpanP", &mut vec![]); // 2 lead bytes
    }

    #[should_panic]
    #[test]
    fn identifier_failure_3() {
        encode_fixed_data(4096, b"TrustSpanP", &mut vec![]); // 0 lead bytes
    }

    #[should_panic]
    #[test]
    fn identifier_failure_variable() {
        encode_variable_data(262144, b"", &mut vec![]);
    }

    #[should_panic]
    #[test]
    fn index_failure() {
        encode_indexed_data(5, 57, b"hello", &mut vec![]); // 1 lead byte
    }

    #[should_panic]
    #[test]
    fn too_long_data_failure() {
        encode_variable_data(
            0,
            &(0..50331646).map(|_| 0).collect::<Vec<u8>>(),
            &mut vec![],
        ); // 1 lead byte
    }

    use base64ct::{Base64UrlUnpadded, Encoding};

    #[test]
    fn decode_and_encode() {
        fn fixed_roundtrip<const N: usize>(ident: u32, content: [u8; N], input: &[u8]) {
            // test that decoding the given output results in the same content
            let payload = decode_fixed_data(ident, &mut &input[..]).unwrap();
            assert_eq!(payload, &content);

            // test that encoding the given input leads to the given output
            let mut output = vec![];
            encode_fixed_data(ident, &content, &mut output);
            assert_eq!(input, output);
        }

        fixed_roundtrip(12, [1, 2], &Base64UrlUnpadded::decode_vec("MAEC").unwrap());
        fixed_roundtrip(
            5,
            [1, 2, 3],
            &Base64UrlUnpadded::decode_vec("1AAFAQID").unwrap(),
        );
        fixed_roundtrip(
            7,
            [1, 2, 3, 4],
            &Base64UrlUnpadded::decode_vec("0HABAgME").unwrap(),
        );
        fixed_roundtrip(
            13,
            [1, 2, 3, 4, 5, 6, 7, 8],
            &Base64UrlUnpadded::decode_vec("NAECAwQFBgcI").unwrap(),
        );
        let mut funky_data = <[u8; 24]>::default();
        Base64UrlUnpadded::decode("2022-10-25T12c04c30d175309p00c00", &mut funky_data).unwrap();
        fixed_roundtrip(
            6,
            funky_data,
            &Base64UrlUnpadded::decode_vec("1AAG2022-10-25T12c04c30d175309p00c00").unwrap(),
        );

        fn variable_roundtrip(ident: u32, content: &[u8], input: &[u8]) {
            // test that decoding the given output results in the same content
            let payload = decode_variable_data(ident, &mut &input[..]).unwrap();
            assert_eq!(payload, content);

            // test that encoding the given input leads to the given output
            let mut output = vec![];
            encode_variable_data(ident, content, &mut output);
            assert_eq!(input, output);
        }

        variable_roundtrip(
            0,
            &Base64UrlUnpadded::decode_vec("barf").unwrap(),
            &Base64UrlUnpadded::decode_vec("4AABbarf").unwrap(),
        );

        variable_roundtrip(
            0,
            &Base64UrlUnpadded::decode_vec("AFoo").unwrap()[1..],
            &Base64UrlUnpadded::decode_vec("5AABAFoo").unwrap(),
        );

        variable_roundtrip(
            0,
            &Base64UrlUnpadded::decode_vec("AAA-field0-field1-field3").unwrap()[2..],
            &Base64UrlUnpadded::decode_vec("6AAGAAA-field0-field1-field3").unwrap(),
        );

        variable_roundtrip(
            1,
            b"1337",
            &Base64UrlUnpadded::decode_vec("6BACAAAxMzM3").unwrap(),
        );

        variable_roundtrip(
            1,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &Base64UrlUnpadded::decode_vec("5BADAAECAwQFBgcI").unwrap(),
        );
    }

    #[test]
    fn dont_gen_overlong_encoding() {
        fn roundtrip(ident: u32, input: &[u8], output: &[u8]) {
            let payload = decode_variable_data(ident, &mut &input[..]).unwrap();
            let mut generated = vec![];
            encode_variable_data(ident, payload, &mut generated);
            assert_eq!(generated, output);
        }

        roundtrip(
            0,
            &Base64UrlUnpadded::decode_vec("9AAAAAABAAA-").unwrap(),
            &Base64UrlUnpadded::decode_vec("6AABAAA-").unwrap(),
        );
        roundtrip(
            1,
            &Base64UrlUnpadded::decode_vec("8AABAAADAAECAwQFBgcI").unwrap(),
            &Base64UrlUnpadded::decode_vec("5BADAAECAwQFBgcI").unwrap(),
        );
    }

    //NOTE: the official CESR example as several places where padding bits have random values; we have changed:
    // 1) E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y =>
    //    EPT2_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y    (padding bits should have a canonical value)
    // 2) EwmQtlcszNoEIDfqD-Zih3N6o5B3humRKvBBln2juTEM =>
    //    EAmQtlcszNoEIDfqD-Zih3N6o5B3humRKvBBln2juTEM    (same reason)
    // 3) AA5267UlFg1jHee4Dauht77SzGl8WUC_0oimYG5If3SdIOSzWM8Qs9SFajAilQcozXJVnbkY5stG_K4NbKdNB4AQ => (1st indexed signature)
    //    AAB267UlFg1jHee4Dauht77SzGl8WUC_0oimYG5If3SdIOSzWM8Qs9SFajAilQcozXJVnbkY5stG_K4NbKdNB4AQ
    // 4) ACTD7NDX93ZGTkZBBuSeSGsAQ7u0hngpNTZTK_Um7rUZGnLRNJvo5oOnnC1J2iBQHuxoq8PyjdT3BHS2LiPrs2Cg => (3rd indexed signature)
    //    ACDD7NDX93ZGTkZBBuSeSGsAQ7u0hngpNTZTK_Um7rUZGnLRNJvo5oOnnC1J2iBQHuxoq8PyjdT3BHS2LiPrs2Cg
    #[test]
    fn demo_example() {
        #[cfg(feature = "strict")]
        let base64_data = "\
-FAB\
EPT2_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y\
-EAB\
0AAAAAAAAAAAAAAAAAAAAAAB\
EAmQtlcszNoEIDfqD-Zih3N6o5B3humRKvBBln2juTEM\
-AAD\
AAB267UlFg1jHee4Dauht77SzGl8WUC_0oimYG5If3SdIOSzWM8Qs9SFajAilQcozXJVnbkY5stG_K4NbKdNB4AQ\
ABBgeqntZW3Gu4HL0h3odYz6LaZ_SMfmITL-Btoq_7OZFe3L16jmOe49Ur108wH7mnBaq2E_0U0N0c5vgrJtDpAQ\
ACDD7NDX93ZGTkZBBuSeSGsAQ7u0hngpNTZTK_Um7rUZGnLRNJvo5oOnnC1J2iBQHuxoq8PyjdT3BHS2LiPrs2Cg\
";
        #[cfg(not(feature = "strict"))]
        let base64_data = "\
-FAB\
E_T2_p83_gRSuAYvGhqV3S0JzYEF2dIa-OCPLbIhBO7Y\
-EAB\
0AAAAAAAAAAAAAAAAAAAAAAB\
EwmQtlcszNoEIDfqD-Zih3N6o5B3humRKvBBln2juTEM\
-AAD\
AA5267UlFg1jHee4Dauht77SzGl8WUC_0oimYG5If3SdIOSzWM8Qs9SFajAilQcozXJVnbkY5stG_K4NbKdNB4AQ\
ABBgeqntZW3Gu4HL0h3odYz6LaZ_SMfmITL-Btoq_7OZFe3L16jmOe49Ur108wH7mnBaq2E_0U0N0c5vgrJtDpAQ\
ACTD7NDX93ZGTkZBBuSeSGsAQ7u0hngpNTZTK_Um7rUZGnLRNJvo5oOnnC1J2iBQHuxoq8PyjdT3BHS2LiPrs2Cg\
";

        let data = Base64UrlUnpadded::decode_vec(base64_data).unwrap();

        let slice = &mut &data[..];

        assert_eq!(decode_count(5, slice).unwrap(), 1);
        decode_fixed_data::<32>(4, slice).unwrap();
        assert_eq!(decode_count(4, slice).unwrap(), 1);
        decode_fixed_data::<16>(0, slice).unwrap();
        decode_fixed_data::<32>(4, slice).unwrap();
        assert_eq!(decode_count(0, slice).unwrap(), 3);
        assert_eq!(decode_indexed_data::<64>(0, slice).unwrap().0, 0);
        assert_eq!(decode_indexed_data::<64>(0, slice).unwrap().0, 1);
        assert_eq!(decode_indexed_data::<64>(0, slice).unwrap().0, 2);
    }
}
