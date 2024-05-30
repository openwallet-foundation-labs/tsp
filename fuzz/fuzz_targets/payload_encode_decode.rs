#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: tsp::cesr::fuzzing::Wrapper| {
    let mut buf = Vec::new();
    tsp::cesr::encode_payload(&data.0, &mut buf).unwrap();

    match tsp::cesr::decode_payload(&buf) {
        Ok(decoded) => assert_eq!(data, decoded),
        Err(e) => {
            // most of these errors should be unreachable if encoding succeeded
            match e {
                tsp::cesr::error::DecodeError::UnexpectedData => todo!(),
                tsp::cesr::error::DecodeError::UnexpectedMsgType => todo!(),
                tsp::cesr::error::DecodeError::TrailingGarbage => todo!(),
                tsp::cesr::error::DecodeError::SignatureError => todo!(),
                tsp::cesr::error::DecodeError::VidError => todo!(),
                tsp::cesr::error::DecodeError::VersionMismatch => todo!(),
                tsp::cesr::error::DecodeError::MissingHops => (),
            }
        }
    }
});
