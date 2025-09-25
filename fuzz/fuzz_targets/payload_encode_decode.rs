#![no_main]

use libfuzzer_sys::fuzz_target;
use tsp_sdk::cesr;

fuzz_target!(|data: cesr::fuzzing::Wrapper| {
    let mut buf = Vec::new();
    match cesr::encode_payload(&data.0, None, &mut buf) {
        Ok(()) => {
            let result: cesr::DecodedPayload = cesr::decode_payload(&mut buf).unwrap();

            assert_eq!(data, result.payload);
        }
        Err(cesr::error::EncodeError::MissingHops) => match &data.0 {
            cesr::Payload::RoutedMessage(route, _) => assert!(route.is_empty()),
            _ => todo!(),
        },
        Err(cesr::error::EncodeError::InvalidVid) => {}
        _ => todo!(),
    }
});
