#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: tsp::cesr::fuzzing::Wrapper| {
    let mut buf = Vec::new();
    match tsp::cesr::encode_payload(&data.0, None, &mut buf) {
        Ok(()) => {
            let result: tsp::cesr::DecodedPayload = tsp::cesr::decode_payload(&mut buf).unwrap();

            assert_eq!(data, result.payload);
        }
        Err(tsp::cesr::error::EncodeError::MissingHops) => match &data.0 {
            tsp::cesr::Payload::RoutedMessage(route, _) => assert!(route.is_empty()),
            _ => todo!(),
        },
        _ => todo!(),
    }
});
