#![no_main]

use libfuzzer_sys::fuzz_target;
use tsp_sdk::cesr;

fuzz_target!(|data: cesr::fuzzing::Wrapper| {
    let mut buf = Vec::new();
    match cesr::encode_payload(&data.0, None, None, &mut buf) {
        Ok(()) => {
            let result: cesr::DecodedPayload = cesr::decode_payload(&mut buf).unwrap();

            assert_eq!(data, result.payload);
        }
        // MissingHops is only raised for RoutedMessage with an empty hop list
        Err(cesr::error::EncodeError::MissingHops) => {
            assert!(matches!(
                &data.0,
                cesr::Payload::RoutedMessage(route, _) if route.is_empty()
            ));
        }
        // Fields that exceed the CESR variable-data size limit are legitimately rejected
        Err(cesr::error::EncodeError::ExcessiveFieldSize) => {}
        // Parallel-relation payloads with an empty new_vid are legitimately rejected
        Err(cesr::error::EncodeError::InvalidVid) => {}
        // Nested/routed inner messages must be CESR data (a multiple of 3 bytes)
        Err(cesr::error::EncodeError::MisalignedNestedMessage) => {
            assert!(
                matches!(
                    &data.0,
                    cesr::Payload::NestedMessage(inner) if inner.len() % 3 != 0
                ) || matches!(
                    &data.0,
                    cesr::Payload::RoutedMessage(_, inner) if inner.len() % 3 != 0
                )
            );
        }
        // Any other error is not expected from encode_payload — surface it as a finding
        Err(e) => panic!("unexpected encode error: {e:?}"),
    }
});
