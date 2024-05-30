#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match tsp::cesr::decode_payload::<&[u8]>(data) {
        Ok(decoded) => {
            let mut buf = Vec::new();
            tsp::cesr::encode_payload(&decoded, &mut buf).unwrap();

            let redecoded = tsp::cesr::decode_payload(&buf).unwrap();
            assert_eq!(decoded, redecoded)
        }
        Err(_) => {
            // ignore errors. We're really looking for panics with this fuzzer
        }
    }
});
