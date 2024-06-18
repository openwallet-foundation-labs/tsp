#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match tsp::cesr::decode_payload(data) {
        Ok(decoded) => {
            let mut buf = Vec::new();
            tsp::cesr::encode_payload(&decoded.payload, None, &mut buf).unwrap();

            let redecoded = tsp::cesr::decode_payload(&buf).unwrap().payload;
            assert_eq!(decoded.payload, redecoded)
        }
        Err(_) => {
            // ignore errors. We're really looking for panics with this fuzzer
        }
    }
});
