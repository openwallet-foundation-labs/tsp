#![no_main]

use libfuzzer_sys::fuzz_target;
use tsp_sdk::cesr;

fuzz_target!(|data: &[u8]| {
    match cesr::decode_payload(&mut data.to_owned()) {
        Ok(decoded) => {
            let mut buf = Vec::new();
            cesr::encode_payload(&decoded.payload, None, &mut buf).unwrap();

            let redecoded = cesr::decode_payload(&mut buf).unwrap().payload;
            assert_eq!(decoded.payload, redecoded)
        }
        Err(_) => {
            // ignore errors. We're really looking for panics with this fuzzer
        }
    }
});
