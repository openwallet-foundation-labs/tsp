#![no_main]
use libfuzzer_sys::fuzz_target;
use tsp_sdk::cesr;
use tsp_sdk::vid::OwnedVid;
use tsp_sdk::{crypto, definitions::Payload};
use url::Url;

fuzz_target!(|data: cesr::fuzzing::FuzzInput| {
    let sender = OwnedVid::from_bytes(
        "did:test:sender",
        Url::parse("tcp://127.0.0.1:0").unwrap(),
        data.sender_sign_key,
        data.sender_enc_key,
    );
    let receiver = OwnedVid::from_bytes(
        "did:test:receiver",
        Url::parse("tcp://127.0.0.1:0").unwrap(),
        data.receiver_sign_key,
        data.receiver_enc_key,
    );
    let result = crypto::seal(
        &sender,
        &receiver,
        data.nonconfidential_data.as_deref(),
        Payload::Content(&data.payload),
    );

    if let Ok(mut message) = result {
        let (_, opened_payload, _, _) = crypto::open(&receiver, &sender, &mut message)
            .expect("open failed after seal succeeded");

        assert_eq!(opened_payload, Payload::Content(data.payload.as_slice()));
    }
});
