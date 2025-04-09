use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Please provide a username");
    }

    let name: &str = &args[1];
    let transport: &str = &args[2];

    let (did_doc, private_doc, _) =
        tsp_sdk::vid::create_did_web(name, "did.teaspoon.world", transport);

    fs::write(
        format!("examples/test/{name}-did.json"),
        serde_json::to_string_pretty(&did_doc).unwrap(),
    )
    .unwrap();

    fs::write(
        format!("examples/test/{name}-piv.json"),
        serde_json::to_string_pretty(&private_doc).unwrap(),
    )
    .unwrap();
}
