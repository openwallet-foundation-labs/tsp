use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Please provide a username");
    }

    let name: &str = &args[1];
    let (did_doc, private_doc, _) =
        tsp::vid::create_did_web(name, "did.tsp-test.org", "tcp://127.0.0.1:1337");

    fs::write(
        format!("examples/test/{name}-did.json"),
        serde_json::to_string_pretty(&did_doc).unwrap(),
    )
    .unwrap();

    fs::write(
        format!("examples/test/{name}.json"),
        serde_json::to_string_pretty(&private_doc).unwrap(),
    )
    .unwrap();
}
