pub fn temp_url(name: &str) -> String {
    let suffix = format!("{}.{}.sqlite", name, std::process::id());
    let path = std::env::temp_dir().join(suffix);
    format!("sqlite://{}", path.display())
}
