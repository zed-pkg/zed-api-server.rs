use std::fs;
use std::path::PathBuf;

#[test]
fn cargo_and_zpkg_release_identity_match() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(root.join(".zpkg.toml"))
        .expect("read repository-owned .zpkg.toml");
    let manifest: toml::Value = toml::from_str(&source).expect("parse .zpkg.toml");

    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .expect(".zpkg.toml must contain [package]");
    assert_eq!(
        package.get("name").and_then(toml::Value::as_str),
        Some(env!("CARGO_PKG_NAME")),
        "Cargo.toml and .zpkg.toml must identify the same package",
    );
    assert_eq!(
        package.get("version").and_then(toml::Value::as_str),
        Some(env!("CARGO_PKG_VERSION")),
        "Cargo.toml and .zpkg.toml must identify the same release version",
    );
    assert_eq!(
        package
            .get("repository")
            .and_then(toml::Value::as_table)
            .and_then(|repository| repository.get("url"))
            .and_then(toml::Value::as_str),
        Some(env!("CARGO_PKG_REPOSITORY")),
        "Cargo.toml and .zpkg.toml must identify the same source repository",
    );
}
