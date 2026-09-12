use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(relative: &str) -> String {
    let path = repository_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn formal_workflow_uses_exact_candidate_and_pinned_fmctl_toolchain() {
    let workflow = read(".github/workflows/formal-methods.yml");

    for required in [
        "github.event.pull_request.head.sha || github.sha",
        "git rev-parse HEAD",
        "c2146ef9f054d24e1488c216547852aa148285cf",
        ".formal-tools/opto-sync-clients/tools/fmctl/rust-toolchain.toml",
        "persist-credentials: false",
        "rustup toolchain install \"$toolchain\"",
        "rustup default \"$toolchain\"",
        "rustc --version",
        "cargo build \\",
        "--locked \\",
        "\"$FMCTL\" --format json validate",
        "\"$FMCTL\" --format json doctor",
        "\"$FMCTL\" check",
        "\"$FMCTL\" simulate",
        "\"$FMCTL\" verify",
    ] {
        assert!(
            workflow.contains(required),
            "formal workflow lost required provenance/control `{required}`"
        );
    }

    for forbidden in [
        "dtolnay/rust-toolchain@",
        "toolchain: stable",
        "rustup toolchain install stable",
        "rustup default stable",
        "persist-credentials: true",
        "contents: write",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "formal workflow contains forbidden moving/mutating control `{forbidden}`"
        );
    }
}

#[test]
fn repository_product_toolchain_remains_patch_exact_and_independent() {
    let toolchain: toml::Value =
        toml::from_str(&read("rust-toolchain.toml")).expect("parse rust-toolchain.toml");
    let channel = toolchain["toolchain"]["channel"]
        .as_str()
        .expect("toolchain.channel must be a string");
    let parts = channel.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "product Rust must be x.y.z exact: {channel}");
    assert!(
        parts.iter().all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit())),
        "product Rust must be numeric x.y.z: {channel}"
    );

    let formal = read(".github/workflows/formal-methods.yml");
    assert!(
        !formal.contains(&format!("toolchain: {channel}")),
        "formal runner must use the pinned fmctl toolchain rather than silently coupling to product Rust"
    );
}
