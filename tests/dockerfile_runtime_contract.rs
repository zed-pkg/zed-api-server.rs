use std::fs;
use std::path::PathBuf;

fn runtime_stage() -> String {
    let dockerfile = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Dockerfile");
    let text = fs::read_to_string(&dockerfile)
        .unwrap_or_else(|error| panic!("reading {}: {error}", dockerfile.display()));
    text.split_once("FROM debian:12-slim")
        .map(|(_, runtime)| runtime.to_owned())
        .expect("Dockerfile must retain the Debian 12 runtime stage")
}

#[test]
fn runtime_image_installs_a_system_tls_trust_store_before_dropping_privileges() {
    let runtime = runtime_stage();
    let install = runtime
        .find("apt-get install --no-install-recommends -y ca-certificates")
        .expect("runtime stage must install ca-certificates for HTTPS S3/R2 endpoints");
    let cleanup = runtime
        .find("rm -rf /var/lib/apt/lists/*")
        .expect("runtime package installation must remove apt index files");
    let user = runtime
        .find("USER zed")
        .expect("runtime stage must still drop to the unprivileged zed user");

    assert!(install < cleanup, "apt indexes must be removed after installation");
    assert!(cleanup < user, "the trust store must be installed before USER zed");
}
