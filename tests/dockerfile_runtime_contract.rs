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

    assert!(
        install < cleanup,
        "apt indexes must be removed after installation"
    );
    assert!(
        cleanup < user,
        "the trust store must be installed before USER zed"
    );
}

#[test]
fn healthcheck_is_complete_before_the_runtime_secret_instructions() {
    let runtime = runtime_stage();
    let healthcheck = runtime
        .find("HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3")
        .expect("runtime must retain its bounded HEALTHCHECK");
    let health_command = runtime
        .find("CMD [\"/usr/local/bin/zed-api-server\", \"healthcheck\"]")
        .expect("HEALTHCHECK must invoke the process healthcheck command");
    let secret_arg = runtime
        .find("ARG SOPS_ENV=prod")
        .expect("runtime secret profile argument must remain explicit");
    assert!(
        healthcheck < health_command && health_command < secret_arg,
        "runtime instructions must not be parsed as part of HEALTHCHECK"
    );
    assert!(
        !runtime[healthcheck..health_command].contains("\n\n"),
        "HEALTHCHECK continuation must not contain a blank line"
    );
}

#[test]
fn runtime_secret_files_are_copied_from_the_documented_parent_build_context() {
    let runtime = runtime_stage();
    assert!(
        runtime.contains(
            "COPY --chmod=0755 zed-api-server.rs/scripts/sops-entrypoint.sh /usr/local/bin/sops-entrypoint.sh"
        ),
        "the release workflow builds from the parent source-graph directory"
    );
    assert!(
        runtime.contains(
            "COPY --chmod=0644 zed-api-server.rs/env/enc/${SOPS_ENV}.env.enc /app/secrets/app.env"
        ),
        "the encrypted environment must resolve inside the checked-out API directory"
    );
}
