use std::{fs, process::Command};

use flags2env::BundledFlags2Env;

const CHILD_PROBE: &str = "ZED_API_TEST_DOTENV_CHILD_PROBE";
const SENTINEL_BIND_ADDR: &str = "127.0.0.1:6553";

#[test]
fn working_directory_dotenv_is_ignored_by_api_flags_contract() {
    if std::env::var_os(CHILD_PROBE).is_some() {
        let contract = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cli-flags.toml");
        let contract = contract
            .to_str()
            .expect("repository path must be valid UTF-8 for flags2env");
        let argv = vec!["zed-api-server".to_owned()];
        let parsed = BundledFlags2Env::new()
            .parse_structured(&argv, Some(contract))
            .expect("isolated API flags contract must parse");

        assert_eq!(
            parsed.flags.get("BIND_ADDR").map(String::as_str),
            Some("0.0.0.0:8080"),
            "working-directory .env must not override the declared bind default"
        );
        assert!(
            parsed.dotenv.get("BIND_ADDR").is_none(),
            "working-directory .env must not enter the parser dotenv layer"
        );
        return;
    }

    let workdir = tempfile::tempdir().expect("create isolated dotenv probe directory");
    fs::write(
        workdir.path().join(".env"),
        format!("BIND_ADDR={SENTINEL_BIND_ADDR}\nDATABASE_URL=postgres://dotenv-must-not-load.invalid/db\n"),
    )
    .expect("write hostile working-directory .env fixture");

    let output = Command::new(std::env::current_exe().expect("locate integration-test executable"))
        .arg("--exact")
        .arg("working_directory_dotenv_is_ignored_by_api_flags_contract")
        .arg("--nocapture")
        .env(CHILD_PROBE, "1")
        .current_dir(workdir.path())
        .output()
        .expect("run isolated API dotenv child probe");

    assert!(
        output.status.success(),
        "isolated API dotenv child probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
