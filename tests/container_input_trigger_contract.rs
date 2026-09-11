use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn assert_trigger(workflow: &str, input: &str) {
    let single_quoted = format!("'{input}'");
    let double_quoted = format!("\"{input}\"");
    assert!(
        workflow.contains(&single_quoted) || workflow.contains(&double_quoted),
        "container workflow is missing trigger coverage for {input}"
    );
}

#[test]
fn deployable_image_workflows_cover_non_rust_runtime_inputs() {
    let flags = read("src/flags.rs");
    assert!(
        flags.contains("include_str!(\"../.cli-flags.toml\")"),
        "this test must track the embedded flags2env contract"
    );

    let dockerfile = read("Dockerfile");
    assert!(dockerfile.contains("env/enc/${SOPS_ENV}.env.enc"));
    assert!(dockerfile.contains("scripts/sops-entrypoint.sh"));

    let publish = read(".github/workflows/publish-container.yml");
    for input in [
        ".cli-flags.toml",
        ".ores-rl.toml",
        ".zpkg.toml",
        ".zpkg.lock",
        "env/**",
        "scripts/sops-entrypoint.sh",
        "Dockerfile",
    ] {
        assert_trigger(&publish, input);
    }

    let images = read(".github/workflows/images.yml");
    for input in [
        ".cli-flags.toml",
        ".ores-rl.toml",
        ".zpkg.toml",
        ".zpkg.lock",
        "env/**",
        "scripts/sops-entrypoint.sh",
        "Dockerfile",
        "Dockerfile.*.dkf",
        ".github/workflows/images.yml",
    ] {
        assert_trigger(&images, input);
    }
}
