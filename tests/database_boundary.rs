//! Static regression checks for the API-write / web-read-only database policy.

use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    fs::read_to_string(root().join(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

#[test]
fn zed_package_declares_the_canonical_orm_core() {
    let manifest = read(".zpkg.toml");
    for contract in [
        "org = \"zed-pkg\"",
        "name = \"zed-api-server\"",
        "\"zed-pkg/zed-orm-core\" = \"^0.1.0\"",
        "dir = \".vendor/.zed\"",
    ] {
        assert!(
            manifest.contains(contract),
            "zed package contract lost {contract}"
        );
    }
    assert!(
        !manifest.contains("\"zed-pkg/zed-lib\""),
        "the general library must not become a second ORM package owner"
    );
}

#[test]
fn production_migrations_are_not_enabled_by_default_or_in_kubernetes() {
    let config = read("src/config.rs");
    assert!(config.contains("env_or(\"AUTO_MIGRATE\", \"false\")"));

    let deployment = read("k8s/base/deployment.yaml");
    assert!(deployment.contains("separate release job"));
    assert!(
        !deployment.contains("name: AUTO_MIGRATE"),
        "the request-serving Kubernetes Deployment must not run DDL"
    );

    let compose = read("docker-compose.yml");
    assert!(compose.contains("AUTO_MIGRATE: \"true\""));
    assert!(compose.contains("disposable local stack only"));
}

#[test]
fn role_and_migration_contract_stays_explicit() {
    let boundary = read("docs/database-boundary.md");
    for contract in [
        "sole request-serving writer",
        "zed_pkg__api_rw",
        "zed_pkg__web_ro",
        "zed_pkg__migrator",
        "zed-orm-core",
        "read-write",
        "opaque read/write context",
        "dpm verify",
        "expand → backfill → contract",
    ] {
        assert!(
            boundary.contains(contract),
            "database boundary lost {contract}"
        );
    }

    let cargo = read("Cargo.toml");
    assert!(cargo.contains("sea-orm ="));
    assert!(
        !cargo
            .lines()
            .any(|line| line.trim_start().starts_with("sqlx =")),
        "the API must not introduce a second direct SQL data layer"
    );
}
