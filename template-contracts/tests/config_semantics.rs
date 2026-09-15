use std::path::Path;

const AUTHORITIES: &str = include_str!("../../.ores-config-authorities.json");
const MIDDLEWARE: &str = include_str!("../../.ores-mw.toml");
const RATE_LIMIT: &str = include_str!("../../.ores-rl.toml");
const STACK: &str = include_str!("../../config/ores-middleware-stack.json");

#[test]
fn pins_reviewed_middleware_authority() {
    assert!(AUTHORITIES.contains("a99b7609200c076bedab58d14581d64b57c04387"));
    assert!(AUTHORITIES.contains("\"stackTypespec\":\"contracts/typespec/main.tsp\""));
    assert!(AUTHORITIES.contains("\"stackJsonSchema\":\"contracts/json-schema/middleware-stack.schema.json\""));
}

#[test]
fn api_role_invariants_are_fail_closed() {
    assert!(MIDDLEWARE.contains("default_target = \"api\""));
    assert!(RATE_LIMIT.contains("keyHmacEnv = \"ORES_RL_HMAC_KEY\""));
    assert!(RATE_LIMIT.contains("backendFailureMode = \"fail-closed\""));
    assert!(STACK.contains("\"idempotency\": {\"enabled\": true"));
    assert!(STACK.contains("\"requiredMethods\": [\"POST\", \"PUT\", \"PATCH\"]"));
    assert!(STACK.contains("\"testAuthBypass\": {\"enabled\": false, \"headerName\": \"x-ores-"));
    assert!(!STACK.contains("X-ORES-"));
    assert!(!STACK.contains(": null"));
}

#[test]
fn canonical_shared_auth_config_has_no_authored_alias() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("template-contracts must have a repository parent");
    assert!(root.join(".shared-auth.toml").is_file());
    assert!(!root.join(".auth-shared.toml").exists());
}
