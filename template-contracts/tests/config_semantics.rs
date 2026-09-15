use std::path::Path;

use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

const AUTHORITIES: &str = include_str!("../../.ores-config-authorities.json");
const MIDDLEWARE: &str = include_str!("../../.ores-mw.toml");
const RATE_LIMIT: &str = include_str!("../../.ores-rl.toml");
const LRU: &str = include_str!("../../.ores-lru.toml");
const SHARED_AUTH: &str = include_str!("../../.shared-auth.toml");
const STACK: &str = include_str!("../../config/ores-middleware-stack.json");

fn json(input: &str) -> JsonValue {
    serde_json::from_str(input).expect("checked-in JSON must parse")
}

fn toml(input: &str) -> TomlValue {
    input.parse::<TomlValue>().expect("checked-in TOML must parse")
}

fn no_nulls(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => false,
        JsonValue::Array(values) => values.iter().all(no_nulls),
        JsonValue::Object(values) => values.values().all(no_nulls),
        _ => true,
    }
}

#[test]
fn authority_lock_is_canonical_and_reviewed() {
    let value = json(AUTHORITIES);
    assert_eq!(value["schemaVersion"], 1);
    let middleware = &value["authorities"]["middleware"];
    assert_eq!(
        middleware["revision"],
        "a99b7609200c076bedab58d14581d64b57c04387"
    );
    assert_eq!(middleware["stackTypespec"], "contracts/typespec/main.tsp");
    assert_eq!(
        middleware["stackJsonSchema"],
        "contracts/json-schema/middleware-stack.schema.json"
    );
    let shared_auth = &value["authorities"]["sharedAuth"];
    assert_eq!(shared_auth["canonicalConfig"], ".shared-auth.toml");
    assert_eq!(shared_auth["compatibilityAliases"][0], ".auth-shared.toml");

    let auth = toml(SHARED_AUTH);
    assert_eq!(
        auth["compatibility"]["commit"].as_str(),
        shared_auth["revision"].as_str()
    );
}

#[test]
fn api_role_and_shared_policies_are_structurally_fail_closed() {
    let middleware = toml(MIDDLEWARE);
    let rate_limit = toml(RATE_LIMIT);
    let lru = toml(LRU);
    let stack = json(STACK);

    assert_eq!(middleware["repository_mode"].as_str(), Some("server-only"));
    assert_eq!(middleware["default_target"].as_str(), Some("api"));
    assert_eq!(rate_limit["server"]["keyHmacEnv"].as_str(), Some("ORES_RL_HMAC_KEY"));
    assert_eq!(lru["redis"]["urlEnv"].as_str(), Some("REDIS_URL"));
    assert_eq!(lru["defaults"]["failOpenOnStartup"].as_bool(), Some(false));

    let settings = &stack["settings"];
    let capabilities = stack["requiredCapabilities"].as_array().expect("capabilities array");
    let reps = settings["contentRepresentations"].as_array().expect("representations array");
    assert!(capabilities.iter().any(|v| v.as_str() == Some("idempotency")));
    assert!(!reps.iter().any(|v| v.as_str() == Some("text/html")));
    assert_eq!(settings["idempotency"]["enabled"].as_bool(), Some(true));
    let methods = settings["idempotency"]["requiredMethods"]
        .as_array()
        .expect("idempotency methods");
    let methods = methods
        .iter()
        .map(|v| v.as_str().expect("method string"))
        .collect::<Vec<_>>();
    assert_eq!(methods, vec!["POST", "PUT", "PATCH"]);
    assert_eq!(settings["faultInjection"]["enabled"].as_bool(), Some(false));
    assert_eq!(settings["testAuthBypass"]["enabled"].as_bool(), Some(false));
    let bypass = settings["testAuthBypass"]["headerName"].as_str().expect("bypass header");
    assert!(bypass.starts_with("x-ores-"));
    assert_eq!(bypass, bypass.to_ascii_lowercase());
    assert_eq!(stack["integrations"]["sharedAuth"]["mode"].as_str(), Some("disabled"));
    assert_eq!(stack["integrations"]["sharedAuth"]["failOpen"].as_bool(), Some(false));
    assert_eq!(stack["integrations"]["oresOtel"]["enabled"].as_bool(), Some(true));
    assert!(
        stack["integrations"]["oresOtel"]["serviceName"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(no_nulls(&stack));
}

#[test]
fn rate_limit_manifest_matches_middleware_stack() {
    let rate_limit = toml(RATE_LIMIT);
    let stack = json(STACK);
    let policy_id = rate_limit["defaultPolicyId"].as_str().expect("default policy id");
    let policies = rate_limit["policies"].as_array().expect("policies array");
    let policy = policies
        .iter()
        .find(|p| p["policyId"].as_str() == Some(policy_id))
        .expect("default policy exists");
    let stack_policy = &stack["settings"]["rateLimit"];

    assert_eq!(policy["backendFailureMode"].as_str(), Some("fail-closed"));
    assert_eq!(stack_policy["policyId"].as_str(), Some(policy_id));
    assert_eq!(
        stack_policy["capacity"].as_i64(),
        policy["capacity"].as_integer()
    );
    let refill_tokens = policy["refillTokens"].as_integer().expect("refill tokens") as f64;
    let refill_interval_ms = policy["refillIntervalMs"].as_integer().expect("refill interval") as f64;
    let expected_per_second = refill_tokens * 1000.0 / refill_interval_ms;
    let actual_per_second = stack_policy["refillPerSecond"].as_f64().expect("refill per second");
    assert!((actual_per_second - expected_per_second).abs() < f64::EPSILON);
}

#[test]
fn canonical_shared_auth_config_has_no_authored_alias() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("template-contracts must have a repository parent");
    assert!(root.join(".shared-auth.toml").is_file());
    assert!(!root.join(".auth-shared.toml").exists());
}
