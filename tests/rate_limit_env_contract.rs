use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use toml::Value;

const RATE_LIMIT_CONFIG: &str = ".ores-rl.toml";
const FLAG_CONFIG: &str = ".cli-flags.toml";

#[derive(Debug)]
struct EnvDeclaration {
    kind: String,
    required: bool,
    secret: bool,
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn parse_root_toml(name: &str) -> (String, Value) {
    let path = repository_root().join(name);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display())
    });
    let document = toml::from_str(&source).unwrap_or_else(|error| {
        panic!("failed to parse {}: {error}", path.display())
    });
    (source, document)
}

fn env_declarations(config: &Value) -> BTreeMap<String, EnvDeclaration> {
    let values = config
        .get("env")
        .and_then(Value::as_array)
        .expect(".ores-rl.toml must declare [[env]] metadata");
    let mut declarations = BTreeMap::new();
    for value in values {
        let table = value.as_table().expect("[[env]] entries must be tables");
        let key = table
            .get("key")
            .and_then(Value::as_str)
            .expect("env.key must be a string")
            .to_owned();
        let kind = table
            .get("kind")
            .and_then(Value::as_str)
            .expect("env.kind must be a string")
            .to_owned();
        let required = table
            .get("required")
            .and_then(Value::as_bool)
            .expect("env.required must be a boolean");
        let secret = table
            .get("secret")
            .and_then(Value::as_bool)
            .expect("env.secret must be a boolean");
        assert!(
            !table.contains_key("value"),
            "rate-limit env declarations must contain names/metadata only, never values"
        );
        assert!(
            declarations
                .insert(
                    key.clone(),
                    EnvDeclaration {
                        kind,
                        required,
                        secret,
                    },
                )
                .is_none(),
            "duplicate rate-limit environment declaration for {key}"
        );
    }
    declarations
}

fn public_flag_env_owners(value: &Value, path: &str, owners: &mut BTreeMap<String, Vec<String>>) {
    let Some(table) = value.as_table() else {
        return;
    };
    if let Some(flags) = table.get("flags").and_then(Value::as_table) {
        for (name, value) in flags {
            let Some(flag) = value.as_table() else {
                continue;
            };
            if let Some(key) = flag.get("env").and_then(Value::as_str) {
                owners
                    .entry(key.to_owned())
                    .or_default()
                    .push(format!("{path}.flags.{name}"));
            }
        }
    }
    for (name, child) in table {
        if name != "flags" {
            public_flag_env_owners(child, &format!("{path}.{name}"), owners);
        }
    }
}

#[test]
fn rate_limit_server_env_references_are_declared_required_secrets() {
    let (source, config) = parse_root_toml(RATE_LIMIT_CONFIG);
    let server = config
        .get("server")
        .and_then(Value::as_table)
        .expect(".ores-rl.toml must contain [server]");
    assert_eq!(server.get("backend").and_then(Value::as_str), Some("redis"));

    let declarations = env_declarations(&config);
    let expected = [
        ("REDIS_URL", "url"),
        ("ORES_RL_HMAC_KEY", "string"),
    ];
    assert_eq!(declarations.len(), expected.len());

    for (key, kind) in expected {
        let declaration = declarations
            .get(key)
            .unwrap_or_else(|| panic!("missing [[env]] declaration for {key}"));
        assert_eq!(declaration.kind, kind, "wrong environment kind for {key}");
        assert!(declaration.required, "{key} must remain required");
        assert!(declaration.secret, "{key} must remain confidential");
    }

    for (field, expected_key) in [
        ("redisUrlEnv", "REDIS_URL"),
        ("keyHmacEnv", "ORES_RL_HMAC_KEY"),
    ] {
        let referenced = server
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("server.{field} must name an environment variable"));
        assert_eq!(referenced, expected_key);
        assert!(
            declarations.contains_key(referenced),
            "server.{field} references undeclared environment key {referenced}"
        );
    }

    assert!(
        !source.contains("redis://"),
        ".ores-rl.toml must never contain a Redis credential/value"
    );
}

#[test]
fn rate_limit_secret_keys_are_env_only_in_flags2env_contract() {
    let (_, flags) = parse_root_toml(FLAG_CONFIG);
    let ignored = flags
        .get("env")
        .and_then(Value::as_table)
        .and_then(|env| env.get("ignore"))
        .and_then(Value::as_array)
        .expect(".cli-flags.toml [env].ignore must be an array")
        .iter()
        .map(|value| value.as_str().expect("[env].ignore entries must be strings"))
        .collect::<Vec<_>>();
    let ignored_set = ignored.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        ignored_set.len(),
        ignored.len(),
        ".cli-flags.toml [env].ignore must not contain duplicates"
    );

    let secret_keys = ["REDIS_URL", "ORES_RL_HMAC_KEY"];
    let mut public_owners = BTreeMap::<String, Vec<String>>::new();
    public_flag_env_owners(&flags, "root", &mut public_owners);

    for key in secret_keys {
        assert!(
            ignored_set.contains(key),
            "{key} must stay in flags2env [env].ignore as an env-only secret"
        );
        assert!(
            !public_owners.contains_key(key),
            "{key} must never be exposed through a public CLI flag: {:?}",
            public_owners.get(key)
        );
    }
}
