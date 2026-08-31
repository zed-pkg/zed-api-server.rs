//! Immutable process configuration resolved through flags-2-env.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;

#[cfg(not(test))]
use std::sync::OnceLock;

use flags2env::BundledFlags2Env;
use tempfile::NamedTempFile;

const CONTRACT: &str = include_str!("../.cli-flags.toml");

#[cfg(not(test))]
static RESOLVED: OnceLock<Result<BTreeMap<String, String>, String>> = OnceLock::new();

#[cfg(not(test))]
/// Returns a resolved configuration value by environment-style name.
///
/// # Errors
///
/// Returns `VarError::NotPresent` when the audited configuration has no value
/// for `name`.
pub fn var(name: &str) -> Result<String, std::env::VarError> {
    resolved()
        .get(name)
        .cloned()
        .ok_or(std::env::VarError::NotPresent)
}

#[cfg(test)]
/// Returns a process environment value for isolated configuration tests.
///
/// # Errors
///
/// Returns the standard environment lookup error when `name` is absent or
/// contains non-Unicode data.
pub fn var(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name)
}

/// Parses argv before any server effect and returns help/version output, if requested.
///
/// # Errors
///
/// Returns a redacted error when the contract, argv, or a typed value is invalid.
#[cfg(not(test))]
pub fn process_control(known_command: Option<&str>) -> Result<Option<String>, String> {
    let values = try_resolved(known_command)?;
    if values.get("CLI_HELP_REQUESTED").map(String::as_str) == Some("true") {
        return help_table().map(Some);
    }
    if values.get("CLI_VERSION_REQUESTED").map(String::as_str) == Some("true") {
        return Ok(Some(format!(
            "{} {}\n",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )));
    }
    Ok(None)
}

#[cfg(not(test))]
/// Resolves dotenv and environment configuration without consuming delegated subcommand argv.
///
/// # Errors
///
/// Returns a redacted error when the embedded contract or an environment value is invalid.
pub fn process_environment_only() -> Result<(), String> {
    let argv = vec![env!("CARGO_PKG_NAME").to_owned()];
    RESOLVED
        .get_or_init(|| resolve_from(&argv, std::env::vars()))
        .as_ref()
        .map(|_| ())
        .map_err(Clone::clone)
}

#[cfg(test)]
/// Bypasses process-level argv handling in isolated unit tests.
///
/// # Errors
///
/// The test implementation is infallible.
pub fn process_control(_known_command: Option<&str>) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(test)]
/// Bypasses process-level environment handling in isolated unit tests.
///
/// # Errors
///
/// The test implementation is infallible.
pub fn process_environment_only() -> Result<(), String> {
    Ok(())
}

#[cfg(not(test))]
fn resolved() -> &'static BTreeMap<String, String> {
    try_resolved(None).unwrap_or_else(|error| panic!("{error}"))
}

#[cfg(not(test))]
fn try_resolved(known_command: Option<&str>) -> Result<&'static BTreeMap<String, String>, String> {
    RESOLVED
        .get_or_init(|| resolve(known_command))
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(not(test))]
fn resolve(known_command: Option<&str>) -> Result<BTreeMap<String, String>, String> {
    let argv = argv_for_contract(std::env::args().collect(), known_command);
    resolve_from(&argv, std::env::vars())
}

fn argv_for_contract(mut argv: Vec<String>, known_command: Option<&str>) -> Vec<String> {
    if argv.get(1).map(String::as_str) != known_command {
        return argv;
    }
    match known_command {
        Some("help") => argv[1] = "--help".to_owned(),
        Some("version") => argv[1] = "--version".to_owned(),
        Some(_) => {
            argv.remove(1);
        }
        None => {}
    }
    argv
}

fn resolve_from(
    argv: &[String],
    environment: impl IntoIterator<Item = (String, String)>,
) -> Result<BTreeMap<String, String>, String> {
    let environment = environment.into_iter().collect::<BTreeMap<_, _>>();
    let mut contract = NamedTempFile::new()
        .map_err(|error| format!("cannot create embedded flags-2-env contract: {error}"))?;
    contract
        .write_all(CONTRACT.as_bytes())
        .map_err(|error| format!("cannot materialize embedded flags-2-env contract: {error}"))?;
    let path = contract
        .path()
        .to_str()
        .ok_or_else(|| "flags-2-env contract path is not valid UTF-8".to_owned())?;
    let parser = BundledFlags2Env::new();
    parser
        .audit_config(Some(path))
        .map_err(|error| format!("flags-2-env contract audit failed: {error}"))?;
    let parsed = parser
        .parse_structured(argv, Some(path))
        .map_err(|error| format!("flags-2-env parsing failed: {error}"))?;

    if !parsed.unknown_options.is_empty() {
        let names = parsed
            .unknown_options
            .iter()
            .map(|option| option_name(option))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("unknown command-line option(s): {names}"));
    }
    if !parsed.errors.is_empty() {
        return Err(format!(
            "invalid command-line value(s): {} error(s)",
            parsed.errors.len()
        ));
    }
    if !parsed.extras.is_empty() {
        return Err(format!(
            "unexpected positional argument(s): {}",
            parsed.extras.len()
        ));
    }

    let mut raw = parsed.dotenv;
    raw.extend(
        environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    raw.extend(parsed.dotenv_overrides);
    raw.remove("FLAGS2ENV_COMMAND");
    raw.extend(parsed.provided_flags);
    normalize_legacy_boolean(&mut raw, "ZED_RATE_LIMIT_DISABLED");
    let typed = parser
        .coerce::<serde_json::Map<String, serde_json::Value>, _>(&raw, Some(path))
        .map_err(|error| format!("flags-2-env typed configuration failed: {error}"))?;
    let mut resolved = environment;
    for (name, value) in typed {
        if !value.is_null() {
            resolved.insert(name.clone(), scalar_string(&name, value)?);
        }
    }
    Ok(resolved)
}

fn normalize_legacy_boolean(values: &mut std::collections::HashMap<String, String>, name: &str) {
    if let Some(value) = values.get_mut(name) {
        match value.as_str() {
            "1" => *value = "true".to_owned(),
            "0" => *value = "false".to_owned(),
            _ => {}
        }
    }
}

fn scalar_string(name: &str, value: serde_json::Value) -> Result<String, String> {
    match value {
        serde_json::Value::String(value) => Ok(value),
        serde_json::Value::Bool(value) => Ok(value.to_string()),
        serde_json::Value::Number(value) => Ok(value.to_string()),
        _ => Err(format!(
            "flags-2-env returned a non-scalar value for {name}"
        )),
    }
}

fn option_name(option: &str) -> String {
    if let Some(long) = option.strip_prefix("--") {
        return format!("--{}", long.split('=').next().unwrap_or_default());
    }
    option.chars().take(2).collect()
}

fn help_table() -> Result<String, String> {
    let contract = toml::from_str::<toml::Value>(CONTRACT)
        .map_err(|error| format!("cannot read flags-2-env help metadata: {error}"))?;
    let flags = contract
        .get("flags")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "flags-2-env contract has no flags table".to_owned())?;
    let mut output = format!("Usage: {} [OPTIONS]\n\nOptions:\n", env!("CARGO_PKG_NAME"));
    for flag in flags.values() {
        let Some(flag) = flag.as_table() else {
            continue;
        };
        let long = flag.get("long").and_then(toml::Value::as_str).or_else(|| {
            flag.get("aliases")
                .and_then(toml::Value::as_array)
                .and_then(|aliases| aliases.first())
                .and_then(toml::Value::as_str)
        });
        let Some(long) = long else {
            continue;
        };
        let short = flag.get("short").and_then(toml::Value::as_str);
        let value_type = flag
            .get("type")
            .and_then(toml::Value::as_str)
            .unwrap_or("string");
        let mut option = short.map_or_else(
            || format!("--{long}"),
            |short| format!("-{short}, --{long}"),
        );
        if !matches!(value_type, "bool" | "boolean") {
            option.push_str(" <VALUE>");
        }
        let description = flag
            .get("help")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        let default = flag
            .get("default")
            .map(|value| format!(" [default: {value}]"))
            .unwrap_or_default();
        writeln!(output, "  {option:<28} {description}{default}")
            .map_err(|error| format!("cannot render flags-2-env help: {error}"))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_options_fail_closed_without_echoing_values() {
        let error = resolve_from(
            &[
                "server".to_owned(),
                "--definitely-unknown=do-not-echo".to_owned(),
            ],
            std::iter::empty(),
        )
        .expect_err("unknown option");
        assert!(error.contains("--definitely-unknown"));
        assert!(!error.contains("do-not-echo"));
    }

    #[test]
    fn command_line_overrides_environment_with_a_typed_value() {
        let contract = toml::from_str::<toml::Value>(CONTRACT).expect("contract");
        let flag = contract["flags"]
            .as_table()
            .and_then(|flags| {
                flags.values().find_map(|flag| {
                    let flag = flag.as_table()?;
                    let value_type = flag.get("type")?.as_str()?;
                    if matches!(value_type, "bool" | "boolean") {
                        return None;
                    }
                    Some((
                        flag.get("long")?.as_str()?.to_owned(),
                        flag.get("env")?.as_str()?.to_owned(),
                        value_type.to_owned(),
                    ))
                })
            })
            .expect("typed value flag");
        let command_line_value = if flag.2 == "integer" {
            "31337"
        } else {
            "from-cli"
        };
        let option = format!("--{}={command_line_value}", flag.0);
        let resolved = resolve_from(
            &["server".to_owned(), option],
            [(flag.1.clone(), "from-env".to_owned())],
        )
        .expect("valid command-line option");
        assert_eq!(
            resolved.get(&flag.1).map(String::as_str),
            Some(command_line_value)
        );
    }

    #[test]
    fn help_is_derived_from_the_audited_contract() {
        let help = help_table().expect("help");
        assert!(help.contains("--help"));
        assert!(help.contains("Options:"));
    }

    #[test]
    fn operational_subcommands_are_removed_and_control_aliases_are_normalized() {
        assert_eq!(
            argv_for_contract(
                vec![
                    "zed-api-server".to_owned(),
                    "serve".to_owned(),
                    "--bind-addr=127.0.0.1:9000".to_owned(),
                ],
                Some("serve"),
            ),
            vec!["zed-api-server", "--bind-addr=127.0.0.1:9000"]
        );
        assert_eq!(
            argv_for_contract(
                vec!["zed-api-server".to_owned(), "help".to_owned()],
                Some("help"),
            ),
            vec!["zed-api-server", "--help"]
        );
    }

    #[test]
    fn legacy_numeric_rate_limit_boolean_is_normalized_before_coercion() {
        let resolved = resolve_from(
            &["zed-api-server".to_owned()],
            [("ZED_RATE_LIMIT_DISABLED".to_owned(), "1".to_owned())],
        )
        .expect("legacy boolean");
        assert_eq!(
            resolved.get("ZED_RATE_LIMIT_DISABLED").map(String::as_str),
            Some("true")
        );
    }
}
