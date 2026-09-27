#![allow(clippy::needless_return)]

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::Value;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Fingerprint {
    code: String,
    file: String,
    message: String,
}

#[derive(Debug)]
enum ComparatorError {
    Usage(String),
    Io(io::Error),
    Json(serde_json::Error),
    InvalidEvent(String),
}

impl fmt::Display for ComparatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => {
                return write!(formatter, "{message}");
            }
            Self::Io(error) => {
                return write!(formatter, "I/O error: {error}");
            }
            Self::Json(error) => {
                return write!(formatter, "invalid Cargo JSON: {error}");
            }
            Self::InvalidEvent(message) => {
                return write!(formatter, "invalid compiler event: {message}");
            }
        }
    }
}

impl std::error::Error for ComparatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => {
                return Some(error);
            }
            Self::Json(error) => {
                return Some(error);
            }
            Self::Usage(_) | Self::InvalidEvent(_) => {
                return None;
            }
        }
    }
}

impl From<io::Error> for ComparatorError {
    fn from(error: io::Error) -> Self {
        return Self::Io(error);
    }
}

impl From<serde_json::Error> for ComparatorError {
    fn from(error: serde_json::Error) -> Self {
        return Self::Json(error);
    }
}

#[derive(Debug)]
struct Cli {
    base: PathBuf,
    head: PathBuf,
}

fn parse_args(args: Vec<OsString>) -> Result<Cli, ComparatorError> {
    if let [base_flag, base, head_flag, head] = args.as_slice()
        && base_flag == "--base"
        && head_flag == "--head"
    {
        return Ok(Cli {
            base: PathBuf::from(base),
            head: PathBuf::from(head),
        });
    }

    return Err(ComparatorError::Usage(
        "usage: ci-differential-clippy --base <cargo-json> --head <cargo-json>".to_owned(),
    ));
}

fn primary_file(diagnostic: &Value) -> String {
    let spans = diagnostic.get("spans").and_then(Value::as_array);
    let primary = spans.and_then(|values| {
        values.iter().find(|span| {
            return span
                .get("is_primary")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && span.get("file_name").and_then(Value::as_str).is_some();
        })
    });
    let fallback = spans.and_then(|values| {
        return values
            .iter()
            .find(|span| span.get("file_name").and_then(Value::as_str).is_some());
    });
    let file = primary
        .or(fallback)
        .and_then(|span| span.get("file_name"))
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    return file.to_owned();
}

fn warning_fingerprint(event: &Value) -> Result<Option<(Fingerprint, String)>, ComparatorError> {
    if event.get("reason").and_then(Value::as_str) != Some("compiler-message") {
        return Ok(None);
    }

    let diagnostic = event
        .get("message")
        .ok_or_else(|| ComparatorError::InvalidEvent("missing message object".to_owned()))?;
    if diagnostic.get("level").and_then(Value::as_str) != Some("warning") {
        return Ok(None);
    }

    let code = diagnostic
        .get("code")
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("<no-code>")
        .to_owned();
    let message = diagnostic
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("<missing-message>")
        .to_owned();
    let rendered = diagnostic
        .get("rendered")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim_end()
        .to_owned();

    return Ok(Some((
        Fingerprint {
            code,
            file: primary_file(diagnostic),
            message,
        },
        rendered,
    )));
}

type WarningCounts = BTreeMap<Fingerprint, u64>;
type WarningExamples = BTreeMap<Fingerprint, String>;

fn read_warnings(
    path: &Path,
) -> Result<(WarningCounts, WarningExamples), ComparatorError> {
    let reader = BufReader::new(File::open(path)?);
    let result = reader.lines().enumerate().try_fold(
        (
            BTreeMap::<Fingerprint, u64>::new(),
            BTreeMap::<Fingerprint, String>::new(),
        ),
        |(mut counts, mut examples), (offset, line)| -> Result<_, ComparatorError> {
            let line = line?;
            if line.trim().is_empty() {
                return Ok((counts, examples));
            }
            let event: Value = serde_json::from_str(&line).map_err(|error| {
                return ComparatorError::InvalidEvent(format!(
                    "{}:{}: {error}",
                    path.display(),
                    offset + 1
                ));
            })?;
            if let Some((fingerprint, rendered)) = warning_fingerprint(&event)? {
                let count = counts.entry(fingerprint.clone()).or_insert(0_u64);
                *count = count.saturating_add(1);
                if !rendered.is_empty() {
                    examples.entry(fingerprint).or_insert(rendered);
                }
            }
            return Ok((counts, examples));
        },
    )?;
    return Ok(result);
}

fn compare(base_path: &Path, head_path: &Path) -> Result<bool, ComparatorError> {
    let (base, _) = read_warnings(base_path)?;
    let (head, examples) = read_warnings(head_path)?;
    let regressions = head
        .iter()
        .filter_map(|(fingerprint, head_count)| {
            let base_count = base.get(fingerprint).copied().unwrap_or(0);
            let delta = head_count.saturating_sub(base_count);
            if delta == 0 {
                return None;
            }
            return Some((fingerprint, delta));
        })
        .collect::<Vec<_>>();

    if regressions.is_empty() {
        let removed = base
            .iter()
            .map(|(fingerprint, base_count)| {
                let head_count = head.get(fingerprint).copied().unwrap_or(0);
                return base_count.saturating_sub(head_count);
            })
            .sum::<u64>();
        println!(
            "differential-clippy: pass; base={} head={} removed={removed} new=0",
            base.values().sum::<u64>(),
            head.values().sum::<u64>()
        );
        return Ok(true);
    }

    eprintln!(
        "differential-clippy: FAIL; base={} head={} new={}",
        base.values().sum::<u64>(),
        head.values().sum::<u64>(),
        regressions.iter().map(|(_, delta)| *delta).sum::<u64>()
    );
    for (fingerprint, delta) in regressions {
        eprintln!(
            "\n+{delta} [{}] {}: {}",
            fingerprint.code, fingerprint.file, fingerprint.message
        );
        if let Some(example) = examples.get(fingerprint) {
            eprintln!("{example}");
        }
    }
    return Ok(false);
}

fn run() -> Result<bool, ComparatorError> {
    let cli = parse_args(env::args_os().skip(1).collect::<Vec<_>>())?;
    return compare(&cli.base, &cli.head);
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => {
            return ExitCode::SUCCESS;
        }
        Ok(false) => {
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("ci-differential-clippy: {error}");
            return ExitCode::from(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiler_warning(code: &str, file: &str, message: &str, line: u64) -> Value {
        return serde_json::json!({
            "reason": "compiler-message",
            "message": {
                "level": "warning",
                "code": {"code": code},
                "message": message,
                "spans": [{
                    "file_name": file,
                    "line_start": line,
                    "line_end": line,
                    "column_start": 1,
                    "column_end": 2,
                    "is_primary": true
                }],
                "rendered": format!("warning: {message}\n --> {file}:{line}:1\n")
            }
        });
    }

    fn fingerprint(event: &Value) -> Result<Fingerprint, ComparatorError> {
        let parsed = warning_fingerprint(event)?;
        return parsed
            .map(|(fingerprint, _)| fingerprint)
            .ok_or_else(|| ComparatorError::InvalidEvent("expected warning".to_owned()));
    }

    #[test]
    fn line_moves_do_not_change_fingerprint() -> Result<(), ComparatorError> {
        let first = fingerprint(&compiler_warning(
            "unreachable_pub",
            "src/lib.rs",
            "unreachable pub item",
            10,
        ))?;
        let moved = fingerprint(&compiler_warning(
            "unreachable_pub",
            "src/lib.rs",
            "unreachable pub item",
            99,
        ))?;
        assert_eq!(first, moved);
        return Ok(());
    }

    #[test]
    fn file_and_message_are_part_of_identity() -> Result<(), ComparatorError> {
        let first = fingerprint(&compiler_warning(
            "unwrap_used",
            "src/a.rs",
            "used unwrap",
            10,
        ))?;
        let moved = fingerprint(&compiler_warning(
            "unwrap_used",
            "src/b.rs",
            "used unwrap",
            10,
        ))?;
        assert_ne!(first, moved);
        return Ok(());
    }

    #[test]
    fn non_warning_events_are_ignored() -> Result<(), ComparatorError> {
        let event = serde_json::json!({
            "reason": "build-finished",
            "success": true
        });
        assert!(warning_fingerprint(&event)?.is_none());
        return Ok(());
    }
}
