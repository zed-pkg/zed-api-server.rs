#!/usr/bin/env python3
"""Build the final signed public-intake API from current main."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTERFACES_REV = "ed9b3b67fe24741dd96db0490e80d95cf37d1a4f"
CORE_REV = os.environ["ZED_LIB_CORE_REV"]
BASELINE_FILES = [
    "Cargo.lock",
    "Cargo.toml",
    "src/routes/mod.rs",
    "src/state.rs",
    "src/server.rs",
]


def baseline(path: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(
        subprocess.check_output(["git", "show", f"origin/main:{path}"], cwd=ROOT)
    )


def insert_dependency(text: str, key: str, value: str) -> str:
    heading = re.search(r"(?m)^\[dependencies\]\s*$", text)
    if heading is None:
        return text.rstrip() + f"\n\n[dependencies]\n{key} = {value}\n"
    next_heading = re.search(r"(?m)^\[[^\n]+\]\s*$", text[heading.end() :])
    end = heading.end() + (next_heading.start() if next_heading else len(text) - heading.end())
    body = text[heading.end() : end]
    line = f"{key} = {value}"
    pattern = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
    if pattern.search(body):
        body = pattern.sub(line, body, count=1)
    else:
        body = body.rstrip() + "\n" + line + "\n"
    return text[: heading.end()] + body + text[end:]


def add_state_accessor() -> None:
    path = ROOT / "src/state.rs"
    text = path.read_text()
    structure = re.search(r"pub struct AppState\s*\{(?P<body>[\s\S]*?)\n\}", text)
    if structure is None:
        raise RuntimeError("cannot locate AppState")
    field = re.search(
        r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:std::sync::Arc<|Arc<)?(?:zed_orm_core::)?WriteContext>?\s*,?\s*$",
        structure.group("body"),
    )
    if field is None:
        raise RuntimeError("cannot locate AppState WriteContext field")
    name = field.group(1)
    text += f'''\nimpl AppState {{
    /// Opaque public-intake persistence authority. Routes never receive the
    /// underlying database connection or generated ORM entities.
    pub fn public_intake_write_context(&self) -> &zed_orm_core::WriteContext {{
        &self.{name}
    }}
}}
'''
    path.write_text(text)


def add_routes() -> None:
    module = ROOT / "src/routes/mod.rs"
    text = module.read_text().rstrip() + "\n\npub mod public_intake;\n"
    module.write_text(text)

    server = ROOT / "src/server.rs"
    text = server.read_text()
    marker = "Router::new()"
    index = text.find(marker)
    if index < 0:
        raise RuntimeError("cannot locate root Router::new()")
    replacement = '''Router::new()
        .route(
            crate::routes::public_intake::PRE_INTEREST_PATH,
            axum::routing::post(crate::routes::public_intake::submit_pre_interest),
        )
        .route(
            crate::routes::public_intake::QUOTE_REQUEST_PATH,
            axum::routing::post(crate::routes::public_intake::submit_quote_request),
        )'''
    server.write_text(text[:index] + replacement + text[index + len(marker) :])


def patch_staged_route() -> None:
    staged = ROOT / ".github/materialize/public_intake.rs"
    if not staged.is_file():
        raise RuntimeError("staged public-intake route is missing")
    text = staged.read_text()
    text = text.replace(
        "const COMMON_FIELDS: &[&str] = &[",
        "#[cfg(test)]\nconst COMMON_FIELDS: &[&str] = &[",
        1,
    )
    text = text.replace(
        "serde_json::from_value(value)\n",
        "serde_json::from_value(value.clone())\n",
    )
    text = text.replace(
        "fn common_field_inventory_is a subset of every request shape()",
        "fn common_field_inventory_is_a_subset_of_every_request_shape()",
        1,
    )
    old = '''fn contains_secret_shape(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.contains("-----begin private key-----")
        || lowercase.contains("password=")
        || lowercase.contains("github_pat_")
        || lowercase.contains("ghp_")
        || lowercase.contains("sk-")
        || lowercase.contains("akia")
}
'''
    new = '''fn contains_secret_shape(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.contains("-----begin private key-----")
        || lowercase.contains("password=")
        || contains_token(&lowercase, "github_pat_", 20)
        || contains_token(&lowercase, "ghp_", 20)
        || contains_token(&lowercase, "sk-", 20)
        || value.as_bytes().windows(20).any(|window| {
            window.starts_with(b"AKIA")
                && window[4..].iter().all(u8::is_ascii_uppercase)
        })
}

fn contains_token(value: &str, prefix: &str, minimum_suffix: usize) -> bool {
    value.match_indices(prefix).any(|(index, _)| {
        let suffix = &value[index + prefix.len()..];
        suffix
            .bytes()
            .take_while(u8::is_ascii_alphanumeric)
            .count()
            >= minimum_suffix
    })
}
'''
    if old not in text:
        raise RuntimeError("secret-shape helper anchor not found")
    text = text.replace(old, new, 1)
    (ROOT / "src/routes/public_intake.rs").write_text(text)


def write_permanent_ci() -> None:
    path = ROOT / ".github/workflows/public-intake-api-contract.yml"
    path.write_text(
        f'''name: public intake API contract

on:
  pull_request:
    paths:
      - "src/routes/public_intake.rs"
      - "src/routes/mod.rs"
      - "src/state.rs"
      - "src/server.rs"
      - "Cargo.toml"
      - "Cargo.lock"
      - ".github/workflows/public-intake-api-contract.yml"
  push:
    branches: [main]
    paths:
      - "src/routes/public_intake.rs"
      - "src/routes/mod.rs"
      - "src/state.rs"
      - "src/server.rs"
      - "Cargo.toml"
      - "Cargo.lock"
      - ".github/workflows/public-intake-api-contract.yml"

permissions:
  contents: read

concurrency:
  group: public-intake-api-contract-${{{{ github.workflow }}}}-${{{{ github.ref }}}}
  cancel-in-progress: true

jobs:
  public-intake-api:
    runs-on: ubuntu-24.04
    timeout-minutes: 40
    steps:
      - name: Check out API
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          path: zed-api-server
          persist-credentials: false
          show-progress: false

      - name: Check out immutable interface contract
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          repository: zed-pkg/zed-interfaces
          ref: {INTERFACES_REV}
          path: zed-interfaces
          persist-credentials: false
          show-progress: false

      - name: Check out immutable persistence contract
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with:
          repository: zed-pkg/zed-lib-core
          ref: {CORE_REV}
          path: zed-lib-core
          persist-credentials: false
          show-progress: false

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@6d653acedea9b9aaf8b1d10a8d8b03ee8a4a20b1
        with:
          toolchain: stable
          components: rustfmt, clippy

      - name: Verify signed ingress and API boundaries
        working-directory: zed-api-server
        run: |
          set -euo pipefail
          cargo fmt --all -- --check
          cargo test --all-targets --all-features --locked
          cargo clippy --all-targets --all-features --locked -- -D warnings
          git diff --check
          if git grep -nE '(ghp_|github_pat_|lin_api_)[A-Za-z0-9_]+' -- .; then
            echo "credential-shaped material found" >&2
            exit 1
          fi
'''
    )


def main() -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", CORE_REV):
        raise RuntimeError("ZED_LIB_CORE_REV must be an immutable commit SHA")
    for path in BASELINE_FILES:
        baseline(path)
    patch_staged_route()

    cargo_path = ROOT / "Cargo.toml"
    cargo = cargo_path.read_text()
    for key, value in [
        ("base64", '"0.22"'),
        ("hex", '"0.4"'),
        ("hmac", '"0.12"'),
        ("sha2", '"0.10"'),
        ("zeroize", '"1"'),
        ("zed-interfaces", '{ path = "../zed-interfaces/src/rust" }'),
        ("zed-lib-core", '{ path = "../zed-lib-core/src/rust" }'),
        ("zed-orm-core", '{ path = "../zed-lib-core/src/rust-orm" }'),
    ]:
        cargo = insert_dependency(cargo, key, value)
    cargo_path.write_text(cargo)

    add_routes()
    add_state_accessor()
    write_permanent_ci()


if __name__ == "__main__":
    main()
