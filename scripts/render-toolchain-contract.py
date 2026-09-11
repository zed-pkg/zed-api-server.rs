#!/usr/bin/env python3
"""Render the repository's actual Cargo/Zed/flags contract as TJSV instance evidence."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path

CANONICAL_FLAGS_GIT = "https://github.com/flags-2-env/flags-2-env"
REQUIRED_SECRET_ENV = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "DATABASE_URL",
    "FIDUCIA_INTERNAL_SECRET",
    "GITHUB_TOKEN",
    "SHARED_AUTH_SERVICE_CREDENTIAL",
}


def load_toml(path: Path) -> dict:
    with path.open("rb") as source:
        value = tomllib.load(source)
    if not isinstance(value, dict):
        raise SystemExit(f"expected TOML table root: {path}")
    return value


def normalized_repo(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.removesuffix(".git").rstrip("/")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    cargo = load_toml(root / "Cargo.toml")
    lock = load_toml(root / "Cargo.lock")
    zpkg = load_toml(root / ".zpkg.toml")
    cli = load_toml(root / ".cli-flags.toml")

    cargo_package = cargo.get("package", {})
    zed_package = zpkg.get("package", {})
    flags2env = cargo.get("dependencies", {}).get("flags2env", {})
    flags_git = normalized_repo(flags2env.get("git") if isinstance(flags2env, dict) else None)
    flags_revision = flags2env.get("rev") if isinstance(flags2env, dict) else None
    if not isinstance(flags_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", flags_revision):
        raise SystemExit(f"flags2env dependency revision is not immutable: {flags_revision!r}")

    root_lock_packages = [
        package
        for package in lock.get("package", [])
        if isinstance(package, dict)
        and package.get("name") == cargo_package.get("name")
        and "source" not in package
    ]
    root_lock_matches = (
        len(root_lock_packages) == 1
        and root_lock_packages[0].get("version") == cargo_package.get("version")
    )

    env_policy = cli.get("env", {})
    ignored = set(env_policy.get("ignore", [])) if isinstance(env_policy, dict) else set()
    flags = cli.get("flags", {})
    flag_count = len(flags) if isinstance(flags, dict) else 0

    source_text = "\n".join(
        (root / name).read_text(encoding="utf-8").lower()
        for name in ("Cargo.toml", ".zpkg.toml", ".cli-flags.toml")
    )

    evidence = {
        "schema": "zed.api/toolchain-contract/v1",
        "flags2envRevision": flags_revision,
        "cargoPackageName": cargo_package.get("name"),
        "cargoPackageVersion": cargo_package.get("version"),
        "zedPackageName": zed_package.get("name"),
        "zedPackageVersion": zed_package.get("version"),
        "packageRepositoryMatch": normalized_repo(cargo_package.get("repository"))
        == normalized_repo(zed_package.get("repository", {}).get("url") if isinstance(zed_package.get("repository"), dict) else None),
        "cargoLockMatchesPackage": root_lock_matches,
        "canonicalFlagsAuthority": flags_git == CANONICAL_FLAGS_GIT,
        "strictUnknownOptions": cli.get("parse", {}).get("allow_unknown") is False,
        "dotenvDisabled": env_policy.get("dotenv") is False and env_policy.get("files") == [],
        "flagCount": flag_count,
        "requiredSecretEnvIgnored": REQUIRED_SECRET_ENV.issubset(ignored),
        "legacyFlagsAuthorityPresent": "github.com/oresoftware/flags-2-env" in source_text,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()
