# zed-api-server.rs — environment secret management.
#
#   just                 # list recipes
#   just use dev         # decrypt env/enc/dev.env.enc and link it to ./.env
#   just edit prod       # edit secrets in place, never touching plaintext on disk
#   just audit           # fail if plaintext could reach a commit
#
# The server itself is flags-2-env style: all configuration is environment
# variables (see README "Configuration (env)" and env/template.env.example).
# These recipes only manage the encrypted per-environment stores; run the
# server with e.g. `sops exec-env env/enc/dev.env.enc 'cargo run'`.
#
# Invariant: plaintext secrets exist only in env/dec/ and the ./.env symlink,
# both gitignored. Only env/enc/*.env.enc is ever committed.

set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := false

enc_dir := justfile_directory() / "env/enc"
dec_dir := justfile_directory() / "env/dec"
age_key := env_var_or_default("SOPS_AGE_KEY_FILE", env_var("HOME") / ".config/sops/age/keys.txt")

_default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# Environment secrets — delegated to `ores-sops`
#
# ores-sops (github.com/ORESoftware/ores-sops) is the single implementation,
# shared across orgs and supplied by this flake's devShell. These recipes hold
# no logic of their own so there is nothing here to drift.
#
# Anything not listed is plain sops:
#   sops edit env/enc/prod.env.enc          change a secret, no plaintext on disk
#   sops updatekeys env/enc/prod.env.enc    after editing .sops.yaml recipients
#   sops exec-env env/enc/prod.env.enc CMD  run CMD with secrets, no file at all
# ---------------------------------------------------------------------------

# Decrypt <name> and point ./.env at it. The normal daily command.
use name:
    @ores-sops use {{ name }}

# Per-environment state; * marks the active one.
status:
    @ores-sops status

# Edit a secret in place; plaintext never touches disk.
edit name:
    @ores-sops edit {{ name }}

# Fold env/dec/<name>.env edits back into the ciphertext.
encrypt name:
    @ores-sops encrypt {{ name }}

# What local plaintext edits would change.
diff name:
    @ores-sops diff {{ name }}

# Re-decrypt the active env if its ciphertext changed (git hooks call this).
refresh:
    @ores-sops refresh

# Remove decrypted plaintext and the .env symlink.
lock:
    @ores-sops lock

# Print this host's age public key (for onboarding into .sops.yaml).
age-key:
    @age-keygen -y "{{ age_key }}"

# Fail if plaintext secrets could reach a commit. Wire into pre-commit / CI.
audit:
    #!/usr/bin/env bash
    set -euo pipefail
    tracked="$(git ls-files -- '*.env' 'env/dec/*' '.env' 2>/dev/null || true)"
    if [ -n "$tracked" ]; then
        echo "FAIL: plaintext env files are tracked by git:" >&2
        printf '  %s\n' "$tracked" >&2
        exit 1
    fi
    shopt -s nullglob
    for f in env/enc/*.env.enc; do
        grep -q 'ENC\[AES256_GCM' "$f" || { echo "FAIL: $f is not sops-encrypted" >&2; exit 1; }
    done
    echo "audit ok: no plaintext env tracked, all env/enc files encrypted"
