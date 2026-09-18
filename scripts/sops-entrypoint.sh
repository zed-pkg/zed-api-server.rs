#!/bin/sh
# Runtime-only SOPS loading for a shell-bearing image, then direct exec.
# Keep the fixed service in ENTRYPOINT after this wrapper; CMD holds defaults.
# Values remain literal. Never source/eval dotenv or print decryption output.
set -eu

# Clear inherited export attributes before creating private loader variables.
unset _ORES_SOPS_PRINTENV _ORES_SOPS_PLAINTEXT _ORES_SOPS_NL _ORES_SOPS_LINE \
  _ORES_SOPS_REST _ORES_SOPS_KEY _ORES_SOPS_VALUE _ORES_SOPS_SEEN _ORES_SOPS_IMPORT

if [ "$#" -eq 0 ] || [ -z "$1" ]; then
  printf '%s\n' 'sops-entrypoint: no command configured' >&2
  exit 64
fi
case "${SOPS_REQUIRE_KEY:-0}" in
  0|1) ;;
  *) printf '%s\n' 'sops-entrypoint: invalid required-key setting' >&2; exit 64 ;;
esac
: "${SOPS_SECRETS_FILE:=/app/secrets/app.env}"
if [ ! -f "$SOPS_SECRETS_FILE" ]; then
  if [ "${SOPS_REQUIRE_KEY:-0}" = 1 ] || [ -e "$SOPS_SECRETS_FILE" ]; then
    printf '%s\n' 'sops-entrypoint: required ciphertext is unavailable or not a regular file' >&2
    exit 1
  fi
  exec "$@"
fi
if [ -z "${SOPS_AGE_KEY:-}" ] && [ -z "${SOPS_AGE_KEY_FILE:-}" ]; then
  if [ "${SOPS_REQUIRE_KEY:-0}" = 1 ]; then
    printf '%s\n' 'sops-entrypoint: required age identity is unavailable' >&2
    exit 1
  fi
  printf '%s\n' 'sops-entrypoint: optional decryption skipped; no age identity supplied' >&2
  exec "$@"
fi
command -v sops >/dev/null 2>&1 || {
  printf '%s\n' 'sops-entrypoint: sops binary not in image' >&2; exit 1;
}
_ORES_SOPS_PRINTENV=$(command -v printenv) || {
  printf '%s\n' 'sops-entrypoint: printenv binary not in image' >&2; exit 1;
}
case "$_ORES_SOPS_PRINTENV" in
  /*) ;;
  *) printf '%s\n' 'sops-entrypoint: printenv must resolve to an absolute path' >&2; exit 1 ;;
esac
_ORES_SOPS_PLAINTEXT=$(sops --decrypt --input-type dotenv --output-type dotenv "$SOPS_SECRETS_FILE" 2>/dev/null) || {
  printf '%s\n' 'sops-entrypoint: decryption failed' >&2; exit 1;
}

# Iterate in this shell with parameter expansion, not a pipeline/subshell or a
# plaintext here-document. Split only the first '='; do not reinterpret values.
_ORES_SOPS_NL='
'
_ores_sops_record() {
  case "$_ORES_SOPS_REST" in
    *"$_ORES_SOPS_NL"*)
      _ORES_SOPS_LINE=${_ORES_SOPS_REST%%"$_ORES_SOPS_NL"*}
      _ORES_SOPS_REST=${_ORES_SOPS_REST#*"$_ORES_SOPS_NL"} ;;
    *) _ORES_SOPS_LINE=$_ORES_SOPS_REST; _ORES_SOPS_REST= ;;
  esac
  case "$_ORES_SOPS_LINE" in
    ''|'#'*|sops_*=*) return 1 ;;
    *=*) _ORES_SOPS_KEY=${_ORES_SOPS_LINE%%=*}; _ORES_SOPS_VALUE=${_ORES_SOPS_LINE#*=} ;;
    *) printf '%s\n' 'sops-entrypoint: invalid dotenv record' >&2; exit 1 ;;
  esac
  case "$_ORES_SOPS_KEY" in
    ''|*[!A-Za-z0-9_]*|[0-9]*|_ORES_SOPS_*)
      printf '%s\n' 'sops-entrypoint: invalid or reserved variable name' >&2; exit 1 ;;
  esac
}

# First validate every record and snapshot presence, including empty values.
# No exports occur yet, so imported PATH/LD_PRELOAD cannot affect printenv.
_ORES_SOPS_SEEN='|'
_ORES_SOPS_IMPORT='|'
_ORES_SOPS_REST=$_ORES_SOPS_PLAINTEXT
while [ -n "$_ORES_SOPS_REST" ]; do
  if ! _ores_sops_record; then continue; fi
  case "$_ORES_SOPS_SEEN" in
    *"|$_ORES_SOPS_KEY|"*) printf '%s\n' 'sops-entrypoint: duplicate variable name' >&2; exit 1 ;;
  esac
  _ORES_SOPS_SEEN="$_ORES_SOPS_SEEN$_ORES_SOPS_KEY|"
  if "$_ORES_SOPS_PRINTENV" "$_ORES_SOPS_KEY" >/dev/null 2>&1; then
    :
  else
    case "$?" in
      1) _ORES_SOPS_IMPORT="$_ORES_SOPS_IMPORT$_ORES_SOPS_KEY|" ;;
      *) printf '%s\n' 'sops-entrypoint: environment presence check failed' >&2; exit 1 ;;
    esac
  fi
done

# Apply only unset variables after successful validation. No external helper is
# executed after the first export; the private loader namespace is reserved.
_ORES_SOPS_REST=$_ORES_SOPS_PLAINTEXT
while [ -n "$_ORES_SOPS_REST" ]; do
  if ! _ores_sops_record; then continue; fi
  case "$_ORES_SOPS_IMPORT" in
    *"|$_ORES_SOPS_KEY|"*) export "$_ORES_SOPS_KEY=$_ORES_SOPS_VALUE" ;;
  esac
done
unset _ORES_SOPS_PRINTENV _ORES_SOPS_PLAINTEXT _ORES_SOPS_NL _ORES_SOPS_LINE \
  _ORES_SOPS_REST _ORES_SOPS_KEY _ORES_SOPS_VALUE _ORES_SOPS_SEEN _ORES_SOPS_IMPORT
exec "$@"
