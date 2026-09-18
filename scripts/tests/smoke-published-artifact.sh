#!/bin/sh
set -eu

target="${ZED_PKG_TEST_TARGET:?ZED_PKG_TEST_TARGET is required}"

test -f "$target/src/main.rs"
test -f "$target/src/routes/publish.rs"
test -f "$target/schema/schema.sql"
