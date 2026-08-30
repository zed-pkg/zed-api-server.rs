# Agent instructions

## Parent / root agent contract

The fleet-wide parent lives at:

- GitHub: https://github.com/oresoftware/my-ai/AGENTS.md
- Canonical disk path: `~/codes/oresoftware/my-ai/AGENTS.md`
- `~/codes/AGENTS.md` is a symlink to `~/codes/oresoftware/my-ai/AGENTS.md` (installed by `~/codes/oresoftware/my-ai/setup-final.sh`)

When this file and the parent disagree: follow this file for this repository's local layout and tools; follow the parent for org-wide conventions and the functional programming rules.

## Scope and hierarchy

- These instructions apply to the whole `zed-pkg/zed-api-server.rs` repository unless a deeper lowercase `agents.md` adds narrower rules.
- Before editing, resolve the current working directory and load every readable ancestor `agents.md` from the filesystem root to the working directory. Do not search siblings. Resolve symlinks, deduplicate resolved files, and report unreadable or cyclic instruction files.
- `.claude/CLAUDE.md`, `.gemini/GEMINI.md`, and `.openai/AGENTS.md` are pointers only. Never duplicate instructions in tool-specific files.

## Repository role

This Rust service is the Zed registry API boundary. It owns authenticated package metadata and artifact operations, registry compatibility, persistence behavior, service health, and code-first API contracts consumed by the CLI and generated clients.

## Working rules

- Treat routes, status codes, error bodies, OpenAPI schemas, authentication requirements, and pagination as public APIs.
- Reuse `zed-interfaces` models; update the contract repository before consumers when a change spans repositories.
- Keep database migrations forward-safe, explicit, and tested against realistic upgrade paths. Do not hide schema changes in startup code.
- Fail closed for publish, yank, token, organization, and administrative operations; read-only diagnostics must not expose credentials or package secrets.
- Preserve checksum, size, content-type, and immutable artifact guarantees across upload and download paths.
- Keep health/readiness and metrics endpoints bounded and free of sensitive data.
- Never commit tokens, database URLs, cloud credentials, kubeconfigs, or production environment files.
- Exercise focused unit/integration tests, OpenAPI drift checks, formatting, compilation, Clippy, and container/runtime checks relevant to the change.

## Validation

The pinned `agents policy` workflow validates this hierarchy and the three tool pointers. Follow `README.md` and existing CI for service-specific validation before requesting review.

## Code style and coding patterns

remember to modularize the rust, typescript and dart - not everything belongs in main.rs, main.ts and main.dart; also follow functional coding principles - fewer side-effects (use pure functions more), more immutability (immutable variables); but for stateful apps like the client or stateful servers like websockets or tcp connections, sometimes classes and oop make more sense than functional programming perse, but we can still adhere to functional programming more than usual. Favor exhaustive pattern matching and use formal methods checking too. Favor composability and re-use , so basically create more utility functions and routines for shared use. You can follow a medium level of D.R.Y. (don't repeat yourself) - in other words you can repeat yourself at medium amount (not too much not too little). Some chaining is totally fine, so either method-chaining (immutable sometimes although with classes can be mutable too for performance), and chaining via the pipe operator is ok in languages like gleamlang.

Functional programming is mostly the following:

+ explicit inputs
+ explicit outputs
+ immutable values
+ pure transformations
+ typed errors
+ explicit state transitions
+ composition
+ effects pushed outward
+ illegal states excluded by types

## Functional programming conformance

This repository carries an FP conformance ratchet. Before you land a change:

```sh
python3 tools/fp-conformance/fp_conformance.py .
```

CI compares your findings against `tools/fp-conformance/budget.json` and fails
only when a rule's count *increases*. Do not raise the budget to get green — fix
the new violations. When you clear a class of violation, lower the budget in the
same commit with `--write-budget`.

The principles, the rule codes and the remedy for each are in `FP-GUIDELINES.md`.
