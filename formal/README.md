# Formal verification

This directory defines the first executable formal-methods boundary for the
Zed registry. The repository owns the behavioral model and its assumptions;
the shared `fmctl` runner owns manifest discovery, bounded execution, tool
pinning, normalized artifacts, and CI exit behavior.

## Tooling lineage

There are two existing ORESoftware implementations with different roles:

- `ORESoftware/k8s-cluster/remote/deployments/formal-methods-server-rs` is an
  annotation-to-SMT/Z3 service for local preconditions, postconditions, and
  assertions.
- `opto-sync/opto-sync-clients/tools/fmctl` is the incubating executable-model
  orchestrator. It runs repository-owned Quint models and is the source of the
  schema-v1 `formal/fm.toml` contract.

The reusable `ORESoftware/formal-methods.rs` extraction is tracked by Linear
DEN-565 and DEN-580. Until that repository is published, CI checks out the
incubator at an exact commit. Zed does not copy the runner into production
code.

## Publication model

`package_publication.qnt` models two authorized requests racing to publish one
immutable package/version. The second request nondeterministically uses either
the same content digest (retry/idempotency) or a different digest (conflict).
The finite state space includes:

- content-addressed upload before metadata finalization;
- a single unique-row transaction winner;
- duplicate and competing finalizers;
- a crash or transaction failure after upload; and
- authorization rejection before upload.

The composed `publication_safety` invariant checks:

1. at most one package/version finalization commits;
2. package metadata, immutable version identity, and advertisement agree;
3. no release is advertised before its metadata commit;
4. every committed digest remains present in blob storage; and
5. unauthorized requests have no artifact or metadata effect.

Simulation must also reach crash-after-upload, competing-publish,
abort-after-upload, unauthorized-rejection, and same-digest-race witnesses.
Those witnesses prevent a green safety result caused by accidentally disabling
the fault paths.

## Latest-selection and yank model

`latest_selection.qnt`, configured by `latest_selection.fm.toml`, models three
totally ordered immutable versions. It explores every publication order plus
yank, restore, and idempotent desired-state replay. The composed
`selection_safety` invariant checks that:

1. only published versions can be yanked;
2. advertised latest is exactly the maximal published, non-yanked version;
3. a yanked version is never advertised as latest; and
4. no latest value is advertised exactly when no visible version exists.

Simulation must reach an older version published after a newer one, yanking the
current latest, restoring a newer version, replaying an already-applied state,
and the all-versions-yanked state. The integer identities abstract the shared
Rust version comparator into a finite total order; Rust regression tests check
the concrete semantic-version and timestamp-independent selection behavior.

## Concurrency finding: retain before safe garbage collection

The model makes artifact availability a safety property. Immediate blob
deletion after a failed metadata transaction cannot preserve that property
without a shared upload lease:

1. request A and request B upload the same content-addressed key;
2. neither version row is committed yet;
3. request A fails and observes zero committed references;
4. request A deletes the key while request B is still in flight; and
5. request B commits a version row that now references a missing object.

The safe failure mode is to retain an unreferenced blob. A future garbage
collector may delete it only after an age or lease boundary proves that no
publisher can still commit it. Temporary storage leakage is a liveness/cost
concern; a committed release that cannot be downloaded is a correctness
failure.

## Run locally

With a schema-v1-compatible `fmctl` binary, Node.js 22, and Java 17 or newer:

```sh
fmctl validate
fmctl doctor
fmctl check
fmctl simulate
fmctl verify

fmctl --manifest formal/latest_selection.fm.toml validate
fmctl --manifest formal/latest_selection.fm.toml check
fmctl --manifest formal/latest_selection.fm.toml simulate
fmctl --manifest formal/latest_selection.fm.toml verify
```

Both manifests pin Quint `0.32.0`, bound simulation to 5,000 samples (16 steps
for publication and 12 for latest selection), bound retained child output to 8
MiB, and give each operation a 10-minute wall-clock budget. `verify` uses TLC
to exhaust each complete finite state graph.

Normalized stdout, stderr, and result records are written beneath
`.formal-artifacts/fmctl/` for publication and
`.formal-artifacts/latest-selection/fmctl/` for selection. CI uploads both even
when verification fails, so counterexamples and exact command provenance
remain inspectable.

## What this proves—and what it does not

A green `fmctl verify` proves `publication_safety` for every reachable state in
the publication model and `selection_safety` for every reachable state in the
latest-selection model. It does not by itself prove:

- that every Rust/SeaORM/S3 execution refines the Quint transition system;
- Postgres, object-store, filesystem, or network durability;
- fairness or eventual successful publication;
- safe age/lease-aware orphan garbage collection;
- dependency-graph resolution, mirror fan-out, or provenance verification;
- ordering correctness outside the concrete comparator behavior covered by
  Rust tests; or
- correctness outside the tool versions, assumptions, and bounds recorded in
  the two manifests.

Rust handler tests cover the matching immutability and transaction regressions.
Later work can add an ITF adapter that drives the real in-memory HTTP/SQLite
stack, then extend the model to reservation, target fan-out, provenance,
dependency-graph resolution, and mirrors.
