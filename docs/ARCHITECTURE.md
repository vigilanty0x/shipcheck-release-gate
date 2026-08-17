# Architecture

## Data flow

```text
protected policy digest + protected trust digest
                         │
candidate + observations ├─ strict contracts / configured local MAC checks
                         ▼
                 pure DecisionEngine
                         │
        15 gates + READY/BLOCKED/UNKNOWN
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
     JSON/MD/HTML/SARIF       SQLite assessment envelope
                                      │
                              hash chain + tail anchor
                                      │
                         local promotion state / receipt
```

Shipcheck has four bounded layers:

1. `models`, `limits`, and `risk` parse immutable, versioned contracts. Strict
   JSON rejects duplicate keys, non-finite numbers, invalid UTF-8, lone
   surrogates, excessive size/depth/node counts, and unknown model keys.
2. `trust` authenticates exact canonical observation/waiver bytes with a
   configured local HMAC key and explicit key usage. This is a local shared-key
   MAC, not a public signature, SLSA attestation, or identity proof.
3. `engine` is pure and deterministic for fixed inputs and clock. It has no file,
   subprocess, network, forge, or deployment capability.
4. `ledger`, `receipt`, `report`, and `api` make the result observable. The
   ledger is the only stateful core component; its promotion states describe
   local governance only.

## Candidate and evidence binding

`Candidate.digest` is canonical SHA-256 over repository identifier, base commit,
head commit, tree digest, and ref. Every observation contains the candidate
digest and exact head commit. Artifact-related observations additionally bind
artifact names/digests; deployment and rollback observations bind environment
and release/artifact identity.

The assessment envelope records candidate, evidence, policy, trust-store and
waiver digests; source kinds; policy thresholds/required sets; and the full
decision. The ledger payload digest binds the exact canonical envelope.

## Gate semantics

- Proven failures become `BLOCKED`.
- Missing, stale, unauthenticated, incomplete, in-progress, cancelled, skipped,
  or ambiguous evidence becomes `UNKNOWN`.
- `READY` requires every gate to pass or carry a valid explicit waiver.
- Waived gates remain `warn`, retain `original_status`, and name the waiver.
- Subject, authenticity, integrity, reproducibility mismatch, and artifact
  binding failures are unwaivable.
- `production_ready` is derived, never supplied: only `PRODUCTION / READY` is
  true. A PRODUCTION policy cannot allow synthetic evidence.

## Ledger protocol

Initialization preflights an existing file before schema mutation. The exact
schema version, metadata, DDL fingerprint, table-xinfo columns, indexes, foreign
keys, and absence of triggers/views are checked. A fresh file is securely
precreated and initialized under a cross-process initialization lock.

Mutations use `BEGIN IMMEDIATE`:

1. validate the current anchor against the database history;
2. bind idempotency digest to operation, payload and caller context;
3. append the canonical payload and hash-chain entry;
4. update the derived promotion state in the same transaction;
5. commit SQLite;
6. advance the local anchor.

The commit-before-anchor order leaves a recoverable anchor-behind window rather
than a fatal anchor-ahead window. Exact idempotent replay repairs a valid
historical anchor. Missing, ahead, or history-conflicting anchors fail closed.

`verify()` serializes its database snapshot and anchor read with writers,
recalculates every payload/request/entry hash, validates assessment envelopes,
replays promotion transitions, compares the derived state table, and checks the
anchor. The anchor is local mutable storage and is not a transparency log.

## Stable public surfaces

- Python: immutable models, `DecisionEngine`, `DecisionLedger`, normalizers.
- CLI: JSON errors and fixed exit codes; all decision JSONs expose profile and
  production readiness.
- Reports: JSON, Markdown, HTML, SARIF.
- API: authenticated loopback GET/HEAD only.
- JSON schemas: evidence, policy, decision, normalized inputs, receipt.

Compatibility is promised only within the `shipcheck/v1` family during 0.1.x.
Unknown fields fail closed. A future breaking contract receives a new schema
identifier and explicit migration notes.
