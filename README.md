# Shipcheck

Shipcheck is an offline, evidence-first release decision engine. It binds a
release candidate to imported CI results, test evidence, artifact manifests,
reproducibility claims, supply-chain records, rollback drills, and deployment
observations; evaluates a versioned policy; and records the decision in a local
transactional ledger.

Shipcheck **decides and records**. It does not merge a pull request, contact a
forge, execute a build, run repository code, extract an archive, or deploy an
artifact. A `READY` decision is not an action. Only `READY` under the
`PRODUCTION` assurance profile is exposed as `production_ready: true`.

Version: **0.1.0 alpha** · Python **3.11+** · runtime dependencies: **zero**.

## Why this is a separate tool

- A generic proof engine can decide whether arbitrary evidence satisfies rules.
  Shipcheck owns the release-specific candidate, CI matrix, artifact,
  reproducibility, deployment-truth, and rollback contracts.
- A repository doctor scans source state. Shipcheck does not scan or execute the
  candidate repository; it evaluates an immutable evidence bundle supplied to
  it.
- An orchestrator runs work. Shipcheck has no job runner or deployment adapter.
  Its only mutation is an explicitly local SQLite decision/promotion ledger.

## Decision contract

Every decision contains all 15 gates:

1. exact subject binding;
2. evidence freshness;
3. configured local attestation authenticity;
4. deterministic diff risk;
5. complete latest CI matrix;
6. commit-bound CI cache evidence;
7. independent-run flakiness;
8. coherent nonzero test execution;
9. exact release artifact set and version;
10. independent reproducibility manifests;
11. artifact-bound SBOM;
12. artifact-bound changelog;
13. candidate/artifact-bound provenance;
14. rollback readiness;
15. observed deployment truth.

Outcomes are `READY`, `BLOCKED`, and `UNKNOWN`. Missing, stale,
unauthenticated, pending, cancelled, or ambiguous evidence never becomes
production-ready. A rerun does not erase an earlier failing independent run.

## Quick start: three synthetic states

The demo is intentionally synthetic and always uses `assurance_profile: LAB`.
Even its complete scenario is `LAB / READY`, returns exit 2, and has
`production_ready: false`.

A shell-safe reproducible flow is:

```bash
python -m shipcheck demo --out .shipcheck-demo > demo-manifest.json
POLICY_DIGEST=$(python -c "import json;print(json.load(open('demo-manifest.json'))['policy_digest'])")
TRUST_DIGEST=$(python -c "import json;print(json.load(open('demo-manifest.json'))['trust_digest'])")

python -m shipcheck decide \
  --evidence .shipcheck-demo/evidence.json \
  --policy .shipcheck-demo/policy.json \
  --trust-store .shipcheck-demo/DEMO_ONLY_trust_store.json \
  --expected-policy-digest "$POLICY_DIGEST" \
  --expected-trust-digest "$TRUST_DIGEST" \
  --format json
# Expected: exit 2, outcome READY, assurance_profile LAB,
# production_ready false.
```

Substitute `evidence-blocked.json` or `evidence-unknown.json` for the other two
states. The demo manifest states the expected outcome, profile, production flag,
and exit code for every scenario. `demo` refuses to overwrite existing files.

## Protected configuration is mandatory

`decide` requires both `--expected-policy-digest` and
`--expected-trust-digest`. Supply those values and the trust store from a
protected CI context outside an untrusted head checkout. A pull request that can
replace its own policy or trust root can otherwise authorize itself.

On POSIX, trust-store and API-token files must be regular, owned by the current
user, and mode `0600`. Ledger directories must be owned by the current user and
mode `0700`. See [docs/TRUST_AND_CI.md](docs/TRUST_AND_CI.md).

## Offline normalizers

Normalizers parse bounded inert files. Output is always marked
`source_kind: supplied` and `trust_level: self_declared`; normalization alone can
never satisfy a production authenticity gate.

```bash
shipcheck normalize junit --input junit.xml --run-id run-42 --out junit.normalized.json
shipcheck normalize sarif --input findings.sarif --out sarif.normalized.json
shipcheck normalize cyclonedx --input bom.json \
  --artifact-name package.whl --artifact-digest "$ARTIFACT_SHA256" \
  --out sbom.normalized.json
shipcheck normalize bundle --input junit.normalized.json \
  --input sarif.normalized.json --input sbom.normalized.json \
  --out evidence.normalized.json
```

JUnit rejects DTD/ENTITY declarations and malformed or oversized XML. SARIF is
limited to version 2.1.0. CycloneDX components and all JSON trees are bounded.

## Reports and exit codes

`decide --format` supports `json`, `markdown`, `html`, and `sarif`. All formats
state the assurance profile and production-ready flag. HTML and Markdown escape
untrusted content; all report projections redact secret-shaped values.

| Exit | Meaning |
|---:|---|
| `0` | `PRODUCTION / READY` or a successful non-decision utility |
| `2` | `BLOCKED`, `UNKNOWN`, or `LAB / READY` |
| `3` | invalid/unsafe input or a contract conflict |
| `4` | unexpected internal fault, emitted without a traceback |

`validate` validates and evaluates structure/trust; it is not a synonym for
production readiness. Its JSON includes `assurance_profile` and
`production_ready`.

## Local ledger and receipts

The ledger uses SQLite WAL transactions, request-bound idempotency keys (stored
only as digests), fencing tokens, a SHA-256 hash chain, and a separate local tail
anchor. It records a decision and local `PLANNED → APPLIED → VERIFIED` state;
rollback yields `ROLLED_BACK`. These transitions never mutate a deployment.

```bash
shipcheck decide ... \
  --ledger /private/shipcheck/ledger.sqlite \
  --idempotency-key release-2026-08-17 \
  --receipt-out receipt.private.json \
  --out decision.json

shipcheck ledger verify --ledger /private/shipcheck/ledger.sqlite
shipcheck receipt verify --receipt receipt.private.json
shipcheck receipt explain --receipt receipt.private.json
```

Receipts contain the exact assessment envelope and can contain operational IDs;
treat them as potentially sensitive. Verification establishes **internal
consistency only**: it replays the chain from genesis and binds the decision to
the assessment payload, but returns `authenticity_established: false`. An
attacker can construct a new self-consistent unkeyed chain. External authenticity
requires an independently protected signed checkpoint or transparency service,
which 0.1.0 deliberately does not implement.

## Read-only dashboard

```bash
shipcheck serve --ledger /private/shipcheck/ledger.sqlite \
  --host 127.0.0.1 --port 8765
```

The server binds only `127.0.0.1` or `::1`, requires a bearer token for API
routes, caps concurrent handlers and response sizes, and exposes no mutation
method. Static dashboard assets do not use dynamic HTML injection.

## Artifact inspection

```bash
shipcheck artifact hash --root dist --path shipcheck-0.1.0.tar.gz
shipcheck artifact inspect --root dist --path shipcheck-0.1.0.tar.gz
```

The bounded inspector does not extract. It rejects traversal, symlinks, devices,
FIFOs, duplicate/case-colliding/non-portable paths, encrypted ZIP entries,
unbounded metadata, expansion bombs, malformed CRCs, and truncated TARs. On
POSIX it opens paths component-by-component beneath an anchored directory. See
the Windows reparse-point limitation in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Development and release gate

```bash
python scripts/check.py
```

The check compiles sources, runs the adversarial suite, validates public JSON
artifacts, builds wheel and sdist, installs the wheel in a clean virtual
environment, and compares the installed capability contract with the source
contract. CI repeats this on Linux and Windows with Python 3.11 and 3.13.

Architecture, governance, security policy, migration mapping, and public JSON
schemas are in [docs/](docs/), [SECURITY.md](SECURITY.md),
[MIGRATION.md](MIGRATION.md), and
[`shipcheck/public_schemas`](src/shipcheck/public_schemas/).
