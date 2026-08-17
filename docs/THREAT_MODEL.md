# Threat model

## Assets

- accuracy of `READY`, `BLOCKED`, and `UNKNOWN` decisions;
- exact candidate, policy, trust-root, evidence, artifact and environment
  bindings;
- local ledger ordering, idempotence, fencing and audit history;
- confidentiality of configured HMAC keys, API tokens and accidental secrets;
- availability under bounded untrusted JSON, XML, archives and local API input.

## Trust boundaries

The candidate repository, imported evidence, CI files, report text, archive
metadata, API requests and idempotency keys are untrusted. The operator must
protect expected policy/trust digests, HMAC secrets, token files and ledger
directory outside the head checkout. The OS, Python runtime, SQLite library and
protected configuration channel are trusted.

## Addressed attacks

| Attack | Control |
|---|---|
| Self-authorizing pull request | mandatory expected policy and trust-store digests supplied outside the bundle |
| Digest confused with identity | explicit trust level/source kind/authority; local MAC wording; unverified evidence never production-ready |
| Mixed/stale/future evidence | exact candidate/head and bounded timestamp checks |
| Green rerun hides red | flakiness is per independent run ID and retains any failing attempt |
| CI duplication/dilution | unique run/attempt and run-sequence bijection |
| Artifact/SBOM/provenance substitution | exact artifact set, version and digest binding |
| Ambiguous archive | one-FD snapshot, bounded ZIP preflight/TAR stream, traversal/type/collision rejection |
| FIFO/device/symlink input | regular-file no-follow/nonblocking opens on supported POSIX paths |
| JSON/XML bombs | byte/depth/node/count bounds; DTD/ENTITY rejection |
| Waiver privilege confusion | waiver-only key usage, allowed authority, approver identity and exact gate/policy/candidate binding |
| Idempotency confusion | only key digests stored; request binds operation, payload and context |
| Ledger row/state tamper | canonical hash replay plus derived-state reconstruction |
| Ledger truncation | separate monotonic tail anchor; missing/ahead/conflicting anchor fails closed |
| Report injection/secret echo | HTML/Markdown escaping and output-only redaction |
| Local API misuse | loopback-only bind, bearer auth, Host validation, read-only routes, bounded threads/pages |

## Known limits

1. HMAC proves possession of a shared local secret, not public identity,
   non-repudiation, or compliance with an external provenance standard.
2. The ledger anchor shares the local security domain with SQLite. An attacker
   who can rewrite both can create another internally consistent history.
   Receipts therefore always state `authenticity_established: false`.
3. There is an unavoidable post-commit/pre-anchor crash window. It is
   fail-observable and repaired only by an exact idempotent replay from a valid
   historical anchor.
4. POSIX component-wise `openat`/`O_NOFOLLOW` provides the strongest hostile
   workspace containment. Python 3.11 does not expose a complete Windows
   handle-by-handle reparse-point API; the Windows fallback rejects visible
   symlinks but cannot claim race-free containment against a concurrently
   malicious junction owner. Use a protected copied artifact directory or run
   archive inspection in a sandbox when the Windows workspace is hostile.
5. Read-only SQLite preflight can update SQLite shared-memory lock bookkeeping;
   it does not change application tables or ledger content.
6. Offline normalizers establish syntax and coherent summaries only. Their
   outputs remain supplied/self-declared until authenticated externally.

## Non-goals

Shipcheck does not sandbox code because it never executes repository code. It
does not fetch attestations, validate public-key certificate chains, access
GitHub, merge, deploy, extract archives, estimate CI cost, or replace a
transparency service.
