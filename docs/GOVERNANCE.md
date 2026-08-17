# Governance and release policy

Shipcheck is evidence-first and fail-closed. Contract changes require:

1. a versioned schema change or a backwards-compatible optional behavior;
2. negative tests for missing, malformed, forged, stale and conflicting input;
3. source and built-artifact parity;
4. security review for trust, path, archive, ledger, waiver, API or redaction
   changes;
5. an entry in `CHANGELOG.md` and, for breaking changes, `MIGRATION.md`.

No maintainer may declare production readiness from a LAB decision. Waivers must
be time-bounded, exact-subject, exact-policy, exact-gate, authenticated with a
waiver-only key, and preserved visibly as `warn` with original status. Trust,
subject and integrity failures are never waived.

Release artifacts are a wheel and sdist built from the same source. The release
gate runs `python scripts/check.py`, installs the wheel in a fresh environment,
and compares the installed and source capability contracts. CI runs on Linux
and Windows, Python 3.11 and 3.13, with action SHAs pinned and repository
permissions read-only.

Security reports follow [SECURITY.md](../SECURITY.md). The project does not
promise that a local receipt is publicly authentic; claims must match the
machine-readable fields.
