# Contributing

Use Python 3.11 or newer and make changes inside this repository only. Preserve
the offline/no-execution boundary. Add negative tests for every input-validation,
trust, path, archive, ledger, waiver, API or redaction change.

Run:

```bash
python scripts/check.py
```

Do not weaken strict unknown-key handling or convert missing/unauthenticated data
to passing evidence for convenience. A behavior change requires a changelog
entry; a contract break requires a new schema identifier and migration notes.
