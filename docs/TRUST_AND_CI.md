# Protected trust and CI runbook

## Required topology

Keep these outside an untrusted pull-request checkout:

- the policy JSON or its protected expected SHA-256 digest;
- the trust store and its protected expected digest;
- HMAC secrets and waiver-only keys;
- API token files;
- the private `0700` ledger directory.

Never compute both `--expected-policy-digest` and the policy from the same
untrusted head checkout. Never accept a trust store added by the candidate.
Shipcheck checks digest equality; the CI platform must protect where the expected
digests originate.

## Source kinds and trust levels

- `synthetic`: fixtures only; forbidden by a PRODUCTION policy invariant.
- `supplied`: normalized caller data; self-declared until authenticated.
- `observed`: locally observed fact, still not automatically authenticated.
- `attested`: an authenticated claim under configured policy.

`verified_attestation` in 0.1.0 means a valid configured local HMAC over the
exact canonical observation. It does not mean a public signature or hosted CI
identity. Policies may additionally restrict authority, issuer and workflow.

## Minimal protected invocation

```bash
shipcheck decide \
  --evidence "$RUNNER_TEMP/evidence.json" \
  --policy "$PROTECTED_CONFIG/policy.json" \
  --trust-store "$PROTECTED_CONFIG/trust-store.json" \
  --expected-policy-digest "$SHIPCHECK_POLICY_SHA256" \
  --expected-trust-digest "$SHIPCHECK_TRUST_SHA256" \
  --ledger "$SHIPCHECK_STATE/ledger.sqlite" \
  --idempotency-key "$CI_RUN_ID:$RELEASE_CANDIDATE" \
  --receipt-out "$RUNNER_TEMP/receipt.private.json" \
  --out "$RUNNER_TEMP/decision.json"
```

Treat a not-ready exit 2 as an expected governance result, not an infrastructure
failure. Treat exit 3 as invalid evidence/configuration. Do not place raw secrets
in evidence, ledger payloads, waiver reasons or idempotency keys.
