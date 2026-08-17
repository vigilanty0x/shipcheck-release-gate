# Security policy

Shipcheck 0.1.x receives security fixes while it is the current minor line.
Report suspected vulnerabilities privately to the repository maintainers. Do
not include production HMAC keys, tokens, private receipts, customer repository
identifiers, or ledger databases in a public issue.

Useful reports contain the Shipcheck/Python/OS versions, the smallest inert
fixture, exact command, observed result, expected invariant and whether the
attacker controls the candidate checkout, evidence bundle, protected
configuration, or ledger directory.

High-priority invariants are:

- forged, stale, mixed or self-authorized evidence cannot become production
  ready;
- policy/trust roots cannot be taken from the same untrusted checkout without a
  protected digest mismatch;
- archive/path input cannot escape its declared root or cause unbounded parsing;
- waiver-only authority and unwaivable gates cannot be bypassed;
- local ledger idempotence, fencing, chain, anchor and derived state fail closed;
- secret-shaped values are not written to reports or ledger payloads;
- the loopback API remains authenticated and read-only.

The following are documented limits rather than vulnerabilities unless a claim
contradicts them: shared-secret HMAC is not a public signature; a local anchor is
not a transparency log; a self-consistent portable receipt does not establish
authorship; Windows junction containment is not claimed for a concurrently
hostile workspace. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
