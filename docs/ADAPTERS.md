# Offline adapter contracts

All adapters accept at most 2 MiB and output strict canonical JSON marked
`source_kind: supplied`, `trust_level: self_declared`.

- JUnit XML rejects DTD/ENTITY, nested suites, malformed counts, non-finite
  duration, more than 10,000 XML nodes, and duplicate suite names. It emits
  engine-compatible `test_summary` payloads.
- SARIF accepts 2.1.0 and emits a bounded result-level/rule-gap summary. It does
  not claim that findings passed or that the producing scanner is trusted.
- CycloneDX JSON validates format/version, unique bounded `bom-ref` values and
  emits an engine-compatible SBOM payload explicitly bound to a caller-supplied
  artifact name and SHA-256 digest.
- Bundle composes up to 100 already-normalized documents while refusing any
  upgraded source/trust claim.

Normalizers do not discover files, scan a repository, call a forge, execute a
scanner or build, access a network, or sign their output.
