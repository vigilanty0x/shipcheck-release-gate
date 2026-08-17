# Consolidation and migration map

Shipcheck provides one coherent release-decision contract for concepts that
previously appeared across multiple utilities and proposals. No legacy
repository was modified, archived, deleted or imported. Git history has not
been transplanted. The machine-readable source map is packaged as
[`shipcheck/compatibility.json`](src/shipcheck/compatibility.json).

| Prior concept | Shipcheck 0.1 target | Compatibility |
|---|---|---|
| CI Summary | `ci_run` observations and reports | normalize data; no legacy CLI alias |
| Matrix | `required_checks × required_matrix` gate | exact exhaustive matrix |
| Diff Risk | `shipcheck/diff-risk-v1` | versioned deterministic score |
| Test Evidence | `test_summary`, JUnit normalizer | coherent counts/nonzero execution |
| Flaky | independent run histories | rerun green never erases red |
| Release | artifact/version/supply-chain gates | exact release subject |
| Deploy Truth | imported `deploy_observation` | observation only; never deploys |
| Rollback | imported `rollback_drill` | observation only; local state record |
| Build Metrics | CI/test durations in evidence | reported, not a job runner |
| Bug Capsule | not implemented in 0.1 | use a separate diagnostic artifact |
| CI Proof Bundle | assessment envelope + private receipt | receipt authenticity remains external |
| Action SHA Auditor | not implemented | repository scanning belongs elsewhere |
| Workflow Permission Linter | not implemented | repository scanning belongs elsewhere |
| Cleanroom Package Tester | artifact/install/repro observations | Shipcheck imports results; never executes tests |
| SBOM Diff | exact SBOM-to-artifact binding | semantic SBOM diff deferred |
| Release Repro Comparator | build-manifest gate | exact artifact/file set comparison |
| Changelog/SemVer validator | expected version + changelog binding | semantic prose validation deferred |
| CI Cost Estimator | not implemented | durations imported; pricing/orchestration out of scope |

The former names do not become hidden compatibility modes. Automation must move
to versioned Shipcheck JSON or the documented normalizers. Unsupported legacy
commands receive no silent success path.
