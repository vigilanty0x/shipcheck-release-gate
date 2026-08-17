"""Deterministic synthetic end-to-end demo data."""

from __future__ import annotations

import base64
import datetime as dt
from pathlib import Path
from typing import Any

from .canonical import object_digest
from .models import Attestation, Candidate, Observation, ReleaseEvidence, ReleasePolicy, format_time
from .secureio import atomic_write
from .trust import TrustKey, TrustStore, sign_observation
from .canonical import canonical_json
from .errors import ValidationError

DEMO_SECRET = b"shipcheck-demo-key-not-for-production-000000000000000000000000"
DEMO_SECRET_2 = b"shipcheck-demo-key-2-not-for-production-0000000000000000000000"


def build_demo(*, now: dt.datetime | None = None, scenario: str = "ready-lab") -> tuple[ReleaseEvidence, ReleasePolicy, TrustStore, dict[str, Any]]:
    if scenario not in {"ready-lab", "blocked", "unknown"}:
        raise ValueError("scenario must be ready-lab, blocked, or unknown")
    observed_at = (now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)).astimezone(dt.timezone.utc)
    candidate = Candidate("vigilanty0x/shipcheck-demo", "a" * 40, "b" * 40, "c" * 64, "refs/tags/v0.1.0")
    key = TrustKey("demo-evidence", "synthetic-demo-builder", DEMO_SECRET, ("evidence",))
    key2 = TrustKey("demo-evidence-2", "synthetic-demo-builder-2", DEMO_SECRET_2, ("evidence",))
    observations: list[Observation] = []

    def add(kind: str, observation_id: str, payload: dict[str, Any], *, signer: TrustKey = key) -> None:
        unsigned = Observation(
            observation_id, kind, "synthetic", candidate.digest, candidate.head_commit, observed_at,
            Attestation("self_declared", issuer="shipcheck-demo", workflow="offline-fixture"), payload,
        )
        observations.append(sign_observation(unsigned, signer))

    add("diff", "diff-v1", {"version": "shipcheck/diff-risk-v1", "files": [
        {"path": "src/example.py", "status": "modified", "additions": 18, "deletions": 4, "binary": False},
        {"path": "tests/test_example.py", "status": "modified", "additions": 32, "deletions": 2, "binary": False},
    ]})
    sequence = 100
    for check in ("tests", "package"):
        for matrix in ("ubuntu-py311", "windows-py313"):
            for sample in (1, 2):
                sequence += 1
                add("ci_run", f"ci-{check}-{matrix}-{sample}", {
                    "check": check, "matrix": matrix, "status": "passed", "run_id": f"run-{check}-{matrix}-{sample}",
                    "run_sequence": sequence, "attempt": 1, "duration_seconds": 12 + sample,
                    "cache_hit": sample == 2, "cache_key_bound_to_commit": True,
                })
    add("test_summary", "tests-unit", {"suite": "unit", "run_id": "run-tests-ubuntu-py311-2", "total": 88, "passed": 88, "failed": 0, "skipped": 0, "duration_seconds": 3.2, "truncated": False})
    artifact_specs = [
        ("shipcheck-0.1.0-py3-none-any.whl", "d" * 64, 42_000),
        ("shipcheck-0.1.0.tar.gz", "e" * 64, 38_000),
    ]
    for name, digest, size in artifact_specs:
        add("artifact", f"artifact-{name[-3:]}", {"name": name, "digest": digest, "size_bytes": size, "version": "0.1.0", "install_tested": True})
    build_artifacts = [
        {"name": name, "digest": digest, "size_bytes": size, "files": [{"path": name, "digest": digest, "size_bytes": size, "type": "file"}]}
        for name, digest, size in artifact_specs
    ]
    add("build_manifest", "build-linux", {"build_id": "cleanroom-linux", "environment": "ubuntu-24.04-py311", "artifacts": build_artifacts})
    add("build_manifest", "build-windows", {"build_id": "cleanroom-windows", "environment": "windows-2025-py313", "artifacts": build_artifacts}, signer=key2)
    for index, (name, digest, _) in enumerate(artifact_specs, 1):
        add("sbom", f"sbom-{index}", {"format": "cyclonedx-json", "document_digest": str(index) * 64, "artifact_name": name, "artifact_digest": digest, "component_count": 1})
        add("provenance", f"provenance-{index}", {"artifact_name": name, "artifact_digest": digest, "candidate_digest": candidate.digest, "version": "0.1.0", "builder_id": "synthetic-demo-builder", "build_type": "cleanroom-package", "materials_digest": str(index + 2) * 64})
    artifact_set_digest = object_digest([{"name": name, "digest": digest} for name, digest, _ in sorted(artifact_specs)])
    add("changelog", "changelog-v010", {"version": "0.1.0", "document_digest": "f" * 64, "artifact_set_digest": artifact_set_digest})
    add("rollback_drill", "rollback-staging", {"drill_id": "synthetic-drill-1", "environment": "staging", "artifact_digest": artifact_specs[0][1], "status": "passed", "tested_at": format_time(observed_at), "restore_point_digest": "9" * 64, "estimated_minutes": 4})
    if scenario == "blocked":
        first_ci = next(index for index, item in enumerate(observations) if item.kind == "ci_run")
        item = observations[first_ci]
        changed_payload = dict(item.payload); changed_payload["status"] = "failed"
        observations[first_ci] = sign_observation(Observation(item.observation_id, item.kind, item.source_kind, item.subject_candidate_digest, item.subject_commit, item.collected_at, item.trust, changed_payload), key)
    elif scenario == "unknown":
        observations = [item for item in observations if item.kind != "rollback_drill"]
    evidence = ReleaseEvidence(f"v0.1.0-demo-{scenario}", observed_at, candidate, tuple(observations))
    policy = ReleasePolicy.from_dict({
        "schema_version": "shipcheck/v1", "policy_id": "synthetic-demo-policy", "assurance_profile": "LAB",
        "required_checks": ["tests", "package"], "required_matrix": ["ubuntu-py311", "windows-py313"],
        "required_test_suites": ["unit"], "required_artifacts": [item[0] for item in artifact_specs],
        "expected_environment": "staging", "expected_version": "0.1.0", "minimum_test_count": 80, "minimum_flake_samples": 2,
        "allowed_authorities": ["synthetic-demo-builder", "synthetic-demo-builder-2"], "allowed_issuers": ["shipcheck-demo"],
        "allowed_workflows": ["offline-fixture"], "allowed_source_kinds": ["synthetic"],
    })
    store = TrustStore({key.key_id: key, key2.key_id: key2})
    raw_store = {"schema_version": "shipcheck/trust-v1", "keys": [
        {"key_id": signer.key_id, "authority": signer.authority, "secret_base64": base64.b64encode(signer.secret).decode("ascii"), "usages": ["evidence"]}
        for signer in (key, key2)
    ]}
    return evidence, policy, store, raw_store


def write_demo(directory: str | Path) -> dict[str, Any]:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    shared_now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    evidence, policy, _, trust = build_demo(now=shared_now, scenario="ready-lab")
    outputs = {
        "evidence": target / "evidence.json",
        "policy": target / "policy.json",
        "trust_store": target / "DEMO_ONLY_trust_store.json",
    }
    scenario_paths = {scenario: target / f"evidence-{scenario}.json" for scenario in ("blocked", "unknown")}
    existing = [path for path in [*outputs.values(), *scenario_paths.values()] if path.exists()]
    if existing:
        raise ValidationError("demo refuses to overwrite existing fixture files")
    atomic_write(outputs["evidence"], canonical_json(evidence.to_dict()) + b"\n")
    atomic_write(outputs["policy"], canonical_json(policy.to_dict()) + b"\n")
    atomic_write(outputs["trust_store"], canonical_json(trust) + b"\n")
    scenarios: dict[str, Any] = {"ready-lab": {"evidence": str(outputs["evidence"]), "expected_outcome": "READY", "assurance_profile": "LAB", "production_ready": False, "expected_exit": 2}}
    for scenario in ("blocked", "unknown"):
        scenario_evidence, _, _, _ = build_demo(now=shared_now, scenario=scenario)
        scenario_path = scenario_paths[scenario]
        atomic_write(scenario_path, canonical_json(scenario_evidence.to_dict()) + b"\n")
        scenarios[scenario] = {"evidence": str(scenario_path), "expected_outcome": scenario.upper(), "assurance_profile": "LAB", "production_ready": False, "expected_exit": 2}
    return {
        "schema_version": "shipcheck/demo-manifest-v1",
        **{name: str(path) for name, path in outputs.items()},
        "policy_digest": policy.digest,
        "trust_digest": TrustStore.from_dict(trust).digest,
        "scenarios": scenarios,
    }
