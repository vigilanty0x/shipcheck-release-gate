"""Evidence-first release decision engine."""

from __future__ import annotations

import datetime as dt
import uuid
from collections import defaultdict
from typing import Any, Callable, Iterable, Mapping

from .errors import ValidationError
from .models import (
    Decision,
    GateResult,
    Observation,
    ReleaseEvidence,
    ReleasePolicy,
    SHA256_RE,
    Waiver,
    group_observations,
    parse_time,
    require_bool,
    require_int,
    require_keys,
    require_number,
    require_string,
)
from .risk import normalize_repo_path, score_diff
from .canonical import object_digest
from .trust import TrustStore

FUTURE_SKEW = dt.timedelta(minutes=5)
UNWAIVABLE = {
    "SUBJECT_MISMATCH",
    "EVIDENCE_UNAUTHENTICATED",
    "ATTESTATION_POLICY_MISMATCH",
    "REPRODUCIBILITY_MISMATCH",
    "ARTIFACT_BINDING_MISMATCH",
    "WAIVER_INVALID",
    "LEDGER_INTEGRITY_FAILED",
}


def _gate(gate: str, status: str, code: str, message: str, observations: Iterable[Observation] = (), **details: Any) -> GateResult:
    return GateResult(gate, status, code, message, tuple(item.observation_id for item in observations), details=details)


def _exact_payload(payload: Mapping[str, Any], name: str, required: set[str], optional: set[str] = frozenset()) -> None:
    require_keys(payload, name, required, optional)


class DecisionEngine:
    """Pure evaluator. It never executes code, calls a forge, merges, or deploys."""

    def __init__(self, *, trust_store: TrustStore | None = None, clock: Callable[[], dt.datetime] | None = None) -> None:
        self.trust_store = trust_store or TrustStore()
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def evaluate(
        self,
        evidence: ReleaseEvidence,
        policy: ReleasePolicy,
        *,
        waivers: Iterable[Waiver] = (),
    ) -> Decision:
        now = self.clock().astimezone(dt.timezone.utc)
        if evidence.created_at > now + FUTURE_SKEW:
            raise ValidationError("evidence.created_at is implausibly in the future")
        gates: list[GateResult] = []
        gates.extend(self._subject_and_trust(evidence, policy, now))
        gates.append(self._diff(evidence, policy))
        gates.extend(self._ci(evidence, policy))
        gates.append(self._tests(evidence, policy))
        gates.append(self._artifacts(evidence, policy))
        gates.append(self._reproducibility(evidence, policy))
        gates.extend(self._supply_chain(evidence, policy))
        gates.append(self._rollback(evidence, policy, now))
        gates.append(self._deployment(evidence, policy, now))
        gates, applied = self._apply_waivers(gates, tuple(waivers), evidence, policy, now)

        if any(item.status == "fail" for item in gates):
            outcome = "BLOCKED"
        elif any(item.status in {"unknown", "pending", "cancelled", "skipped"} for item in gates):
            outcome = "UNKNOWN"
        else:
            outcome = "READY"
        decision_seed = {
            "release_id": evidence.release_id,
            "candidate_digest": evidence.candidate.digest,
            "evidence_digest": evidence.digest,
            "policy_digest": policy.digest,
            "evaluated_at": now.isoformat(),
            "gates": [item.to_dict() for item in gates],
        }
        decision_id = str(uuid.uuid5(uuid.NAMESPACE_URL, object_digest(decision_seed)))
        return Decision(
            decision_id=decision_id,
            release_id=evidence.release_id,
            outcome=outcome,
            evaluated_at=now,
            candidate_digest=evidence.candidate.digest,
            evidence_digest=evidence.digest,
            policy_id=policy.policy_id,
            policy_digest=policy.digest,
            assurance_profile=policy.assurance_profile,
            gates=tuple(gates),
            applied_waivers=tuple(applied),
        )

    def _subject_and_trust(self, evidence: ReleaseEvidence, policy: ReleasePolicy, now: dt.datetime) -> list[GateResult]:
        subject_bad = [item for item in evidence.observations if item.subject_candidate_digest != evidence.candidate.digest or item.subject_commit != evidence.candidate.head_commit]
        results: list[GateResult] = []
        if subject_bad:
            results.append(_gate("subject_binding", "fail", "SUBJECT_MISMATCH", "evidence is mixed or bound to another candidate", subject_bad))
        else:
            results.append(_gate("subject_binding", "pass", "SUBJECT_BOUND", "all observations bind the exact candidate", evidence.observations))

        stale: list[Observation] = []
        future: list[Observation] = []
        age_limit = dt.timedelta(hours=policy.max_evidence_age_hours)
        for item in evidence.observations:
            if item.collected_at > now + FUTURE_SKEW:
                future.append(item)
            elif now - item.collected_at > age_limit:
                stale.append(item)
        if future:
            results.append(_gate("freshness", "fail", "EVIDENCE_FROM_FUTURE", "evidence timestamp exceeds allowed clock skew", future))
        elif stale:
            results.append(_gate("freshness", "unknown", "EVIDENCE_STALE", "evidence is older than policy allows", stale))
        else:
            results.append(_gate("freshness", "pass", "EVIDENCE_FRESH", "evidence is within the freshness window", evidence.observations))

        invalid: list[Observation] = []
        policy_bad: list[Observation] = []
        for item in evidence.observations:
            ok, _ = self.trust_store.verify(item)
            if not ok:
                invalid.append(item)
                continue
            trust = item.trust
            if item.source_kind not in policy.allowed_source_kinds:
                policy_bad.append(item)
            if policy.allowed_authorities and trust.authority not in policy.allowed_authorities:
                policy_bad.append(item)
            if policy.allowed_issuers and trust.issuer not in policy.allowed_issuers:
                policy_bad.append(item)
            if policy.allowed_workflows and trust.workflow not in policy.allowed_workflows:
                policy_bad.append(item)
        if invalid:
            results.append(_gate("authenticity", "unknown", "EVIDENCE_UNAUTHENTICATED", "one or more observations lack a valid configured local MAC", invalid))
        elif policy_bad:
            results.append(_gate("authenticity", "fail", "ATTESTATION_POLICY_MISMATCH", "attested authority, issuer, or workflow is not allowed", policy_bad))
        else:
            results.append(_gate("authenticity", "pass", "EVIDENCE_AUTHENTICATED", "all observations have a valid configured local MAC and allowed identity", evidence.observations))
        return results

    def _diff(self, evidence: ReleaseEvidence, policy: ReleasePolicy) -> GateResult:
        items = group_observations(evidence, "diff")
        if len(items) != 1:
            return _gate("diff_risk", "unknown", "DIFF_EVIDENCE_MISSING", "exactly one diff observation is required", items)
        assessment = score_diff(items[0].payload)
        status = "pass" if assessment.score <= policy.max_diff_risk else "fail"
        code = "DIFF_RISK_ACCEPTABLE" if status == "pass" else "DIFF_RISK_TOO_HIGH"
        return _gate("diff_risk", status, code, f"diff risk is {assessment.score}/100", items, assessment=assessment.to_dict(), threshold=policy.max_diff_risk)

    def _ci(self, evidence: ReleaseEvidence, policy: ReleasePolicy) -> list[GateResult]:
        items = group_observations(evidence, "ci_run")
        parsed: dict[tuple[str, str], list[tuple[Observation, Mapping[str, Any]]]] = defaultdict(list)
        seen_attempts: dict[tuple[str, int], Mapping[str, Any]] = {}
        run_sequences: dict[str, int] = {}
        sequence_runs: dict[int, str] = {}
        cache_unsafe: list[Observation] = []
        for item in items:
            payload = item.payload
            _exact_payload(payload, "ci_run", {"check", "matrix", "status", "run_id", "run_sequence", "attempt", "duration_seconds", "cache_hit", "cache_key_bound_to_commit"})
            check = require_string(payload["check"], "ci_run.check", limit=128)
            matrix = require_string(payload["matrix"], "ci_run.matrix", limit=128)
            status = require_string(payload["status"], "ci_run.status", limit=16)
            if status not in {"passed", "failed", "pending", "cancelled", "skipped", "timed_out"}:
                raise ValidationError(f"unsupported CI status: {status}")
            run_id = require_string(payload["run_id"], "ci_run.run_id", limit=128)
            run_sequence = require_int(payload["run_sequence"], "ci_run.run_sequence", minimum=1, maximum=10_000_000_000)
            attempt = require_int(payload["attempt"], "ci_run.attempt", minimum=1, maximum=100)
            require_number(payload["duration_seconds"], "ci_run.duration_seconds", maximum=604_800)
            cache_hit = require_bool(payload["cache_hit"], "ci_run.cache_hit")
            bound = require_bool(payload["cache_key_bound_to_commit"], "ci_run.cache_key_bound_to_commit")
            if cache_hit and not bound:
                cache_unsafe.append(item)
            attempt_key = (run_id, attempt)
            if attempt_key in seen_attempts:
                raise ValidationError(f"duplicate CI run/attempt: {run_id}/{attempt}")
            seen_attempts[attempt_key] = payload
            if run_id in run_sequences and run_sequences[run_id] != run_sequence:
                raise ValidationError("CI run_id maps to multiple run_sequence values")
            if run_sequence in sequence_runs and sequence_runs[run_sequence] != run_id:
                raise ValidationError("CI run_sequence maps to multiple run_id values")
            run_sequences[run_id] = run_sequence
            sequence_runs[run_sequence] = run_id
            parsed[(check, matrix)].append((item, payload))

        required = {(check, matrix) for check in policy.required_checks for matrix in policy.required_matrix}
        missing = sorted(required - parsed.keys())
        status_bad: list[Observation] = []
        flake_bad: list[Observation] = []
        sparse: list[Observation] = []
        for key in sorted(required & parsed.keys()):
            attempts = parsed[key]
            ordered = sorted(attempts, key=lambda pair: (int(pair[1]["run_sequence"]), int(pair[1]["attempt"])))
            latest_status = str(ordered[-1][1]["status"])
            if latest_status != "passed":
                status_bad.append(ordered[-1][0])
            distinct_runs = {str(payload["run_id"]) for _, payload in ordered}
            if len(distinct_runs) < policy.minimum_flake_samples:
                sparse.extend(item for item, _ in ordered)
            run_failed: dict[str, bool] = {}
            for _, payload in ordered:
                run_id = str(payload["run_id"])
                run_failed[run_id] = run_failed.get(run_id, False) or str(payload["status"]) != "passed"
            failure_count = sum(run_failed.values())
            rate = failure_count / len(run_failed)
            if rate > policy.maximum_flake_rate:
                flake_bad.extend(item for item, _ in ordered)
        results: list[GateResult] = []
        if missing:
            results.append(_gate("ci_matrix", "unknown", "CI_MATRIX_INCOMPLETE", "required CI combinations are missing", items, missing=[{"check": x, "matrix": y} for x, y in missing]))
        elif status_bad:
            proven_fail = any(item.payload["status"] in {"failed", "timed_out"} for item in status_bad)
            results.append(_gate("ci_matrix", "fail" if proven_fail else "unknown", "CI_REQUIRED_CHECK_NOT_PASSING", "a required latest CI run is not passing", status_bad))
        else:
            results.append(_gate("ci_matrix", "pass", "CI_MATRIX_PASSING", "all required CI combinations pass", items))
        if cache_unsafe:
            results.append(_gate("ci_cache", "fail", "CI_CACHE_UNBOUND", "cache hit is not bound to the candidate commit", cache_unsafe))
        else:
            results.append(_gate("ci_cache", "pass", "CI_CACHE_BOUND", "all reported cache hits bind the candidate commit", items))
        if sparse:
            results.append(_gate("flakiness", "unknown", "FLAKE_SAMPLES_INSUFFICIENT", "insufficient independent CI run samples", sparse, required_samples=policy.minimum_flake_samples))
        elif flake_bad:
            results.append(_gate("flakiness", "fail", "FLAKE_RATE_EXCEEDED", "a green rerun does not erase earlier failing evidence", flake_bad, maximum_rate=policy.maximum_flake_rate))
        else:
            results.append(_gate("flakiness", "pass", "FLAKE_RATE_ACCEPTABLE", "required checks meet the flakiness policy", items))
        return results

    def _tests(self, evidence: ReleaseEvidence, policy: ReleasePolicy) -> GateResult:
        items = group_observations(evidence, "test_summary")
        if not items:
            return _gate("tests", "unknown", "TEST_EVIDENCE_MISSING", "test evidence is required")
        total = 0
        executed = 0
        bad: list[Observation] = []
        seen: set[tuple[str, str]] = set()
        observed_suites: set[str] = set()
        for item in items:
            payload = item.payload
            _exact_payload(payload, "test_summary", {"suite", "run_id", "total", "passed", "failed", "skipped", "duration_seconds", "truncated"})
            suite = require_string(payload["suite"], "test_summary.suite", limit=128)
            observed_suites.add(suite)
            run_id = require_string(payload["run_id"], "test_summary.run_id", limit=128)
            if (suite, run_id) in seen:
                raise ValidationError("duplicate test summary suite/run_id")
            seen.add((suite, run_id))
            count = require_int(payload["total"], "test_summary.total", maximum=10_000_000)
            passed = require_int(payload["passed"], "test_summary.passed", maximum=10_000_000)
            failed = require_int(payload["failed"], "test_summary.failed", maximum=10_000_000)
            skipped = require_int(payload["skipped"], "test_summary.skipped", maximum=10_000_000)
            require_number(payload["duration_seconds"], "test_summary.duration_seconds", maximum=604_800)
            truncated = require_bool(payload["truncated"], "test_summary.truncated")
            if passed + failed + skipped != count:
                raise ValidationError("test summary counts are inconsistent")
            if failed or truncated:
                bad.append(item)
            total += count
            executed += passed + failed
            if total > 100_000_000:
                raise ValidationError("test total exceeds 100,000,000")
        missing_suites = sorted(set(policy.required_test_suites) - observed_suites)
        if missing_suites:
            return _gate("tests", "unknown", "TEST_SUITES_MISSING", "required test suites are missing", items, missing=missing_suites)
        if bad:
            return _gate("tests", "fail", "TEST_EVIDENCE_FAILED", "tests failed or evidence is truncated", bad, total=total)
        if executed < policy.minimum_test_count:
            return _gate("tests", "unknown", "TEST_COUNT_INSUFFICIENT", "too few tests were executed", items, total=total, executed=executed, minimum=policy.minimum_test_count)
        return _gate("tests", "pass", "TESTS_PASSING", f"{executed} coherent executed tests pass", items, total=total, executed=executed)

    def _artifact_records(self, evidence: ReleaseEvidence) -> list[tuple[Observation, str, str, int]]:
        records: list[tuple[Observation, str, str, int]] = []
        for item in group_observations(evidence, "artifact"):
            payload = item.payload
            _exact_payload(payload, "artifact", {"name", "digest", "size_bytes", "version", "install_tested"})
            name = require_string(payload["name"], "artifact.name", limit=256)
            digest = require_string(payload["digest"], "artifact.digest", pattern=SHA256_RE)
            size = require_int(payload["size_bytes"], "artifact.size_bytes", minimum=1, maximum=10_000_000_000)
            require_string(payload["version"], "artifact.version", limit=128)
            require_bool(payload["install_tested"], "artifact.install_tested")
            records.append((item, name, digest, size))
        return records

    def _artifacts(self, evidence: ReleaseEvidence, policy: ReleasePolicy) -> GateResult:
        records = self._artifact_records(evidence)
        if not records:
            status = "unknown" if policy.require_artifact else "pass"
            return _gate("artifact", status, "ARTIFACT_MISSING" if policy.require_artifact else "ARTIFACT_OPTIONAL", "release artifact evidence is missing")
        names = [name for _, name, _, _ in records]
        if len(names) != len(set(names)):
            return _gate("artifact", "fail", "ARTIFACT_BINDING_MISMATCH", "artifact names are duplicated", [item for item, *_ in records])
        missing = sorted(set(policy.required_artifacts) - set(names))
        unexpected = sorted(set(names) - set(policy.required_artifacts))
        if missing or unexpected:
            return _gate("artifact", "fail", "ARTIFACT_SET_MISMATCH", "artifact set does not exactly match policy", [item for item, *_ in records], missing=missing, unexpected=unexpected)
        versions = {str(item.payload["version"]) for item, *_ in records}
        if len(versions) != 1:
            return _gate("artifact", "fail", "ARTIFACT_VERSION_MISMATCH", "release artifacts have inconsistent versions", [item for item, *_ in records])
        if versions != {policy.expected_version}:
            return _gate("artifact", "fail", "ARTIFACT_VERSION_MISMATCH", "artifact version does not match protected policy subject", [item for item, *_ in records], expected=policy.expected_version)
        if not all(bool(item.payload["install_tested"]) for item, *_ in records):
            return _gate("artifact", "unknown", "ARTIFACT_NOT_INSTALL_TESTED", "artifact installation was not proven", [item for item, *_ in records])
        return _gate("artifact", "pass", "ARTIFACT_VERIFIED", "release artifact set, digests, versions, and installation evidence are present", [item for item, *_ in records], artifacts={name: digest for _, name, digest, _ in records})

    def _reproducibility(self, evidence: ReleaseEvidence, policy: ReleasePolicy) -> GateResult:
        items = group_observations(evidence, "build_manifest")
        if len(items) < policy.minimum_reproducible_builds:
            return _gate("reproducibility", "unknown", "REPRO_BUILDS_INSUFFICIENT", "independent build manifests are missing", items, required=policy.minimum_reproducible_builds)
        build_ids: set[str] = set()
        environments: set[str] = set()
        authorities: set[str | None] = set()
        authority_keys: set[tuple[str | None, str | None]] = set()
        release_records = self._artifact_records(evidence)
        release_set = {(name, digest, size) for _, name, digest, size in release_records}
        manifest_shapes: set[tuple[tuple[str, str, int, tuple[tuple[str, str, int], ...]], ...]] = set()
        for item in items:
            payload = item.payload
            _exact_payload(payload, "build_manifest", {"build_id", "environment", "artifacts"})
            build_id = require_string(payload["build_id"], "build_manifest.build_id", limit=128)
            if build_id in build_ids:
                raise ValidationError("duplicate build_manifest.build_id")
            build_ids.add(build_id)
            environments.add(require_string(payload["environment"], "build_manifest.environment", limit=128))
            authorities.add(item.trust.authority)
            authority_keys.add((item.trust.authority, item.trust.key_id))
            raw_artifacts = payload["artifacts"]
            if not isinstance(raw_artifacts, list) or not raw_artifacts or len(raw_artifacts) > 100:
                raise ValidationError("build_manifest.artifacts must contain 1 to 100 entries")
            artifact_shape: list[tuple[str, str, int, tuple[tuple[str, str, int], ...]]] = []
            artifact_names: set[str] = set()
            for artifact in raw_artifacts:
                if not isinstance(artifact, dict):
                    raise ValidationError("build_manifest.artifacts entries must be objects")
                _exact_payload(artifact, "build manifest artifact", {"name", "digest", "size_bytes", "files"})
                name = require_string(artifact["name"], "build_manifest.artifact.name", limit=256)
                if name in artifact_names:
                    raise ValidationError("duplicate artifact name in build manifest")
                artifact_names.add(name)
                artifact_digest = require_string(artifact["digest"], "build_manifest.artifact.digest", pattern=SHA256_RE)
                artifact_size = require_int(artifact["size_bytes"], "build_manifest.artifact.size_bytes", minimum=1, maximum=10_000_000_000)
                files = artifact["files"]
                if not isinstance(files, list) or not files or len(files) > 10_000:
                    raise ValidationError("build_manifest artifact files must contain 1 to 10,000 entries")
                file_shape: list[tuple[str, str, int]] = []
                paths: set[str] = set()
                for entry in files:
                    if not isinstance(entry, dict):
                        raise ValidationError("build_manifest file entries must be objects")
                    _exact_payload(entry, "build manifest file", {"path", "digest", "size_bytes", "type"})
                    path = normalize_repo_path(entry["path"])
                    collision_key = path.casefold()
                    if collision_key in paths:
                        raise ValidationError("duplicate normalized build manifest path")
                    paths.add(collision_key)
                    digest = require_string(entry["digest"], "build_manifest.file.digest", pattern=SHA256_RE)
                    size = require_int(entry["size_bytes"], "build_manifest.file.size_bytes", maximum=10_000_000_000)
                    file_type = require_string(entry["type"], "build_manifest.file.type", limit=16)
                    if file_type != "file":
                        raise ValidationError("build manifests may contain regular files only")
                    file_shape.append((path, digest, size))
                artifact_shape.append((name, artifact_digest, artifact_size, tuple(sorted(file_shape))))
            manifest_shapes.add(tuple(sorted(artifact_shape)))
        if len(manifest_shapes) != 1:
            return _gate("reproducibility", "fail", "REPRODUCIBILITY_MISMATCH", "independent builds do not reproduce the exact release artifact", items)
        shape = next(iter(manifest_shapes))
        observed_set = {(name, digest, size) for name, digest, size, _ in shape}
        if observed_set != release_set:
            return _gate("reproducibility", "fail", "REPRODUCIBILITY_MISMATCH", "build manifests do not match the exact release artifact set", items)
        if len(environments) < 2:
            return _gate("reproducibility", "unknown", "REPRO_ENVIRONMENTS_INSUFFICIENT", "builds are not independent across environments", items)
        if len(authorities) < policy.minimum_reproducible_authorities:
            return _gate("reproducibility", "unknown", "REPRO_AUTHORITIES_INSUFFICIENT", "build claims do not have enough independent configured authorities", items, authorities=len(authorities), required=policy.minimum_reproducible_authorities)
        return _gate("reproducibility", "pass", "REPRODUCIBLE", "independent authenticated manifests reproduce the exact artifact set", items, builds=len(build_ids), environments=sorted(environments), authorities=len(authorities), keys=len(authority_keys))

    def _supply_chain(self, evidence: ReleaseEvidence, policy: ReleasePolicy) -> list[GateResult]:
        artifacts = self._artifact_records(evidence)
        artifact_map = {name: digest for _, name, digest, _ in artifacts}
        artifact_version = str(artifacts[0][0].payload["version"]) if artifacts else None
        artifact_set_digest = object_digest([{"name": name, "digest": artifact_map[name]} for name in sorted(artifact_map)])
        results: list[GateResult] = []
        for kind, required, gate_name in (("sbom", policy.require_sbom, "sbom"), ("changelog", policy.require_changelog, "changelog")):
            items = group_observations(evidence, kind)
            if not items:
                results.append(_gate(gate_name, "unknown" if required else "pass", f"{kind.upper()}_MISSING" if required else f"{kind.upper()}_OPTIONAL", f"{kind} evidence is missing"))
                continue
            if kind == "sbom":
                bound_names: set[str] = set()
                bad_binding = False
                for item in items:
                    payload = item.payload
                    _exact_payload(payload, "sbom", {"format", "document_digest", "artifact_name", "artifact_digest", "component_count"})
                    fmt = require_string(payload["format"], "sbom.format", limit=64)
                    if fmt not in {"cyclonedx-json", "spdx-json"}:
                        raise ValidationError("unsupported SBOM format")
                    require_string(payload["document_digest"], "sbom.document_digest", pattern=SHA256_RE)
                    require_int(payload["component_count"], "sbom.component_count", minimum=1, maximum=1_000_000)
                    name = require_string(payload["artifact_name"], "sbom.artifact_name", limit=256)
                    digest = require_string(payload["artifact_digest"], "sbom.artifact_digest", pattern=SHA256_RE)
                    if name in bound_names:
                        raise ValidationError("duplicate SBOM artifact binding")
                    bound_names.add(name)
                    bad_binding = bad_binding or artifact_map.get(name) != digest
                if bad_binding or bound_names != set(artifact_map):
                    results.append(_gate(gate_name, "fail", "ARTIFACT_BINDING_MISMATCH", "SBOM set is not bound to every release artifact", items))
                else:
                    results.append(_gate(gate_name, "pass", "SBOM_BOUND", "SBOM set is bound to every release artifact", items))
                continue
            else:
                if len(items) != 1:
                    raise ValidationError("exactly one changelog observation is allowed")
                payload = items[0].payload
                _exact_payload(payload, "changelog", {"version", "document_digest", "artifact_set_digest"})
                require_string(payload["version"], "changelog.version", limit=128)
                require_string(payload["document_digest"], "changelog.document_digest", pattern=SHA256_RE)
                if artifact_version is not None and payload["version"] != artifact_version:
                    results.append(_gate(gate_name, "fail", "CHANGELOG_VERSION_MISMATCH", "changelog version does not match artifact", items))
                    continue
            bound = require_string(payload["artifact_set_digest"], "changelog.artifact_set_digest", pattern=SHA256_RE)
            if bound != artifact_set_digest:
                results.append(_gate(gate_name, "fail", "ARTIFACT_BINDING_MISMATCH", f"{kind} is not bound to the release artifact", items))
            else:
                results.append(_gate(gate_name, "pass", f"{kind.upper()}_BOUND", f"{kind} is bound to the release artifact", items))
        provenance = group_observations(evidence, "provenance")
        if not provenance:
            results.append(_gate("provenance", "unknown", "PROVENANCE_MISSING", "build provenance evidence is missing"))
        else:
            seen: set[str] = set()
            invalid = False
            for item in provenance:
                payload = item.payload
                _exact_payload(payload, "provenance", {"artifact_name", "artifact_digest", "candidate_digest", "version", "builder_id", "build_type", "materials_digest"})
                name = require_string(payload["artifact_name"], "provenance.artifact_name", limit=256)
                if name in seen:
                    raise ValidationError("duplicate provenance artifact binding")
                seen.add(name)
                invalid = invalid or artifact_map.get(name) != require_string(payload["artifact_digest"], "provenance.artifact_digest", pattern=SHA256_RE)
                invalid = invalid or payload["candidate_digest"] != evidence.candidate.digest
                invalid = invalid or payload["version"] != policy.expected_version
                require_string(payload["builder_id"], "provenance.builder_id", limit=256)
                require_string(payload["build_type"], "provenance.build_type", limit=256)
                require_string(payload["materials_digest"], "provenance.materials_digest", pattern=SHA256_RE)
            if invalid or seen != set(artifact_map):
                results.append(_gate("provenance", "fail", "ARTIFACT_BINDING_MISMATCH", "provenance is not bound to candidate and every artifact", provenance))
            else:
                results.append(_gate("provenance", "pass", "PROVENANCE_BOUND", "provenance binds candidate and every artifact", provenance))
        return results

    def _rollback(self, evidence: ReleaseEvidence, policy: ReleasePolicy, now: dt.datetime) -> GateResult:
        items = group_observations(evidence, "rollback_drill")
        if not items:
            return _gate("rollback", "unknown" if policy.require_rollback else "pass", "ROLLBACK_MISSING" if policy.require_rollback else "ROLLBACK_OPTIONAL", "rollback drill evidence is missing")
        if len(items) != 1:
            raise ValidationError("exactly one rollback drill observation is allowed")
        item = items[0]
        payload = item.payload
        _exact_payload(payload, "rollback_drill", {"drill_id", "environment", "artifact_digest", "status", "tested_at", "restore_point_digest", "estimated_minutes"})
        require_string(payload["drill_id"], "rollback.drill_id", limit=128)
        require_string(payload["environment"], "rollback.environment", limit=128)
        artifact_digest = require_string(payload["artifact_digest"], "rollback.artifact_digest", pattern=SHA256_RE)
        status = require_string(payload["status"], "rollback.status", limit=16)
        tested = parse_time(payload["tested_at"], "rollback.tested_at")
        require_string(payload["restore_point_digest"], "rollback.restore_point_digest", pattern=SHA256_RE)
        minutes = require_int(payload["estimated_minutes"], "rollback.estimated_minutes", maximum=10_080)
        artifacts = self._artifact_records(evidence)
        expected = {digest for _, _, digest, _ in artifacts}
        if artifact_digest not in expected:
            return _gate("rollback", "fail", "ARTIFACT_BINDING_MISMATCH", "rollback drill targets another artifact", items)
        if tested > now + FUTURE_SKEW:
            return _gate("rollback", "fail", "ROLLBACK_FROM_FUTURE", "rollback timestamp exceeds clock skew", items)
        if now - tested > dt.timedelta(hours=policy.rollback_max_age_hours):
            return _gate("rollback", "unknown", "ROLLBACK_STALE", "rollback drill is stale", items)
        if payload["environment"] != policy.expected_environment:
            return _gate("rollback", "fail", "ROLLBACK_ENVIRONMENT_MISMATCH", "rollback drill targets another environment", items)
        if status != "passed":
            return _gate("rollback", "fail" if status == "failed" else "unknown", "ROLLBACK_NOT_PASSING", "rollback drill is not passing", items)
        if minutes > policy.maximum_rollback_minutes:
            return _gate("rollback", "fail", "ROLLBACK_TOO_SLOW", "rollback exceeds recovery-time policy", items, minutes=minutes)
        return _gate("rollback", "pass", "ROLLBACK_READY", "rollback drill is fresh, bound, and passing", items, minutes=minutes)

    def _deployment(self, evidence: ReleaseEvidence, policy: ReleasePolicy, now: dt.datetime) -> GateResult:
        items = group_observations(evidence, "deploy_observation")
        if not items:
            return _gate("deploy_truth", "unknown" if policy.require_deploy_observation else "pass", "DEPLOY_OBSERVATION_MISSING" if policy.require_deploy_observation else "DEPLOY_OBSERVATION_OPTIONAL", "deployment observation is missing")
        if len(items) != 1:
            raise ValidationError("exactly one deployment observation is allowed")
        payload = items[0].payload
        _exact_payload(payload, "deploy_observation", {"environment", "artifact_digest", "release_id", "status", "observed_at"})
        require_string(payload["environment"], "deploy.environment", limit=128)
        digest = require_string(payload["artifact_digest"], "deploy.artifact_digest", pattern=SHA256_RE)
        release_id = require_string(payload["release_id"], "deploy.release_id", limit=128)
        status = require_string(payload["status"], "deploy.status", limit=32)
        observed = parse_time(payload["observed_at"], "deploy.observed_at")
        artifacts = self._artifact_records(evidence)
        expected = {digest for _, _, digest, _ in artifacts}
        if digest not in expected or release_id != evidence.release_id:
            return _gate("deploy_truth", "fail", "ARTIFACT_BINDING_MISMATCH", "deployment observation targets another release or artifact", items)
        if payload["environment"] != policy.expected_environment:
            return _gate("deploy_truth", "fail", "DEPLOY_ENVIRONMENT_MISMATCH", "deployment observation targets another environment", items)
        if observed > now + FUTURE_SKEW or now - observed > dt.timedelta(hours=policy.max_evidence_age_hours):
            return _gate("deploy_truth", "unknown", "DEPLOY_OBSERVATION_STALE", "deployment observation is stale or from the future", items)
        if status != "observed":
            return _gate("deploy_truth", "unknown", "DEPLOY_STATUS_UNKNOWN", "deployment state is not observed", items)
        return _gate("deploy_truth", "pass", "DEPLOY_TRUTH_BOUND", "deployment observation is fresh and artifact-bound", items)

    def _apply_waivers(
        self,
        gates: list[GateResult],
        waivers: tuple[Waiver, ...],
        evidence: ReleaseEvidence,
        policy: ReleasePolicy,
        now: dt.datetime,
    ) -> tuple[list[GateResult], list[str]]:
        if not waivers:
            return gates, []
        valid: dict[tuple[str, str], Waiver] = {}
        invalid_messages: list[str] = []
        for waiver in waivers:
            ok, reason = self.trust_store.verify_waiver(waiver)
            if not ok:
                invalid_messages.append(f"{waiver.waiver_id}: {reason}")
                continue
            if waiver.candidate_digest != evidence.candidate.digest or waiver.policy_digest != policy.digest:
                invalid_messages.append(f"{waiver.waiver_id}: subject or policy mismatch")
                continue
            if waiver.approver != waiver.trust.authority or waiver.trust.authority not in policy.allowed_waiver_authorities:
                invalid_messages.append(f"{waiver.waiver_id}: approver is not an allowed waiver authority")
                continue
            if waiver.expires_at <= now:
                invalid_messages.append(f"{waiver.waiver_id}: expired")
                continue
            if waiver.reason_code in UNWAIVABLE or waiver.reason_code not in policy.waivable_reason_codes:
                invalid_messages.append(f"{waiver.waiver_id}: reason is not waivable")
                continue
            key = (waiver.gate, waiver.reason_code)
            if key in valid:
                invalid_messages.append(f"{waiver.waiver_id}: duplicate waiver target")
                continue
            valid[key] = waiver
        if invalid_messages:
            gates.append(_gate("waivers", "fail", "WAIVER_INVALID", "one or more waivers are invalid", messages=invalid_messages))
            return gates, []
        output: list[GateResult] = []
        applied: list[str] = []
        for gate in gates:
            waiver = valid.get((gate.gate, gate.reason_code))
            if waiver is not None and gate.status in {"fail", "unknown"}:
                output.append(GateResult(gate.gate, "warn", gate.reason_code, gate.message, gate.evidence_ids, waiver.waiver_id, gate.status, gate.details))
                applied.append(waiver.waiver_id)
            else:
                output.append(gate)
        unused = sorted(set(item.waiver_id for item in valid.values()) - set(applied))
        if unused:
            output.append(_gate("waivers", "fail", "WAIVER_INVALID", "waivers did not match an active gate", unused=unused))
        return output, applied


def evaluate_release(
    evidence: ReleaseEvidence,
    policy: ReleasePolicy,
    *,
    trust_store: TrustStore | None = None,
    waivers: Iterable[Waiver] = (),
    now: dt.datetime | None = None,
) -> Decision:
    clock = (lambda: now) if now is not None else None
    return DecisionEngine(trust_store=trust_store, clock=clock).evaluate(evidence, policy, waivers=waivers)
