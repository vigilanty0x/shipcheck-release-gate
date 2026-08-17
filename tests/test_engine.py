from __future__ import annotations

import dataclasses
import datetime as dt
import unittest

from shipcheck.demo import build_demo
from shipcheck.engine import DecisionEngine
from shipcheck.errors import ValidationError
from shipcheck.models import Attestation, Observation
from shipcheck.trust import sign_observation

from tests.helpers import mutate_observation, payload_change, remove_kind


class EngineGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 8, 17, 10, tzinfo=dt.timezone.utc)
        self.evidence, self.policy, self.store, _ = build_demo(now=self.now)

    def evaluate(self, evidence=None, policy=None):
        return DecisionEngine(trust_store=self.store, clock=lambda: self.now).evaluate(
            evidence or self.evidence, policy or self.policy
        )

    @staticmethod
    def gate(decision, name):
        return next(item for item in decision.gates if item.gate == name)

    def test_baseline_is_ready_lab_not_production(self):
        decision = self.evaluate()
        self.assertEqual("READY", decision.outcome)
        self.assertEqual("LAB", decision.assurance_profile)
        self.assertFalse(decision.production_ready)

    def test_blocked_demo(self):
        evidence, policy, store, _ = build_demo(now=self.now, scenario="blocked")
        decision = DecisionEngine(trust_store=store, clock=lambda: self.now).evaluate(evidence, policy)
        self.assertEqual("BLOCKED", decision.outcome)

    def test_unknown_demo(self):
        evidence, policy, store, _ = build_demo(now=self.now, scenario="unknown")
        decision = DecisionEngine(trust_store=store, clock=lambda: self.now).evaluate(evidence, policy)
        self.assertEqual("UNKNOWN", decision.outcome)

    def test_subject_mismatch_blocks(self):
        evidence = mutate_observation(
            self.evidence, self.store, "diff",
            lambda item: dataclasses.replace(item, subject_commit="f" * 40),
        )
        gate = self.gate(self.evaluate(evidence), "subject_binding")
        self.assertEqual(("fail", "SUBJECT_MISMATCH"), (gate.status, gate.reason_code))

    def test_payload_mutation_invalidates_mac(self):
        evidence = mutate_observation(
            self.evidence, self.store, "diff", payload_change(files=[]), resign=False
        )
        gate = self.gate(self.evaluate(evidence), "authenticity")
        self.assertEqual(("unknown", "EVIDENCE_UNAUTHENTICATED"), (gate.status, gate.reason_code))

    def test_self_declared_observation_is_not_authenticated(self):
        evidence = mutate_observation(
            self.evidence, self.store, "diff",
            lambda item: dataclasses.replace(item, trust=Attestation("self_declared")),
            resign=False,
        )
        self.assertEqual("EVIDENCE_UNAUTHENTICATED", self.gate(self.evaluate(evidence), "authenticity").reason_code)

    def test_stale_observation_is_unknown(self):
        evidence = mutate_observation(
            self.evidence, self.store, "diff",
            lambda item: dataclasses.replace(item, collected_at=self.now - dt.timedelta(hours=25)),
        )
        self.assertEqual(("unknown", "EVIDENCE_STALE"), (self.gate(self.evaluate(evidence), "freshness").status, self.gate(self.evaluate(evidence), "freshness").reason_code))

    def test_future_observation_blocks(self):
        evidence = mutate_observation(
            self.evidence, self.store, "diff",
            lambda item: dataclasses.replace(item, collected_at=self.now + dt.timedelta(minutes=6)),
        )
        self.assertEqual(("fail", "EVIDENCE_FROM_FUTURE"), (self.gate(self.evaluate(evidence), "freshness").status, self.gate(self.evaluate(evidence), "freshness").reason_code))

    def test_missing_diff_is_unknown(self):
        gate = self.gate(self.evaluate(remove_kind(self.evidence, "diff")), "diff_risk")
        self.assertEqual(("unknown", "DIFF_EVIDENCE_MISSING"), (gate.status, gate.reason_code))

    def test_high_diff_risk_blocks(self):
        files = [{"path": f".github/workflows/r{i}.yml", "status": "added", "additions": 10000, "deletions": 0, "binary": False} for i in range(10)]
        evidence = mutate_observation(self.evidence, self.store, "diff", payload_change(version="shipcheck/diff-risk-v1", files=files))
        gate = self.gate(self.evaluate(evidence, dataclasses.replace(self.policy, max_diff_risk=20)), "diff_risk")
        self.assertEqual(("fail", "DIFF_RISK_TOO_HIGH"), (gate.status, gate.reason_code))

    def test_missing_ci_cell_is_unknown(self):
        observations = tuple(item for item in self.evidence.observations if not (item.kind == "ci_run" and item.payload["check"] == "tests" and item.payload["matrix"] == "ubuntu-py311"))
        evidence = dataclasses.replace(self.evidence, observations=observations)
        gate = self.gate(self.evaluate(evidence), "ci_matrix")
        self.assertEqual(("unknown", "CI_MATRIX_INCOMPLETE"), (gate.status, gate.reason_code))

    def test_latest_ci_failure_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "ci_run", payload_change(status="failed"), occurrence=1)
        gate = self.gate(self.evaluate(evidence), "ci_matrix")
        self.assertEqual(("fail", "CI_REQUIRED_CHECK_NOT_PASSING"), (gate.status, gate.reason_code))

    def test_latest_ci_pending_is_unknown(self):
        evidence = mutate_observation(self.evidence, self.store, "ci_run", payload_change(status="pending"), occurrence=1)
        gate = self.gate(self.evaluate(evidence), "ci_matrix")
        self.assertEqual(("unknown", "CI_REQUIRED_CHECK_NOT_PASSING"), (gate.status, gate.reason_code))

    def test_unbound_cache_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "ci_run", payload_change(cache_hit=True, cache_key_bound_to_commit=False))
        gate = self.gate(self.evaluate(evidence), "ci_cache")
        self.assertEqual(("fail", "CI_CACHE_UNBOUND"), (gate.status, gate.reason_code))

    def test_duplicate_ci_attempt_is_invalid(self):
        original = next(item for item in self.evidence.observations if item.kind == "ci_run")
        duplicate = dataclasses.replace(original, observation_id="ci-duplicate")
        duplicate = sign_observation(duplicate, self.store.get(original.trust.key_id or ""))
        evidence = dataclasses.replace(self.evidence, observations=self.evidence.observations + (duplicate,))
        with self.assertRaisesRegex(ValidationError, "duplicate CI run/attempt"):
            self.evaluate(evidence)

    def test_ci_run_sequence_collision_is_invalid(self):
        evidence = mutate_observation(self.evidence, self.store, "ci_run", payload_change(run_sequence=102), occurrence=0)
        with self.assertRaisesRegex(ValidationError, "run_sequence maps"):
            self.evaluate(evidence)

    def test_flake_rate_counts_independent_runs(self):
        evidence = mutate_observation(self.evidence, self.store, "ci_run", payload_change(status="failed"), occurrence=0)
        gate = self.gate(self.evaluate(evidence), "flakiness")
        self.assertEqual(("fail", "FLAKE_RATE_EXCEEDED"), (gate.status, gate.reason_code))

    def test_flake_samples_insufficient_is_unknown(self):
        policy = dataclasses.replace(self.policy, minimum_flake_samples=3)
        gate = self.gate(self.evaluate(policy=policy), "flakiness")
        self.assertEqual(("unknown", "FLAKE_SAMPLES_INSUFFICIENT"), (gate.status, gate.reason_code))

    def test_all_skipped_tests_are_unknown(self):
        evidence = mutate_observation(self.evidence, self.store, "test_summary", payload_change(total=88, passed=0, failed=0, skipped=88))
        gate = self.gate(self.evaluate(evidence), "tests")
        self.assertEqual(("unknown", "TEST_COUNT_INSUFFICIENT"), (gate.status, gate.reason_code))

    def test_incoherent_test_counts_are_invalid(self):
        evidence = mutate_observation(self.evidence, self.store, "test_summary", payload_change(total=88, passed=87))
        with self.assertRaisesRegex(ValidationError, "counts are inconsistent"):
            self.evaluate(evidence)

    def test_failed_tests_block(self):
        evidence = mutate_observation(self.evidence, self.store, "test_summary", payload_change(total=88, passed=87, failed=1, skipped=0))
        gate = self.gate(self.evaluate(evidence), "tests")
        self.assertEqual(("fail", "TEST_EVIDENCE_FAILED"), (gate.status, gate.reason_code))

    def test_truncated_tests_block(self):
        evidence = mutate_observation(self.evidence, self.store, "test_summary", payload_change(truncated=True))
        self.assertEqual("TEST_EVIDENCE_FAILED", self.gate(self.evaluate(evidence), "tests").reason_code)

    def test_required_suite_missing_is_unknown(self):
        policy = dataclasses.replace(self.policy, required_test_suites=("unit", "integration"))
        self.assertEqual("TEST_SUITES_MISSING", self.gate(self.evaluate(policy=policy), "tests").reason_code)

    def test_artifact_version_mismatch_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "artifact", payload_change(version="9.9.9"))
        self.assertEqual("ARTIFACT_VERSION_MISMATCH", self.gate(self.evaluate(evidence), "artifact").reason_code)

    def test_artifact_install_evidence_missing_is_unknown(self):
        evidence = mutate_observation(self.evidence, self.store, "artifact", payload_change(install_tested=False))
        gate = self.gate(self.evaluate(evidence), "artifact")
        self.assertEqual(("unknown", "ARTIFACT_NOT_INSTALL_TESTED"), (gate.status, gate.reason_code))

    def test_artifact_set_mismatch_blocks(self):
        observations = tuple(item for item in self.evidence.observations if item.observation_id != "artifact-.gz")
        evidence = dataclasses.replace(self.evidence, observations=observations)
        self.assertEqual("ARTIFACT_SET_MISMATCH", self.gate(self.evaluate(evidence), "artifact").reason_code)

    def test_reproducibility_manifest_mismatch_blocks(self):
        def mutate(item):
            payload = dict(item.payload); artifacts = [dict(x) for x in payload["artifacts"]]; artifacts[0]["digest"] = "a" * 64; payload["artifacts"] = artifacts
            return dataclasses.replace(item, payload=payload)
        evidence = mutate_observation(self.evidence, self.store, "build_manifest", mutate)
        self.assertEqual("REPRODUCIBILITY_MISMATCH", self.gate(self.evaluate(evidence), "reproducibility").reason_code)

    def test_reproducibility_same_environment_is_unknown(self):
        evidence = mutate_observation(self.evidence, self.store, "build_manifest", payload_change(environment="ubuntu-24.04-py311"), occurrence=1)
        self.assertEqual("REPRO_ENVIRONMENTS_INSUFFICIENT", self.gate(self.evaluate(evidence), "reproducibility").reason_code)

    def test_reproducibility_same_authority_is_unknown(self):
        first = next(item for item in self.evidence.observations if item.kind == "build_manifest")
        key = self.store.get(first.trust.key_id or "")
        evidence = mutate_observation(self.evidence, self.store, "build_manifest", lambda item: dataclasses.replace(item, trust=first.trust), occurrence=1, signer=key)
        self.assertEqual("REPRO_AUTHORITIES_INSUFFICIENT", self.gate(self.evaluate(evidence), "reproducibility").reason_code)

    def test_duplicate_build_id_is_invalid(self):
        evidence = mutate_observation(self.evidence, self.store, "build_manifest", payload_change(build_id="cleanroom-linux"), occurrence=1)
        with self.assertRaisesRegex(ValidationError, "duplicate build_manifest.build_id"):
            self.evaluate(evidence)

    def test_build_manifest_case_collision_is_invalid(self):
        def mutate(item):
            payload = dict(item.payload); artifacts = [dict(x) for x in payload["artifacts"]]
            files = [dict(artifacts[0]["files"][0]), dict(artifacts[0]["files"][0])]
            files[0]["path"] = "A.whl"; files[1]["path"] = "a.whl"; artifacts[0]["files"] = files; payload["artifacts"] = artifacts
            return dataclasses.replace(item, payload=payload)
        evidence = mutate_observation(self.evidence, self.store, "build_manifest", mutate)
        with self.assertRaisesRegex(ValidationError, "duplicate normalized"):
            self.evaluate(evidence)

    def test_sbom_binding_mismatch_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "sbom", payload_change(artifact_digest="a" * 64))
        self.assertEqual("ARTIFACT_BINDING_MISMATCH", self.gate(self.evaluate(evidence), "sbom").reason_code)

    def test_changelog_version_mismatch_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "changelog", payload_change(version="9.9.9"))
        self.assertEqual("CHANGELOG_VERSION_MISMATCH", self.gate(self.evaluate(evidence), "changelog").reason_code)

    def test_provenance_candidate_mismatch_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "provenance", payload_change(candidate_digest="a" * 64))
        self.assertEqual("ARTIFACT_BINDING_MISMATCH", self.gate(self.evaluate(evidence), "provenance").reason_code)

    def test_rollback_environment_mismatch_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "rollback_drill", payload_change(environment="production"))
        self.assertEqual("ROLLBACK_ENVIRONMENT_MISMATCH", self.gate(self.evaluate(evidence), "rollback").reason_code)

    def test_rollback_stale_is_unknown(self):
        evidence = mutate_observation(self.evidence, self.store, "rollback_drill", payload_change(tested_at="2026-08-01T00:00:00Z"))
        self.assertEqual("ROLLBACK_STALE", self.gate(self.evaluate(evidence), "rollback").reason_code)

    def test_rollback_failure_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "rollback_drill", payload_change(status="failed"))
        self.assertEqual("ROLLBACK_NOT_PASSING", self.gate(self.evaluate(evidence), "rollback").reason_code)

    def test_rollback_too_slow_blocks(self):
        evidence = mutate_observation(self.evidence, self.store, "rollback_drill", payload_change(estimated_minutes=31))
        self.assertEqual("ROLLBACK_TOO_SLOW", self.gate(self.evaluate(evidence), "rollback").reason_code)

    def test_required_deploy_observation_missing_is_unknown(self):
        policy = dataclasses.replace(self.policy, require_deploy_observation=True)
        gate = self.gate(self.evaluate(policy=policy), "deploy_truth")
        self.assertEqual(("unknown", "DEPLOY_OBSERVATION_MISSING"), (gate.status, gate.reason_code))

    def test_valid_deploy_observation_passes(self):
        template = next(item for item in self.evidence.observations if item.kind == "rollback_drill")
        artifact = next(item for item in self.evidence.observations if item.kind == "artifact")
        observation = Observation(
            "deploy-staging", "deploy_observation", "synthetic", self.evidence.candidate.digest,
            self.evidence.candidate.head_commit, self.now, template.trust,
            {"environment": "staging", "artifact_digest": artifact.payload["digest"], "release_id": self.evidence.release_id, "status": "observed", "observed_at": self.now.isoformat().replace("+00:00", "Z")},
        )
        observation = sign_observation(observation, self.store.get(template.trust.key_id or ""))
        evidence = dataclasses.replace(self.evidence, observations=self.evidence.observations + (observation,))
        policy = dataclasses.replace(self.policy, require_deploy_observation=True)
        self.assertEqual("DEPLOY_TRUTH_BOUND", self.gate(self.evaluate(evidence, policy), "deploy_truth").reason_code)


if __name__ == "__main__":
    unittest.main()
