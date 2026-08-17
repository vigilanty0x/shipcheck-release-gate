from __future__ import annotations

import dataclasses
import datetime as dt
import json
import unittest

from shipcheck.canonical import canonical_json, object_digest
from shipcheck.errors import ValidationError
from shipcheck.limits import MAX_JSON_BYTES, loads_strict
from shipcheck.models import Attestation, Candidate, Decision, GateResult, ReleaseEvidence, ReleasePolicy
from shipcheck.risk import normalize_repo_path
from shipcheck.trust import TrustStore

from tests.helpers import demo


class StrictJSONTests(unittest.TestCase):
    def test_accepts_canonical_object(self):
        self.assertEqual(loads_strict(b'{"a":1,"b":[true,null]}'), {"a": 1, "b": [True, None]})

    def test_rejects_duplicate_key(self):
        with self.assertRaises(ValidationError): loads_strict(b'{"a":1,"a":2}')

    def test_rejects_nan(self):
        with self.assertRaises(ValidationError): loads_strict(b'{"x":NaN}')

    def test_rejects_infinity(self):
        with self.assertRaises(ValidationError): loads_strict(b'{"x":Infinity}')

    def test_rejects_huge_integer(self):
        with self.assertRaises(ValidationError): loads_strict(b'{"x":' + b'9' * 5000 + b'}')

    def test_rejects_lone_surrogate(self):
        with self.assertRaises(ValidationError): loads_strict(b'{"x":"\\ud800"}')

    def test_rejects_surrogate_in_python_string(self):
        with self.assertRaises(ValidationError): loads_strict('{"x":"\ud800"}')

    def test_rejects_invalid_utf8(self):
        with self.assertRaises(ValidationError): loads_strict(b'{"x":"\xff"}')

    def test_rejects_deep_tree(self):
        with self.assertRaises(ValidationError): loads_strict(("[" * 40 + "0" + "]" * 40).encode())

    def test_rejects_parser_recursion(self):
        with self.assertRaises(ValidationError): loads_strict(("[" * 5000 + "0" + "]" * 5000).encode(), max_bytes=20_000)

    def test_rejects_byte_limit(self):
        with self.assertRaises(ValidationError): loads_strict(b' ' * (MAX_JSON_BYTES + 1))

    def test_canonical_rejects_nonfinite(self):
        with self.assertRaises(ValueError): canonical_json({"x": float("nan")})


class ContractTests(unittest.TestCase):
    def test_candidate_digest_changes_with_head(self):
        evidence, *_ = demo()
        other = dataclasses.replace(evidence.candidate, head_commit="1" * 40)
        self.assertNotEqual(evidence.candidate.digest, other.digest)

    def test_candidate_rejects_short_commit(self):
        with self.assertRaises(ValidationError): Candidate.from_dict({"repository": "a/b", "base_commit": "a", "head_commit": "b" * 40, "tree_digest": "c" * 64, "ref": "main"})

    def test_candidate_rejects_unknown_key(self):
        evidence, *_ = demo(); raw = evidence.candidate.to_dict(); raw["url"] = "https://evil"
        with self.assertRaises(ValidationError): Candidate.from_dict(raw)

    def test_evidence_roundtrip(self):
        evidence, *_ = demo()
        self.assertEqual(ReleaseEvidence.from_dict(evidence.to_dict()).digest, evidence.digest)

    def test_evidence_rejects_unknown_top_key(self):
        evidence, *_ = demo(); raw = evidence.to_dict(); raw["command"] = "rm -rf"
        with self.assertRaises(ValidationError): ReleaseEvidence.from_dict(raw)

    def test_evidence_rejects_duplicate_observation_ids(self):
        evidence, *_ = demo(); raw = evidence.to_dict(); raw["observations"].append(raw["observations"][0])
        with self.assertRaises(ValidationError): ReleaseEvidence.from_dict(raw)

    def test_attestation_requires_mac(self):
        with self.assertRaises(ValidationError): Attestation.from_dict({"level": "verified_attestation", "authority": "a", "key_id": "k"})

    def test_policy_roundtrip(self):
        _, policy, *_ = demo()
        self.assertEqual(ReleasePolicy.from_dict(policy.to_dict()).digest, policy.digest)

    def test_policy_rejects_empty_checks(self):
        _, policy, *_ = demo(); raw = policy.to_dict(); raw["required_checks"] = []
        with self.assertRaises(ValidationError): ReleasePolicy.from_dict(raw)

    def test_policy_rejects_bool_integer(self):
        _, policy, *_ = demo(); raw = policy.to_dict(); raw["max_diff_risk"] = True
        with self.assertRaises(ValidationError): ReleasePolicy.from_dict(raw)

    def test_policy_direct_constructor_is_equally_strict(self):
        _, policy, *_ = demo()
        with self.assertRaises(ValidationError):
            dataclasses.replace(policy, required_checks=())
        with self.assertRaises(ValidationError):
            dataclasses.replace(policy, max_diff_risk=True)

    def test_policy_digest_changes_with_expected_version(self):
        _, policy, *_ = demo(); other = dataclasses.replace(policy, expected_version="9.9.9")
        self.assertNotEqual(policy.digest, other.digest)

    def test_gate_warn_requires_waiver(self):
        with self.assertRaises(ValidationError): GateResult("tests", "warn", "X", "x")

    def test_gate_nonwarn_rejects_waiver(self):
        with self.assertRaises(ValidationError): GateResult("tests", "pass", "X", "x", waived_by="w", original_status="fail")

    def test_contract_payloads_are_deeply_immutable(self):
        evidence, policy, store, _ = demo()
        observation = evidence.observations[0]
        with self.assertRaises(TypeError):
            observation.payload["changed"] = True
        from shipcheck.engine import DecisionEngine
        decision = DecisionEngine(trust_store=store, clock=lambda: evidence.created_at).evaluate(evidence, policy)
        with self.assertRaises(TypeError):
            decision.gates[0].details["changed"] = True

    def test_direct_verified_attestation_requires_complete_mac(self):
        with self.assertRaises(ValidationError):
            Attestation("verified_attestation", authority="authority", key_id="key")

    def test_decision_rejects_empty_gate_set(self):
        with self.assertRaises(ValidationError): Decision("d", "r", "READY", dt.datetime.now(dt.timezone.utc), "a"*64, "b"*64, "p", "c"*64, "LAB", ())

    def test_decision_roundtrip(self):
        evidence, policy, store, _ = demo()
        from shipcheck.engine import DecisionEngine
        decision = DecisionEngine(trust_store=store, clock=lambda: evidence.created_at).evaluate(evidence, policy)
        self.assertEqual(Decision.from_dict(decision.to_dict()).digest, decision.digest)

    def test_trust_store_rejects_usage_unknown(self):
        raw = {"schema_version": "shipcheck/trust-v1", "keys": [{"key_id": "k", "authority": "a", "secret_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=", "usages": ["deploy"]}]}
        with self.assertRaises(ValidationError): TrustStore.from_dict(raw)


class PortablePathTests(unittest.TestCase):
    def test_accepts_portable_path(self): self.assertEqual(normalize_repo_path("src/app.py"), "src/app.py")
    def test_rejects_parent(self):
        with self.assertRaises(ValidationError): normalize_repo_path("../app.py")
    def test_rejects_backslash(self):
        with self.assertRaises(ValidationError): normalize_repo_path("src\\app.py")
    def test_rejects_drive(self):
        with self.assertRaises(ValidationError): normalize_repo_path("C:/app.py")
    def test_rejects_reserved_name(self):
        with self.assertRaises(ValidationError): normalize_repo_path("src/NUL.txt")
    def test_rejects_trailing_dot(self):
        with self.assertRaises(ValidationError): normalize_repo_path("src/name.")
    def test_rejects_non_nfc(self):
        with self.assertRaises(ValidationError): normalize_repo_path("e\u0301.txt")
