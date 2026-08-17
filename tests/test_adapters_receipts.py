from __future__ import annotations

import copy
import datetime as dt
import io
import importlib.resources
import json
import os
import stat
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from pathlib import Path

from shipcheck.adapters import normalize_bundle, normalize_cyclonedx, normalize_junit, normalize_sarif
from shipcheck.artifacts import hash_artifact, inspect_archive
from shipcheck.canonical import object_digest
from shipcheck.cli import EXIT_INVALID, main
from shipcheck.demo import build_demo, write_demo
from shipcheck.engine import DecisionEngine
from shipcheck.errors import SecurityError, ValidationError
from shipcheck.ledger import DecisionLedger, ZERO_HASH
from shipcheck.receipt import INTEGRITY_SCOPE, export_receipt, explain_receipt, verify_receipt
from shipcheck.report import render


class AdapterTests(unittest.TestCase):
    def test_demo_manifest_has_a_versioned_public_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = write_demo(Path(directory) / "fixture")
        schema = json.loads(
            importlib.resources.files("shipcheck")
            .joinpath("public_schemas/demo-manifest-v1.schema.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual("shipcheck/demo-manifest-v1", manifest["schema_version"])
        self.assertEqual(set(schema["required"]), set(manifest))
        self.assertEqual(
            {"ready-lab", "blocked", "unknown"},
            set(manifest["scenarios"]),
        )
        self.assertTrue(all(not item["production_ready"] for item in manifest["scenarios"].values()))

    def test_junit_normalizes_coherent_counts(self):
        result = normalize_junit(b'<testsuite name="unit" tests="3"><testcase time="0.1"/><testcase><failure/></testcase><testcase><skipped/></testcase></testsuite>', run_id="ci-17")
        payload = result["records"][0]["payload"]
        self.assertEqual((3, 1, 1, 1), (payload["total"], payload["passed"], payload["failed"], payload["skipped"]))
        self.assertEqual(("supplied", "self_declared"), (result["source_kind"], result["trust_level"]))

    def test_junit_rejects_dtd(self):
        with self.assertRaisesRegex(ValidationError, "DTD or ENTITY"):
            normalize_junit(b'<!DOCTYPE x [<!ENTITY a "x">]><testsuite name="x" tests="0"/>')

    def test_junit_rejects_malformed_xml(self):
        with self.assertRaisesRegex(ValidationError, "malformed"):
            normalize_junit(b"<testsuite>")

    def test_junit_rejects_declared_count_mismatch(self):
        with self.assertRaisesRegex(ValidationError, "does not match"):
            normalize_junit(b'<testsuite name="x" tests="2"><testcase/></testsuite>')

    def test_sarif_summarizes_results_and_gaps(self):
        raw = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"rules": [{"id": "A"}]}}, "results": [{"ruleId": "A", "level": "error"}, {"ruleId": "B", "level": "warning"}]}]}).encode()
        payload = normalize_sarif(raw)["records"][0]["payload"]
        self.assertEqual(2, payload["result_count"])
        self.assertEqual(["B"], payload["undeclared_rule_ids"])

    def test_sarif_rejects_duplicate_json_key(self):
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            normalize_sarif(b'{"version":"2.1.0","version":"2.1.0","runs":[]}')

    def test_cyclonedx_binds_exact_artifact(self):
        raw = b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"bom-ref":"pkg:a"}]}'
        result = normalize_cyclonedx(raw, artifact_name="a.whl", artifact_digest="a" * 64)
        payload = result["records"][0]["payload"]
        self.assertEqual(("a.whl", "a" * 64, 1), (payload["artifact_name"], payload["artifact_digest"], payload["component_count"]))

    def test_cyclonedx_rejects_duplicate_bom_ref(self):
        raw = b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"bom-ref":"x"},{"bom-ref":"x"}]}'
        with self.assertRaisesRegex(ValidationError, "unique"):
            normalize_cyclonedx(raw, artifact_name="a", artifact_digest="a" * 64)

    def test_bundle_preserves_untrusted_boundary(self):
        junit = normalize_junit(b'<testsuite name="unit" tests="1"><testcase/></testsuite>')
        sbom = normalize_cyclonedx(b'{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{}]}', artifact_name="a", artifact_digest="a" * 64)
        bundle = normalize_bundle([junit, sbom])
        self.assertEqual(("supplied", "self_declared", 2), (bundle["source_kind"], bundle["trust_level"], len(bundle["documents"])))

    def test_bundle_rejects_promoted_trust_claim(self):
        document = normalize_junit(b'<testsuite name="unit" tests="1"><testcase/></testsuite>')
        document["trust_level"] = "verified_attestation"
        with self.assertRaisesRegex(ValidationError, "trust boundary"):
            normalize_bundle([document])


class ReceiptAndReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 8, 17, 10, tzinfo=dt.timezone.utc)
        self.evidence, self.policy, self.store, _ = build_demo(now=self.now)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "private"; self.root.mkdir(mode=0o700)
        if os.name == "posix": os.chmod(self.root, 0o700)
        self.ledger = DecisionLedger(self.root / "ledger.sqlite")
        self.ledger.append("NOTE", {"purpose": "genesis-prefix"}, idempotency_key="prefix")
        self.decision, self.ledger_receipt = self.ledger.evaluate_and_record(
            self.evidence, self.policy, self.store,
            expected_policy_digest=self.policy.digest, expected_trust_digest=self.store.digest,
            idempotency_key="assessment", now=self.now,
        )
        self.receipt = export_receipt(self.ledger, self.ledger_receipt.sequence)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def rehash_outer(receipt):
        unsigned = dict(receipt); unsigned.pop("receipt_digest", None)
        receipt["receipt_digest"] = object_digest(unsigned)

    def test_receipt_binds_exact_assessment_and_genesis(self):
        result = verify_receipt(self.receipt)
        self.assertTrue(result["internally_consistent"])
        self.assertFalse(result["authenticity_established"])
        self.assertEqual(INTEGRITY_SCOPE, result["integrity_scope"])
        self.assertEqual(1, self.receipt["ledger"]["chain"][0]["sequence"])
        self.assertEqual(ZERO_HASH, self.receipt["ledger"]["chain"][0]["previous_hash"])

    def test_receipt_gate_mutation_is_detected_even_when_outer_rehashed(self):
        changed = copy.deepcopy(self.receipt)
        changed["assessment_envelope"]["decision"]["gates"][0]["status"] = "fail"
        self.rehash_outer(changed)
        result = verify_receipt(changed)
        self.assertFalse(result["internally_consistent"])
        self.assertTrue(any("inconsistent" in error or "digest" in error for error in result["errors"]))

    def test_receipt_decision_digest_mutation_is_detected(self):
        changed = copy.deepcopy(self.receipt); changed["decision_digest"] = "0" * 64; self.rehash_outer(changed)
        result = verify_receipt(changed)
        self.assertFalse(result["internally_consistent"])
        self.assertIn("decision digest mismatch", result["errors"])

    def test_receipt_binding_mutation_is_detected(self):
        changed = copy.deepcopy(self.receipt); changed["bindings"]["trust_digest"] = "0" * 64; self.rehash_outer(changed)
        result = verify_receipt(changed)
        self.assertFalse(result["internally_consistent"])
        self.assertIn("receipt bindings do not match assessment envelope", result["errors"])

    def test_receipt_missing_prefix_is_detected(self):
        changed = copy.deepcopy(self.receipt); changed["ledger"]["chain"] = changed["ledger"]["chain"][1:]; self.rehash_outer(changed)
        result = verify_receipt(changed)
        self.assertFalse(result["internally_consistent"])
        self.assertTrue(any("genesis" in error or "sequence gap" in error for error in result["errors"]))

    def test_receipt_reordered_chain_is_detected(self):
        changed = copy.deepcopy(self.receipt); changed["ledger"]["chain"].reverse(); self.rehash_outer(changed)
        self.assertFalse(verify_receipt(changed)["internally_consistent"])

    def test_receipt_deep_mapping_is_bounded(self):
        value = {}; cursor = value
        for _ in range(80): cursor["x"] = {}; cursor = cursor["x"]
        result = verify_receipt(value)
        self.assertFalse(result["internally_consistent"])

    def test_explain_preserves_lab_boundary(self):
        result = explain_receipt(self.receipt)
        self.assertTrue(result["internally_consistent"])
        self.assertEqual(("READY", "LAB", False), (result["outcome"], result["assurance_profile"], result["production_ready"]))

    def test_all_report_formats_expose_lab_and_production_false(self):
        for format_name in ("json", "markdown", "html", "sarif"):
            with self.subTest(format=format_name):
                output = render(self.decision, format_name, self.evidence).decode("utf-8")
                self.assertIn("LAB", output)
                self.assertIn("false", output.lower())

    def test_cli_invalid_arguments_are_stable_json(self):
        stream = io.StringIO()
        with redirect_stderr(stream):
            code = main(["decide"])
        self.assertEqual(EXIT_INVALID, code)
        payload = json.loads(stream.getvalue())
        self.assertEqual("INVALID_INPUT", payload["error"])


class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_regular_artifact_hash(self):
        (self.root / "a.bin").write_bytes(b"shipcheck")
        result = hash_artifact(self.root, "a.bin")
        self.assertEqual(("a.bin", 9, "sha256"), (result["path"], result["size_bytes"], result["algorithm"]))

    def test_zip_manifest_is_deterministic(self):
        with zipfile.ZipFile(self.root / "a.zip", "w") as archive:
            archive.writestr("pkg/a.txt", b"a"); archive.writestr("pkg/b.txt", b"bb")
        result = inspect_archive(self.root, "a.zip")
        self.assertEqual(("zip", 2, ["pkg/a.txt", "pkg/b.txt"]), (result["archive_type"], result["entry_count"], [x["path"] for x in result["files"]]))

    def test_tar_manifest_is_streamed(self):
        with tarfile.open(self.root / "a.tar", "w") as archive:
            info = tarfile.TarInfo("pkg/a.txt"); info.size = 1; archive.addfile(info, io.BytesIO(b"a"))
        result = inspect_archive(self.root, "a.tar")
        self.assertEqual(("tar", 1, "pkg/a.txt"), (result["archive_type"], result["entry_count"], result["files"][0]["path"]))

    def test_archive_traversal_directory_is_rejected(self):
        with zipfile.ZipFile(self.root / "bad.zip", "w") as archive:
            archive.writestr("../../escape/", b""); archive.writestr("safe.txt", b"x")
        with self.assertRaises(ValidationError):
            inspect_archive(self.root, "bad.zip")

    def test_zip_fifo_type_is_rejected(self):
        info = zipfile.ZipInfo("fifo"); info.create_system = 3; info.external_attr = (stat.S_IFIFO | 0o644) << 16
        with zipfile.ZipFile(self.root / "bad.zip", "w") as archive: archive.writestr(info, b"")
        with self.assertRaises(SecurityError):
            inspect_archive(self.root, "bad.zip")

    def test_truncated_tar_is_typed_invalid(self):
        with tarfile.open(self.root / "full.tar", "w") as archive:
            info = tarfile.TarInfo("a.txt"); info.size = 4096; archive.addfile(info, io.BytesIO(b"x" * 4096))
        (self.root / "truncated.tar").write_bytes((self.root / "full.tar").read_bytes()[:1024])
        with self.assertRaises(ValidationError):
            inspect_archive(self.root, "truncated.tar")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_symlink_artifact_is_rejected(self):
        (self.root / "target").write_bytes(b"x")
        try:
            os.symlink("target", self.root / "link")
        except OSError as exc:
            if os.name == "nt" and exc.winerror == 1314:
                self.skipTest("Windows symlink privilege is unavailable")
            raise
        with self.assertRaises(SecurityError):
            hash_artifact(self.root, "link")


if __name__ == "__main__":
    unittest.main()
