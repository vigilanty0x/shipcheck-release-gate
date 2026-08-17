from __future__ import annotations

import dataclasses
import datetime as dt
import gc
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import warnings
from contextlib import closing
from pathlib import Path
from unittest import mock

from shipcheck.canonical import canonical_json
from shipcheck.demo import build_demo
from shipcheck.errors import ConflictError, LedgerError, ValidationError
from shipcheck.ledger import DecisionLedger, ZERO_HASH
from shipcheck.secureio import atomic_write
from shipcheck.trust import sign_observation


class LedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 8, 17, 10, tzinfo=dt.timezone.utc)
        self.evidence, self.policy, self.store, _ = build_demo(now=self.now)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "private"
        self.root.mkdir(mode=0o700)
        if os.name == "posix":
            os.chmod(self.root, 0o700)
        self.path = self.root / "ledger.sqlite"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def ledger(self) -> DecisionLedger:
        return DecisionLedger(self.path)

    def evaluate(self, ledger: DecisionLedger, key: str = "assessment"):
        return ledger.evaluate_and_record(
            self.evidence, self.policy, self.store,
            expected_policy_digest=self.policy.digest,
            expected_trust_digest=self.store.digest,
            idempotency_key=key,
            now=self.now,
        )

    def production_fixture(self):
        policy = dataclasses.replace(self.policy, assurance_profile="PRODUCTION", allowed_source_kinds=("attested",))
        observations = []
        for item in self.evidence.observations:
            key = self.store.get(item.trust.key_id or "")
            observations.append(sign_observation(dataclasses.replace(item, source_kind="attested"), key))
        return dataclasses.replace(self.evidence, observations=tuple(observations)), policy

    def test_append_and_verify(self):
        ledger = self.ledger()
        receipt = ledger.append("NOTE", {"message": "bounded"}, idempotency_key="note-1")
        self.assertEqual(1, receipt.sequence)
        self.assertTrue(ledger.verify()["ok"])

    def test_idempotent_old_replay_does_not_move_anchor_back(self):
        ledger = self.ledger()
        first = ledger.append("ONE", {"n": 1}, idempotency_key="one")
        ledger.append("TWO", {"n": 2}, idempotency_key="two")
        replay = ledger.append("ONE", {"n": 1}, idempotency_key="one")
        self.assertEqual(first, replay)
        self.assertEqual(2, ledger.verify()["anchor"]["sequence"])

    def test_idempotency_key_is_bound_to_operation_and_payload(self):
        ledger = self.ledger()
        ledger.append("ONE", {"n": 1}, idempotency_key="shared", request={"x": 1})
        with self.assertRaises(ConflictError):
            ledger.append("TWO", {"n": 2}, idempotency_key="shared", request={"x": 1})

    def test_raw_idempotency_key_is_never_persisted(self):
        marker = "SHIPCHECK_CREDENTIAL_CANARY_72F4"
        ledger = self.ledger()
        receipt = ledger.append("NOTE", {"message": "safe"}, idempotency_key=marker)
        self.assertNotIn(marker, canonical_json(receipt.to_dict()).decode())
        blobs = b"".join(path.read_bytes() for path in self.root.iterdir() if path.is_file())
        self.assertNotIn(marker.encode(), blobs)

    def test_missing_anchor_fails_verify_and_mutation(self):
        ledger = self.ledger()
        ledger.append("NOTE", {"n": 1}, idempotency_key="one")
        ledger.anchor_path.unlink()
        self.assertFalse(ledger.verify()["ok"])
        with self.assertRaises(LedgerError):
            ledger.append("NOTE", {"n": 2}, idempotency_key="two")
        with closing(ledger._connect()) as connection, connection:
            self.assertEqual(1, connection.execute("SELECT count(*) FROM ledger_entries").fetchone()[0])

    def test_postcommit_anchor_failure_recovers_on_replay(self):
        ledger = self.ledger()
        original = ledger._sync_anchor_to_tail
        with mock.patch.object(ledger, "_sync_anchor_to_tail", side_effect=LedgerError("injected anchor failure")):
            with self.assertRaises(LedgerError):
                ledger.append("NOTE", {"n": 1}, idempotency_key="one")
        self.assertEqual((0, ZERO_HASH), ledger._read_anchor())
        replay = ledger.append("NOTE", {"n": 1}, idempotency_key="one")
        self.assertEqual(1, replay.sequence)
        self.assertEqual(1, ledger._read_anchor()[0])
        self.assertTrue(ledger.verify()["ok"])
        self.assertTrue(callable(original))

    def test_sparse_corruption_is_reported_not_crashed(self):
        ledger = self.ledger()
        ledger.append("NOTE", {"n": 1}, idempotency_key="one")
        with closing(ledger._connect()) as connection, connection:
            connection.execute("UPDATE ledger_entries SET sequence=100 WHERE sequence=1")
        atomic_write(ledger.anchor_path, canonical_json({"schema_version": "shipcheck/anchor-v1", "sequence": 50, "entry_hash": "a" * 64}) + b"\n")
        result = ledger.verify()
        self.assertFalse(result["ok"])
        self.assertTrue(any("historical anchor sequence" in item for item in result["errors"]))

    def test_evaluate_retry_is_stable_across_time(self):
        ledger = self.ledger()
        now = dt.datetime.now(dt.timezone.utc)
        evidence, policy, store, _ = build_demo(now=now)
        first_decision, first_receipt = ledger.evaluate_and_record(
            evidence, policy, store,
            expected_policy_digest=policy.digest, expected_trust_digest=store.digest,
            idempotency_key="assessment", now=now,
        )
        second_decision, second_receipt = ledger.evaluate_and_record(
            evidence, policy, store,
            expected_policy_digest=policy.digest, expected_trust_digest=store.digest,
            idempotency_key="assessment", now=now + dt.timedelta(seconds=1),
        )
        self.assertEqual(first_decision, second_decision)
        self.assertEqual(first_receipt, second_receipt)
        self.assertEqual(1, ledger.verify()["entries"])

    def test_generic_append_rejects_governed_entry_type(self):
        with self.assertRaisesRegex(ValidationError, "reserved"):
            self.ledger().append("EVALUATED_DECISION", {"outcome": "READY"}, idempotency_key="x")

    def test_imported_decision_is_not_promotable(self):
        ledger = self.ledger()
        decision, _ = self.evaluate(ledger)
        ledger.append_decision(decision, idempotency_key="import")
        with self.assertRaises(ValidationError):
            ledger.plan_promotion(decision, idempotency_key="plan")

    def test_lab_ready_is_not_promotable(self):
        ledger = self.ledger()
        decision, _ = self.evaluate(ledger)
        self.assertEqual("READY", decision.outcome)
        with self.assertRaisesRegex(ValidationError, "PRODUCTION/READY"):
            ledger.plan_promotion(decision, idempotency_key="plan")

    def test_production_promotion_lifecycle(self):
        evidence, policy = self.production_fixture()
        ledger = self.ledger()
        decision, _ = ledger.evaluate_and_record(
            evidence, policy, self.store,
            expected_policy_digest=policy.digest, expected_trust_digest=self.store.digest,
            idempotency_key="assessment", now=self.now,
        )
        self.assertTrue(decision.production_ready)
        ledger.plan_promotion(decision, idempotency_key="plan")
        ledger.apply_promotion(candidate_digest=decision.candidate_digest, decision_digest=decision.digest, expected_fencing_token=1, idempotency_key="apply")
        ledger.verify_promotion(candidate_digest=decision.candidate_digest, decision_digest=decision.digest, expected_fencing_token=2, idempotency_key="verify")
        ledger.rollback_promotion(candidate_digest=decision.candidate_digest, reason="synthetic drill", expected_fencing_token=3, idempotency_key="rollback")
        state = ledger.promotion_state(decision.candidate_digest)
        self.assertEqual(("ROLLED_BACK", 4), (state["state"], state["fencing_token"]))
        self.assertTrue(ledger.verify()["ok"])

    def test_apply_rejects_substituted_decision_digest(self):
        evidence, policy = self.production_fixture(); ledger = self.ledger()
        decision, _ = ledger.evaluate_and_record(evidence, policy, self.store, expected_policy_digest=policy.digest, expected_trust_digest=self.store.digest, idempotency_key="assessment", now=self.now)
        ledger.plan_promotion(decision, idempotency_key="plan")
        with self.assertRaises(ConflictError):
            ledger.apply_promotion(candidate_digest=decision.candidate_digest, decision_digest="a" * 64, expected_fencing_token=1, idempotency_key="apply")

    def test_promotion_state_tamper_is_detected(self):
        evidence, policy = self.production_fixture(); ledger = self.ledger()
        decision, _ = ledger.evaluate_and_record(evidence, policy, self.store, expected_policy_digest=policy.digest, expected_trust_digest=self.store.digest, idempotency_key="assessment", now=self.now)
        ledger.plan_promotion(decision, idempotency_key="plan")
        with closing(ledger._connect()) as connection, connection:
            connection.execute("UPDATE promotion_state SET state='APPLIED', fencing_token=999")
        self.assertFalse(ledger.verify()["ok"])

    def test_foreign_database_is_rejected_without_lock_residue(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("CREATE TABLE user_data(x TEXT)")
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        before = {item.name: item.read_bytes() for item in self.root.iterdir() if item.is_file()}
        with self.assertRaises(LedgerError):
            DecisionLedger(self.path)
        after = {item.name: item.read_bytes() for item in self.root.iterdir() if item.is_file()}
        self.assertEqual(before, after)

    def test_future_schema_is_rejected(self):
        ledger = self.ledger()
        with closing(ledger._connect()) as connection, connection:
            connection.execute("PRAGMA user_version=999")
        with self.assertRaisesRegex(LedgerError, "unsupported"):
            DecisionLedger(self.path)

    def test_generated_column_schema_is_rejected(self):
        ledger = self.ledger()
        with closing(ledger._connect()) as connection, connection:
            connection.execute("ALTER TABLE promotion_state ADD COLUMN shadow TEXT GENERATED ALWAYS AS (state) VIRTUAL")
        with self.assertRaises(LedgerError):
            DecisionLedger(self.path)

    def test_immediate_reopen_honors_wal(self):
        ledger = self.ledger(); ledger.append("NOTE", {"n": 1}, idempotency_key="one")
        reopened = DecisionLedger(self.path)
        self.assertEqual(1, reopened.verify()["entries"])

    def test_connections_are_closed_without_resource_warnings(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            ledger = self.ledger()
            ledger.append("NOTE", {"n": 1}, idempotency_key="one")
            ledger.get_entry(1)
            ledger.list_entries()
            ledger.list_recent_summaries()
            ledger.promotion_state("a" * 64)
            del ledger
            gc.collect()
        resource_warnings = [str(item.message) for item in caught if item.category is ResourceWarning]
        self.assertEqual([], resource_warnings)

    def test_every_opened_connection_is_closed(self):
        opened = []

        class TrackingConnection(sqlite3.Connection):
            was_closed = False

            def close(self):
                self.was_closed = True
                return super().close()

        real_connect = sqlite3.connect

        def tracked_connect(*args, **kwargs):
            kwargs["factory"] = TrackingConnection
            connection = real_connect(*args, **kwargs)
            opened.append(connection)
            return connection

        try:
            with mock.patch("shipcheck.ledger.sqlite3.connect", side_effect=tracked_connect):
                ledger = self.ledger()
                ledger.append("NOTE", {"n": 1}, idempotency_key="one")
                ledger.get_entry(1)
                ledger.list_entries()
                ledger.list_recent_summaries()
                ledger.promotion_state("a" * 64)
                ledger.verify()
            self.assertTrue(opened)
            self.assertTrue(all(connection.was_closed for connection in opened))
        finally:
            for connection in opened:
                connection.close()

    def test_concurrent_cold_start_is_safe(self):
        barrier = threading.Barrier(8)
        errors = []
        def worker(index):
            try:
                barrier.wait(timeout=5)
                DecisionLedger(self.path).append("NOTE", {"worker": index}, idempotency_key=f"worker-{index}")
            except Exception as exc:  # collected and asserted below
                errors.append(exc)
        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(8, DecisionLedger(self.path).verify()["entries"])


if __name__ == "__main__":
    unittest.main()
