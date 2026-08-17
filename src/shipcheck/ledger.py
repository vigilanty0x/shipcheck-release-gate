"""Transactional SQLite decision ledger with hash-chain and tail anchor."""

from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import stat
import re
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import canonical_json, object_digest, sha256_hex
from .errors import ConflictError, LedgerError, NotFoundError, SecurityError, ValidationError
from .limits import loads_strict
from .models import Decision, ReleaseEvidence, ReleasePolicy, Waiver, format_time
from .trust import TrustStore
from .redaction import redact
from .secureio import atomic_write, read_regular_file

ZERO_HASH = "0" * 64
ASSESSMENT_ENVELOPE_KEYS = {
    "schema_version", "engine_version", "candidate_digest", "evidence_digest",
    "policy_digest", "trust_digest", "assurance_profile", "source_kinds",
    "policy_summary", "waiver_digests", "decision",
}
POLICY_SUMMARY_KEYS = {
    "required_checks", "required_matrix", "required_test_suites", "required_artifacts",
    "expected_environment", "expected_version", "max_evidence_age_hours", "max_diff_risk",
    "minimum_test_count", "minimum_flake_samples", "maximum_flake_rate",
    "minimum_reproducible_builds", "minimum_reproducible_authorities",
    "require_artifact", "require_sbom", "require_changelog", "require_rollback",
    "require_deploy_observation", "rollback_max_age_hours", "maximum_rollback_minutes",
}
EXPECTED_TABLE_SQL = {
    "ledger_entries": "create table ledger_entries ( sequence integer primary key autoincrement, idempotency_key_digest text not null unique, request_digest text not null, entry_type text not null, payload_json blob not null, payload_digest text not null, previous_hash text not null, entry_hash text not null unique, created_at text not null )",
    "ledger_meta": "create table ledger_meta ( key text primary key, value text not null )",
    "promotion_state": "create table promotion_state ( candidate_digest text primary key, state text not null, fencing_token integer not null, decision_digest text not null, plan_sequence integer not null, updated_sequence integer not null, foreign key(plan_sequence) references ledger_entries(sequence), foreign key(updated_sequence) references ledger_entries(sequence) )",
    "sqlite_sequence": "create table sqlite_sequence(name,seq)",
}


def _normalize_schema_sql(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


def _policy_summary(policy: ReleasePolicy) -> dict[str, Any]:
    raw = policy.to_dict()
    return {key: raw[key] for key in sorted(POLICY_SUMMARY_KEYS)}


@dataclass(frozen=True, slots=True)
class LedgerReceipt:
    sequence: int
    entry_hash: str
    previous_hash: str
    idempotency_key_digest: str
    request_digest: str
    entry_type: str
    payload_digest: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "entry_hash": self.entry_hash,
            "previous_hash": self.previous_hash,
            "idempotency_key_digest": self.idempotency_key_digest,
            "request_digest": self.request_digest,
            "entry_type": self.entry_type,
            "payload_digest": self.payload_digest,
            "created_at": self.created_at,
        }


def _check_no_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise SecurityError(f"symlink path component is forbidden: {current}")


class DecisionLedger:
    """A local integrity log; it is not an external signature or transparency log."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).absolute()
        self.anchor_path = self.path.with_suffix(self.path.suffix + ".anchor")
        self.lock_path = Path(str(self.path) + ".init.lock")
        _check_no_symlink_components(self.path.parent)
        if not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=False, mode=0o700)
        self._check_private_directory(self.path.parent)
        _check_no_symlink_components(self.path)
        if self.path.exists() and self.path.stat().st_size > 0 and not self.lock_path.exists():
            self._check_private_file(self.path)
            self._preflight_existing()
        with self._initialization_lock():
            _check_no_symlink_components(self.path)
            _check_no_symlink_components(self.anchor_path)
            if not self.path.exists():
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(self.path, flags, 0o600)
                os.close(fd)
            existing = self.path.stat().st_size > 0
            for candidate in (self.path, self.anchor_path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm"), self.lock_path):
                if candidate.exists():
                    self._check_private_file(candidate)
            if existing:
                self._preflight_existing()
            self._initialize()

    @contextmanager
    def _initialization_lock(self):
        _check_no_symlink_components(self.lock_path)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.lock_path, flags, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            yield
        finally:
            if os.name == "posix":
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            else:
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)

    @staticmethod
    def _check_private_directory(path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SecurityError("ledger parent must be a real directory")
        if os.name == "posix":
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise SecurityError("ledger parent must be owned by current user with mode 0700")

    @staticmethod
    def _check_private_file(path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SecurityError(f"ledger file must be regular and no-follow: {path}")
        if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise SecurityError(f"ledger file must be owned by current user with mode 0600: {path}")

    def _preflight_existing(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)
            names = connection.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY type,name").fetchall()
            expected_names = {("table", "ledger_entries"), ("table", "ledger_meta"), ("table", "promotion_state"), ("table", "sqlite_sequence")}
            if set(names) != expected_names:
                raise LedgerError("existing SQLite file is not an exact Shipcheck ledger schema")
            if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise LedgerError("unsupported Shipcheck ledger schema version")
            meta = dict(connection.execute("SELECT key,value FROM ledger_meta").fetchall())
            if meta != {"schema_id": "shipcheck-ledger", "schema_version": "1"}:
                raise LedgerError("Shipcheck ledger metadata is missing or incompatible")
            expected_columns = {
                "ledger_meta": [("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0)],
                "ledger_entries": [("sequence", "INTEGER", 0, 1), ("idempotency_key_digest", "TEXT", 1, 0), ("request_digest", "TEXT", 1, 0), ("entry_type", "TEXT", 1, 0), ("payload_json", "BLOB", 1, 0), ("payload_digest", "TEXT", 1, 0), ("previous_hash", "TEXT", 1, 0), ("entry_hash", "TEXT", 1, 0), ("created_at", "TEXT", 1, 0)],
                "promotion_state": [("candidate_digest", "TEXT", 0, 1), ("state", "TEXT", 1, 0), ("fencing_token", "INTEGER", 1, 0), ("decision_digest", "TEXT", 1, 0), ("plan_sequence", "INTEGER", 1, 0), ("updated_sequence", "INTEGER", 1, 0)],
            }
            for table, expected in expected_columns.items():
                actual = [(row[1], row[2].upper(), row[3], row[4], row[5], row[6]) for row in connection.execute(f"PRAGMA table_xinfo({table})")]
                expected = [(name, kind, required, None, primary, 0) for name, kind, required, primary in expected]
                if actual != expected:
                    raise LedgerError(f"existing ledger table schema mismatch: {table}")
            expected_indexes = {
                "ledger_meta": {("key",)},
                "ledger_entries": {("idempotency_key_digest",), ("entry_hash",)},
                "promotion_state": {("candidate_digest",)},
            }
            for table, expected in expected_indexes.items():
                actual: set[tuple[str, ...]] = set()
                for index in connection.execute(f"PRAGMA index_list({table})"):
                    if index[3] not in {"u", "pk"}:
                        raise LedgerError(f"unexpected custom index in ledger table: {table}")
                    actual.add(tuple(row[2] for row in connection.execute(f"PRAGMA index_info('{index[1]}')")))
                if actual != expected:
                    raise LedgerError(f"existing ledger index schema mismatch: {table}")
            foreign = {(row[3], row[4], row[2], row[5], row[6], row[7]) for row in connection.execute("PRAGMA foreign_key_list(promotion_state)")}
            if foreign != {("updated_sequence", "sequence", "ledger_entries", "NO ACTION", "NO ACTION", "NONE"), ("plan_sequence", "sequence", "ledger_entries", "NO ACTION", "NO ACTION", "NONE")}:
                raise LedgerError("existing ledger foreign-key schema mismatch")
            for table, expected_sql in EXPECTED_TABLE_SQL.items():
                sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0]
                if _normalize_schema_sql(sql) != expected_sql:
                    raise LedgerError(f"existing ledger DDL fingerprint mismatch: {table}")
        except sqlite3.Error as exc:
            raise LedgerError("existing SQLite file is not a valid Shipcheck ledger", detail=type(exc).__name__) from exc
        finally:
            if connection is not None:
                connection.close()

    def _connect(self) -> sqlite3.Connection:
        _check_no_symlink_components(self.path)
        for candidate in (self.path, self.anchor_path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            if candidate.exists():
                self._check_private_file(candidate)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            if os.name == "posix":
                for candidate in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
                    if candidate.exists():
                        os.chmod(candidate, 0o600)
            return connection
        except Exception as exc:
            if connection is not None:
                connection.close()
            if isinstance(exc, sqlite3.Error):
                raise LedgerError("SQLite ledger cannot be opened", detail=type(exc).__name__) from exc
            raise

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_entries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key_digest TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    entry_type TEXT NOT NULL,
                    payload_json BLOB NOT NULL,
                    payload_digest TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ledger_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS promotion_state (
                    candidate_digest TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    decision_digest TEXT NOT NULL,
                    plan_sequence INTEGER NOT NULL,
                    updated_sequence INTEGER NOT NULL,
                    FOREIGN KEY(plan_sequence) REFERENCES ledger_entries(sequence),
                    FOREIGN KEY(updated_sequence) REFERENCES ledger_entries(sequence)
                );
                INSERT OR IGNORE INTO ledger_meta(key,value) VALUES('schema_id','shipcheck-ledger');
                INSERT OR IGNORE INTO ledger_meta(key,value) VALUES('schema_version','1');
                PRAGMA user_version=1;
                """
            )
        if os.name == "posix":
            os.chmod(self.path, 0o600)
        self.recover_anchor()

    @staticmethod
    def _entry_hash(body: Mapping[str, Any]) -> str:
        return sha256_hex(canonical_json(body))

    def append(self, entry_type: str, payload: Mapping[str, Any], *, idempotency_key: str, request: Mapping[str, Any] | None = None) -> LedgerReceipt:
        if entry_type in {"EVALUATED_DECISION", "PROMOTION_PLANNED", "PROMOTION_APPLIED", "PROMOTION_VERIFIED", "PROMOTION_ROLLED_BACK"}:
            raise ValidationError("reserved ledger entry_type must be produced by its governed operation")
        return self._append(entry_type, payload, idempotency_key=idempotency_key, request=request)

    def _append(self, entry_type: str, payload: Mapping[str, Any], *, idempotency_key: str, request: Mapping[str, Any] | None = None, context_idempotent: bool = False) -> LedgerReceipt:
        if not isinstance(entry_type, str) or not entry_type or len(entry_type) > 64:
            raise ValidationError("entry_type must be a non-empty string of at most 64 characters")
        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 128:
            raise ValidationError("idempotency_key must be 1 to 128 characters")
        idempotency_key_digest = object_digest({"idempotency_key": idempotency_key})
        payload_dict = dict(payload)
        if redact(payload_dict) != payload_dict:
            raise SecurityError("secret-shaped values are forbidden in ledger payloads")
        payload_bytes = canonical_json(payload_dict)
        if len(payload_bytes) > 1_048_576:
            raise ValidationError("ledger payload exceeds 1 MiB")
        payload_digest = sha256_hex(payload_bytes)
        context = dict(request or {})
        request_material = {"entry_type": entry_type, "context": context}
        if not context_idempotent:
            request_material["payload_digest"] = payload_digest
        request_digest = object_digest(request_material)
        created_at = format_time(dt.datetime.now(dt.timezone.utc))
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_anchor_matches_tail(connection)
            existing = connection.execute(
                "SELECT * FROM ledger_entries WHERE idempotency_key_digest=?", (idempotency_key_digest,)
            ).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest or existing["entry_type"] != entry_type or (not context_idempotent and existing["payload_digest"] != payload_digest):
                    connection.rollback()
                    raise ConflictError("idempotency key was already used for another request")
                receipt = self._row_receipt(existing)
                connection.commit()
                # A previous identical call may have committed the database row
                # but crashed before advancing the separately stored tail anchor.
                # Idempotent replay is the recovery point for that bounded window.
                self._sync_anchor_to_tail()
                return receipt
            tail = connection.execute("SELECT sequence, entry_hash FROM ledger_entries ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_hash = tail["entry_hash"] if tail else ZERO_HASH
            sequence = (int(tail["sequence"]) if tail else 0) + 1
            body = {
                "sequence": sequence,
                "idempotency_key_digest": idempotency_key_digest,
                "request_digest": request_digest,
                "entry_type": entry_type,
                "payload_digest": payload_digest,
                "previous_hash": previous_hash,
                "created_at": created_at,
            }
            entry_hash = self._entry_hash(body)
            cursor = connection.execute(
                "INSERT INTO ledger_entries(sequence,idempotency_key_digest,request_digest,entry_type,payload_json,payload_digest,previous_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (sequence, idempotency_key_digest, request_digest, entry_type, payload_bytes, payload_digest, previous_hash, entry_hash, created_at),
            )
            if cursor.rowcount != 1:
                raise LedgerError("ledger append did not insert exactly one row")
            connection.commit()
            receipt = LedgerReceipt(sequence, entry_hash, previous_hash, idempotency_key_digest, request_digest, entry_type, payload_digest, created_at)
            self._sync_anchor_to_tail()
            return receipt
        except sqlite3.Error as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise LedgerError("SQLite ledger append failed", detail=type(exc).__name__) from exc
        finally:
            connection.close()

    def append_decision(self, decision: Decision, *, idempotency_key: str) -> LedgerReceipt:
        """Import an external decision for audit only; imported entries are never promotable."""
        request = {
            "operation": "import_decision",
            "decision_digest": decision.digest,
            "candidate_digest": decision.candidate_digest,
            "policy_digest": decision.policy_digest,
        }
        return self._append("IMPORTED_DECISION", decision.to_dict(), idempotency_key=idempotency_key, request=request)

    def evaluate_and_record(
        self,
        evidence: ReleaseEvidence,
        policy: ReleasePolicy,
        trust_store: TrustStore,
        *,
        expected_policy_digest: str,
        expected_trust_digest: str,
        idempotency_key: str,
        waivers: tuple[Waiver, ...] = (),
        now: dt.datetime | None = None,
    ) -> tuple[Decision, LedgerReceipt]:
        if policy.digest != expected_policy_digest:
            raise ValidationError("policy digest does not match protected expectation")
        if trust_store.digest != expected_trust_digest:
            raise ValidationError("trust store digest does not match protected expectation")
        from .engine import DecisionEngine

        engine = DecisionEngine(trust_store=trust_store, clock=(lambda: now) if now is not None else None)
        decision = engine.evaluate(evidence, policy, waivers=waivers)
        waiver_digests = [object_digest(item.to_dict()) for item in waivers]
        envelope = {
            "schema_version": "shipcheck/assessment-v1",
            "engine_version": "0.1.0",
            "candidate_digest": evidence.candidate.digest,
            "evidence_digest": evidence.digest,
            "policy_digest": policy.digest,
            "trust_digest": trust_store.digest,
            "assurance_profile": policy.assurance_profile,
            "source_kinds": sorted({item.source_kind for item in evidence.observations}),
            "policy_summary": _policy_summary(policy),
            "waiver_digests": waiver_digests,
            "decision": decision.to_dict(),
        }
        request = {
            "operation": "evaluate_and_record",
            "candidate_digest": evidence.candidate.digest,
            "evidence_digest": evidence.digest,
            "policy_digest": policy.digest,
            "trust_digest": trust_store.digest,
            "assurance_profile": policy.assurance_profile,
            "waiver_digests": waiver_digests,
            "engine_version": "0.1.0",
        }
        receipt = self._append("EVALUATED_DECISION", envelope, idempotency_key=idempotency_key, request=request, context_idempotent=True)
        if receipt.payload_digest != object_digest(envelope):
            stored = self.get_entry(receipt.sequence)["payload"]
            if not isinstance(stored, dict) or not isinstance(stored.get("decision"), dict):
                raise LedgerError("idempotent assessment receipt points to an invalid envelope")
            decision = Decision.from_dict(stored["decision"])
        return decision, receipt

    def plan_promotion(self, decision: Decision, *, idempotency_key: str) -> LedgerReceipt:
        if not decision.production_ready:
            raise ValidationError("only a PRODUCTION/READY decision can produce a local promotion plan")
        payload = {
            "decision_id": decision.decision_id,
            "decision_digest": decision.digest,
            "candidate_digest": decision.candidate_digest,
            "policy_digest": decision.policy_digest,
            "effect": "local-ledger-only",
            "state": "PLANNED",
        }
        return self._transition("PROMOTION_PLANNED", payload, idempotency_key=idempotency_key, expected_states=None, expected_token=None, target="PLANNED", decision_digest=decision.digest)

    def apply_promotion(self, *, candidate_digest: str, decision_digest: str, idempotency_key: str, expected_fencing_token: int) -> LedgerReceipt:
        payload = {
            "candidate_digest": candidate_digest,
            "decision_digest": decision_digest,
            "effect": "local-ledger-only",
            "state": "APPLIED",
            "expected_fencing_token": expected_fencing_token,
        }
        return self._transition("PROMOTION_APPLIED", payload, idempotency_key=idempotency_key, expected_states=("PLANNED",), expected_token=expected_fencing_token, target="APPLIED", decision_digest=decision_digest)

    def verify_promotion(self, *, candidate_digest: str, decision_digest: str, idempotency_key: str, expected_fencing_token: int) -> LedgerReceipt:
        payload = {
            "candidate_digest": candidate_digest,
            "decision_digest": decision_digest,
            "effect": "local-ledger-only",
            "state": "VERIFIED",
            "expected_fencing_token": expected_fencing_token,
        }
        return self._transition("PROMOTION_VERIFIED", payload, idempotency_key=idempotency_key, expected_states=("APPLIED",), expected_token=expected_fencing_token, target="VERIFIED", decision_digest=decision_digest)

    def rollback_promotion(self, *, candidate_digest: str, reason: str, idempotency_key: str, expected_fencing_token: int) -> LedgerReceipt:
        if not reason or len(reason) > 2_000:
            raise ValidationError("rollback reason must be 1 to 2,000 characters")
        payload = {
            "candidate_digest": candidate_digest,
            "reason": reason,
            "effect": "local-ledger-only",
            "state": "ROLLED_BACK",
            "expected_fencing_token": expected_fencing_token,
        }
        state = self.promotion_state(candidate_digest)
        decision_digest = str(state["decision_digest"]) if state else ""
        return self._transition("PROMOTION_ROLLED_BACK", payload, idempotency_key=idempotency_key, expected_states=("APPLIED", "VERIFIED"), expected_token=expected_fencing_token, target="ROLLED_BACK", decision_digest=decision_digest)

    def _transition(self, entry_type: str, payload: Mapping[str, Any], *, idempotency_key: str, expected_states: tuple[str, ...] | None, expected_token: int | None, target: str, decision_digest: str) -> LedgerReceipt:
        candidate_digest = str(payload["candidate_digest"])
        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 128:
            raise ValidationError("idempotency_key must be 1 to 128 characters")
        idempotency_key_digest = object_digest({"idempotency_key": idempotency_key})
        if len(candidate_digest) != 64 or any(character not in "0123456789abcdef" for character in candidate_digest):
            raise ValidationError("candidate_digest must be a lowercase SHA-256 digest")
        if len(decision_digest) != 64 or any(character not in "0123456789abcdef" for character in decision_digest):
            raise ValidationError("decision_digest must be a lowercase SHA-256 digest")
        if expected_token is not None and (type(expected_token) is not int or expected_token < 1):
            raise ValidationError("expected_fencing_token must be a positive integer")
        if redact(dict(payload)) != dict(payload):
            raise SecurityError("secret-shaped values are forbidden in ledger transitions")
        payload_bytes = canonical_json(dict(payload))
        if len(payload_bytes) > 1_048_576:
            raise ValidationError("ledger transition payload exceeds 1 MiB")
        payload_digest = sha256_hex(payload_bytes)
        request_digest = object_digest({"entry_type": entry_type, "payload_digest": payload_digest, "context": {}})
        created_at = format_time(dt.datetime.now(dt.timezone.utc))
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_anchor_matches_tail(connection)
            existing = connection.execute("SELECT * FROM ledger_entries WHERE idempotency_key_digest=?", (idempotency_key_digest,)).fetchone()
            if existing is not None:
                if existing["request_digest"] != request_digest or existing["entry_type"] != entry_type or existing["payload_digest"] != payload_digest:
                    connection.rollback()
                    raise ConflictError("idempotency key was already used for another transition")
                connection.commit()
                receipt = self._row_receipt(existing)
                # See _append(): exact replay also repairs a valid historical
                # anchor left behind by a post-commit interruption.
                self._sync_anchor_to_tail()
                return receipt
            state = connection.execute("SELECT * FROM promotion_state WHERE candidate_digest=?", (candidate_digest,)).fetchone()
            if expected_states is None:
                if state is not None:
                    raise ConflictError("candidate already has a promotion state")
                registered = None
                for candidate_row in connection.execute("SELECT sequence,payload_json FROM ledger_entries WHERE entry_type='EVALUATED_DECISION' ORDER BY sequence DESC").fetchall():
                    candidate_payload = loads_strict(bytes(candidate_row["payload_json"]))
                    if isinstance(candidate_payload, dict) and isinstance(candidate_payload.get("decision"), dict):
                        try:
                            candidate_decision = Decision.from_dict(candidate_payload["decision"])
                        except ValidationError:
                            continue
                        if candidate_decision.digest == decision_digest:
                            registered = candidate_row
                            break
                if registered is None:
                    raise ConflictError("promotion decision must be recorded in this ledger first")
                registered_envelope = loads_strict(bytes(registered["payload_json"]))
                registered_payload = registered_envelope.get("decision") if isinstance(registered_envelope, dict) else None
                try:
                    registered_decision = Decision.from_dict(registered_payload) if isinstance(registered_payload, dict) else None
                except ValidationError:
                    registered_decision = None
                if registered_decision is None or not registered_decision.production_ready or registered_decision.candidate_digest != candidate_digest:
                    raise ConflictError("recorded promotion decision is not READY for this candidate")
                next_token = 1
                plan_sequence = None
            else:
                if state is None or state["state"] not in expected_states or int(state["fencing_token"]) != expected_token:
                    raise ConflictError("promotion state or fencing token changed")
                if state["decision_digest"] != decision_digest:
                    raise ConflictError("promotion decision digest does not match the plan")
                next_token = int(expected_token) + 1
                plan_sequence = int(state["plan_sequence"])
            tail = connection.execute("SELECT sequence,entry_hash FROM ledger_entries ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_hash = tail["entry_hash"] if tail else ZERO_HASH
            sequence = (int(tail["sequence"]) if tail else 0) + 1
            body = {"sequence": sequence, "idempotency_key_digest": idempotency_key_digest, "request_digest": request_digest, "entry_type": entry_type, "payload_digest": payload_digest, "previous_hash": previous_hash, "created_at": created_at}
            entry_hash = self._entry_hash(body)
            connection.execute(
                "INSERT INTO ledger_entries(sequence,idempotency_key_digest,request_digest,entry_type,payload_json,payload_digest,previous_hash,entry_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (sequence, idempotency_key_digest, request_digest, entry_type, payload_bytes, payload_digest, previous_hash, entry_hash, created_at),
            )
            if plan_sequence is None:
                plan_sequence = sequence
            connection.execute(
                "INSERT INTO promotion_state(candidate_digest,state,fencing_token,decision_digest,plan_sequence,updated_sequence) VALUES(?,?,?,?,?,?) ON CONFLICT(candidate_digest) DO UPDATE SET state=excluded.state,fencing_token=excluded.fencing_token,decision_digest=excluded.decision_digest,plan_sequence=excluded.plan_sequence,updated_sequence=excluded.updated_sequence",
                (candidate_digest, target, next_token, decision_digest, plan_sequence, sequence),
            )
            connection.commit()
            receipt = LedgerReceipt(sequence, entry_hash, previous_hash, idempotency_key_digest, request_digest, entry_type, payload_digest, created_at)
            self._sync_anchor_to_tail()
            return receipt
        except (ConflictError, ValidationError):
            connection.rollback()
            raise
        except sqlite3.Error as exc:
            connection.rollback()
            raise LedgerError("SQLite promotion transition failed", detail=type(exc).__name__) from exc
        finally:
            connection.close()

    @staticmethod
    def _row_receipt(row: sqlite3.Row) -> LedgerReceipt:
        return LedgerReceipt(
            int(row["sequence"]), row["entry_hash"], row["previous_hash"], row["idempotency_key_digest"],
            row["request_digest"], row["entry_type"], row["payload_digest"], row["created_at"],
        )

    def get_entry(self, sequence: int) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM ledger_entries WHERE sequence=?", (sequence,)).fetchone()
        if row is None:
            raise NotFoundError(f"ledger sequence not found: {sequence}")
        payload = loads_strict(bytes(row["payload_json"]))
        return {"receipt": self._row_receipt(row).to_dict(), "payload": payload}

    def list_entries(self, *, limit: int = 100, after: int = 0) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 500 or type(after) is not int or after < 0:
            raise ValidationError("ledger pagination is invalid")
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT * FROM ledger_entries WHERE sequence>? ORDER BY sequence LIMIT ?", (after, limit)).fetchall()
        return [{"receipt": self._row_receipt(row).to_dict(), "payload": loads_strict(bytes(row["payload_json"]))} for row in rows]

    def list_summaries(self, *, limit: int = 100, after: int = 0) -> list[dict[str, Any]]:
        entries = self.list_entries(limit=limit, after=after)
        output: list[dict[str, Any]] = []
        for entry in entries:
            payload = entry["payload"] if isinstance(entry["payload"], dict) else {}
            if isinstance(payload.get("decision"), dict):
                payload = payload["decision"]
            summary = {key: payload[key] for key in ("outcome", "state", "release_id", "decision_id", "candidate_digest") if key in payload and isinstance(payload[key], (str, int, bool))}
            for key in ("assurance_profile", "production_ready"):
                if key in payload and isinstance(payload[key], (str, bool)):
                    summary[key] = payload[key]
            output.append({"receipt": entry["receipt"], "payload": summary})
        return output

    def list_recent_summaries(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValidationError("recent summary limit must be in [1, 100]")
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT * FROM ledger_entries ORDER BY sequence DESC LIMIT ?", (limit,)).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            payload = loads_strict(bytes(row["payload_json"]))
            if isinstance(payload, dict) and isinstance(payload.get("decision"), dict):
                payload = payload["decision"]
            if not isinstance(payload, dict):
                payload = {}
            summary = {key: payload[key] for key in ("outcome", "state", "release_id", "decision_id", "candidate_digest", "assurance_profile", "production_ready") if key in payload and isinstance(payload[key], (str, int, bool))}
            output.append({"receipt": self._row_receipt(row).to_dict(), "payload": summary})
        return output

    def promotion_state(self, candidate_digest: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM promotion_state WHERE candidate_digest=?", (candidate_digest,)).fetchone()
        return None if row is None else dict(row)

    def verify(self) -> dict[str, Any]:
        connection = self._connect()
        anchor_error: LedgerError | None = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign = connection.execute("PRAGMA foreign_key_check").fetchall()
            rows = connection.execute("SELECT * FROM ledger_entries ORDER BY sequence").fetchall()
            state_rows = connection.execute("SELECT * FROM promotion_state ORDER BY candidate_digest").fetchall()
            try:
                anchor = self._read_anchor()
            except LedgerError as exc:
                anchor_error = exc
                anchor = None
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        errors: list[str] = []
        if integrity != "ok":
            errors.append(f"sqlite integrity_check: {integrity}")
        if foreign:
            errors.append("sqlite foreign_key_check failed")
        previous = ZERO_HASH
        expected_sequence = 1
        derived_states: dict[str, dict[str, Any]] = {}
        evaluated_decisions: dict[str, dict[str, Any]] = {}
        for row in rows:
            raw_sequence = row["sequence"]
            if type(raw_sequence) is not int or raw_sequence < 1:
                errors.append("invalid sequence column type or value")
                sequence = expected_sequence
            else:
                sequence = raw_sequence
            text_values: dict[str, str] = {}
            for column, maximum in (("idempotency_key_digest", 64), ("request_digest", 64), ("entry_type", 64), ("payload_digest", 64), ("previous_hash", 64), ("entry_hash", 64), ("created_at", 64)):
                raw_value = row[column]
                if not isinstance(raw_value, str) or not raw_value or len(raw_value) > maximum:
                    errors.append(f"invalid {column} at {sequence}")
                    text_values[column] = ""
                else:
                    text_values[column] = raw_value
            if sequence != expected_sequence:
                errors.append(f"sequence gap at {expected_sequence}")
            if text_values["previous_hash"] != previous:
                errors.append(f"previous hash mismatch at {sequence}")
            try:
                raw_payload = row["payload_json"]
                if not isinstance(raw_payload, bytes):
                    raise TypeError("payload is not a BLOB")
                payload = raw_payload
                if sha256_hex(payload) != text_values["payload_digest"]:
                    errors.append(f"payload digest mismatch at {sequence}")
                parsed_payload = loads_strict(payload)
            except (ValidationError, TypeError):
                errors.append(f"invalid payload at {sequence}")
                parsed_payload = None
            body = {
                "sequence": sequence, "idempotency_key_digest": text_values["idempotency_key_digest"], "request_digest": text_values["request_digest"],
                "entry_type": text_values["entry_type"], "payload_digest": text_values["payload_digest"], "previous_hash": text_values["previous_hash"], "created_at": text_values["created_at"],
            }
            try:
                expected_hash = self._entry_hash(body)
            except (TypeError, ValueError, UnicodeError):
                expected_hash = ""
                errors.append(f"unhashable entry metadata at {sequence}")
            if text_values["entry_hash"] != expected_hash:
                errors.append(f"entry hash mismatch at {sequence}")
            previous = text_values["entry_hash"]
            expected_sequence += 1
            if text_values["entry_type"] == "EVALUATED_DECISION":
                if not isinstance(parsed_payload, dict) or set(parsed_payload) != ASSESSMENT_ENVELOPE_KEYS or parsed_payload.get("schema_version") != "shipcheck/assessment-v1" or parsed_payload.get("engine_version") != "0.1.0":
                    errors.append(f"invalid evaluated decision envelope at {sequence}")
                else:
                    try:
                        source_kinds = parsed_payload["source_kinds"]
                        if (
                            not isinstance(source_kinds, list)
                            or not source_kinds
                            or source_kinds != sorted(set(source_kinds))
                            or any(item not in {"synthetic", "supplied", "observed", "attested"} for item in source_kinds)
                        ):
                            raise ValidationError("assessment source kinds are invalid")
                        policy_summary = parsed_payload["policy_summary"]
                        if not isinstance(policy_summary, dict) or set(policy_summary) != POLICY_SUMMARY_KEYS:
                            raise ValidationError("assessment policy summary is invalid")
                        assessed = Decision.from_dict(parsed_payload["decision"])
                        if assessed.candidate_digest != parsed_payload["candidate_digest"] or assessed.evidence_digest != parsed_payload["evidence_digest"] or assessed.policy_digest != parsed_payload["policy_digest"] or assessed.assurance_profile != parsed_payload["assurance_profile"]:
                            raise ValidationError("assessment binding mismatch")
                        expected_request = {
                            "operation": "evaluate_and_record", "candidate_digest": parsed_payload["candidate_digest"],
                            "evidence_digest": parsed_payload["evidence_digest"], "policy_digest": parsed_payload["policy_digest"],
                            "trust_digest": parsed_payload["trust_digest"], "assurance_profile": parsed_payload["assurance_profile"], "waiver_digests": parsed_payload["waiver_digests"], "engine_version": "0.1.0",
                        }
                        expected_request_digest = object_digest({"entry_type": "EVALUATED_DECISION", "context": expected_request})
                        if expected_request_digest != text_values["request_digest"]:
                            raise ValidationError("assessment request digest mismatch")
                        evaluated_decisions[assessed.digest] = {"sequence": sequence, "decision": assessed}
                    except (ValidationError, TypeError, KeyError):
                        errors.append(f"evaluated decision binding failed at {sequence}")
            if text_values["entry_type"] in {"PROMOTION_PLANNED", "PROMOTION_APPLIED", "PROMOTION_VERIFIED", "PROMOTION_ROLLED_BACK"}:
                expected_transition_request = object_digest({"entry_type": text_values["entry_type"], "payload_digest": text_values["payload_digest"], "context": {}})
                if expected_transition_request != text_values["request_digest"]:
                    errors.append(f"promotion request digest mismatch at {sequence}")
                if not isinstance(parsed_payload, dict):
                    errors.append(f"invalid promotion payload at {sequence}")
                else:
                    candidate = parsed_payload.get("candidate_digest")
                    target = parsed_payload.get("state")
                    expected_target = {"PROMOTION_PLANNED": "PLANNED", "PROMOTION_APPLIED": "APPLIED", "PROMOTION_VERIFIED": "VERIFIED", "PROMOTION_ROLLED_BACK": "ROLLED_BACK"}[text_values["entry_type"]]
                    if not isinstance(candidate, str) or target not in {"PLANNED", "APPLIED", "VERIFIED", "ROLLED_BACK"}:
                        errors.append(f"invalid promotion transition at {sequence}")
                    elif target != expected_target:
                        errors.append(f"promotion entry type/state mismatch at {sequence}")
                    elif target == "PLANNED":
                        decision_digest = parsed_payload.get("decision_digest")
                        evaluated = evaluated_decisions.get(decision_digest) if isinstance(decision_digest, str) else None
                        if candidate in derived_states or evaluated is None or evaluated["sequence"] >= sequence or not evaluated["decision"].production_ready or evaluated["decision"].candidate_digest != candidate:
                            errors.append(f"invalid promotion plan at {sequence}")
                        else:
                            derived_states[candidate] = {"candidate_digest": candidate, "state": target, "fencing_token": 1, "decision_digest": decision_digest, "plan_sequence": sequence, "updated_sequence": sequence}
                    else:
                        current = derived_states.get(candidate)
                        allowed = {"APPLIED": {"PLANNED"}, "VERIFIED": {"APPLIED"}, "ROLLED_BACK": {"APPLIED", "VERIFIED"}}[target]
                        if current is None or current["state"] not in allowed or parsed_payload.get("expected_fencing_token") != current["fencing_token"]:
                            errors.append(f"invalid promotion transition order at {sequence}")
                        elif "decision_digest" in parsed_payload and parsed_payload["decision_digest"] != current["decision_digest"]:
                            errors.append(f"promotion decision mismatch at {sequence}")
                        else:
                            current["state"] = target
                            current["fencing_token"] += 1
                            current["updated_sequence"] = sequence
        actual_states = {row["candidate_digest"]: dict(row) for row in state_rows if isinstance(row["candidate_digest"], str)}
        if len(actual_states) != len(state_rows):
            errors.append("promotion_state contains an invalid candidate key")
        if actual_states != derived_states:
            errors.append("promotion_state does not match replayed ledger transitions")
        if anchor_error is not None:
            errors.append(f"tail anchor invalid: {anchor_error.message}")
        tail_sequence = int(rows[-1]["sequence"]) if rows else 0
        tail_hash = previous
        if anchor is None and tail_sequence > 0:
            errors.append("tail anchor missing for non-empty ledger")
        if anchor is not None:
            if anchor[0] > tail_sequence:
                errors.append("ledger truncation detected: anchor is ahead of database")
            elif anchor[0] == tail_sequence and anchor[1] != tail_hash:
                errors.append("tail anchor hash mismatch")
            elif anchor[0] < tail_sequence:
                anchored_hashes = {
                    row["sequence"]: row["entry_hash"]
                    for row in rows
                    if type(row["sequence"]) is int and isinstance(row["entry_hash"], str)
                }
                anchored_hash = ZERO_HASH if anchor[0] == 0 else anchored_hashes.get(anchor[0])
                if anchored_hash is None:
                    errors.append("historical anchor sequence is absent from ledger")
                elif anchor[1] != anchored_hash:
                    errors.append("historical anchor mismatch")
        return {"ok": not errors, "entries": tail_sequence, "tail_hash": tail_hash, "anchor": None if anchor is None else {"sequence": anchor[0], "entry_hash": anchor[1]}, "errors": errors, "integrity_scope": "local hash-chain plus local tail anchor; not external authenticity"}

    def _read_anchor(self) -> tuple[int, str] | None:
        if not self.anchor_path.exists():
            return None
        _check_no_symlink_components(self.anchor_path)
        try:
            raw = loads_strict(read_regular_file(self.anchor_path, max_bytes=1_024), max_bytes=1_024)
        except (OSError, ValidationError) as exc:
            raise LedgerError("tail anchor is unreadable or invalid") from exc
        if not isinstance(raw, dict) or set(raw) != {"schema_version", "sequence", "entry_hash"}:
            raise LedgerError("tail anchor shape is invalid")
        if raw["schema_version"] != "shipcheck/anchor-v1" or type(raw["sequence"]) is not int or raw["sequence"] < 0:
            raise LedgerError("tail anchor values are invalid")
        if not isinstance(raw["entry_hash"], str) or len(raw["entry_hash"]) != 64:
            raise LedgerError("tail anchor hash is invalid")
        return raw["sequence"], raw["entry_hash"]

    def _update_anchor(self, sequence: int, entry_hash: str, *, allow_create: bool = False) -> None:
        current = self._read_anchor()
        if current is None and not allow_create:
            raise LedgerError("tail anchor disappeared; refusing to recreate it")
        if current is not None and current[0] > sequence:
            return
        if current is not None and current[0] == sequence:
            if current[1] != entry_hash:
                raise LedgerError("tail anchor conflict at same sequence")
            return
        atomic_write(self.anchor_path, canonical_json({"schema_version": "shipcheck/anchor-v1", "sequence": sequence, "entry_hash": entry_hash}) + b"\n")

    def _sync_anchor_to_tail(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            # Fail closed on a missing/ahead/conflicting anchor.  A valid anchor
            # behind the database tail is the sole recoverable crash state.
            self._assert_anchor_matches_tail(connection)
            tail = connection.execute("SELECT sequence,entry_hash FROM ledger_entries ORDER BY sequence DESC LIMIT 1").fetchone()
            sequence = int(tail["sequence"]) if tail else 0
            entry_hash = str(tail["entry_hash"]) if tail else ZERO_HASH
            self._update_anchor(sequence, entry_hash)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _assert_anchor_matches_tail(self, connection: sqlite3.Connection) -> None:
        tail = connection.execute("SELECT sequence,entry_hash FROM ledger_entries ORDER BY sequence DESC LIMIT 1").fetchone()
        sequence = int(tail["sequence"]) if tail else 0
        entry_hash = str(tail["entry_hash"]) if tail else ZERO_HASH
        anchor = self._read_anchor()
        if anchor is None:
            raise LedgerError("tail anchor is missing; mutation is fail-closed")
        if anchor[0] > sequence:
            raise LedgerError("tail anchor is ahead of database; mutation is fail-closed")
        if anchor[0] == sequence:
            expected_anchor_hash = entry_hash
        elif anchor[0] == 0:
            expected_anchor_hash = ZERO_HASH
        else:
            row = connection.execute("SELECT entry_hash FROM ledger_entries WHERE sequence=?", (anchor[0],)).fetchone()
            expected_anchor_hash = str(row["entry_hash"]) if row else ""
        if anchor[1] != expected_anchor_hash:
            raise LedgerError("tail anchor does not match database history; mutation is fail-closed")

    def recover_anchor(self) -> None:
        result = self.verify() if self.path.exists() else {"ok": True, "entries": 0, "tail_hash": ZERO_HASH, "anchor": None, "errors": []}
        if not result["ok"]:
            raise LedgerError("ledger integrity verification failed", detail="; ".join(result["errors"]))
        anchor = result["anchor"]
        if anchor is None and int(result["entries"]) > 0:
            raise LedgerError("tail anchor is missing for a non-empty ledger")
        if anchor is None or int(anchor["sequence"]) < int(result["entries"]):
            self._update_anchor(
                int(result["entries"]),
                str(result["tail_hash"]),
                allow_create=anchor is None and int(result["entries"]) == 0,
            )
