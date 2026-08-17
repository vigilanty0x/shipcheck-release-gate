"""Portable local-consistency receipts.

Receipts deliberately make no authorship or public-authenticity claim. They
contain the exact ledger assessment envelope so an offline verifier can bind
the parsed decision to the ledger payload digest and replay the chain from its
genesis. Anyone can construct a new self-consistent hash chain; callers need
an independently protected checkpoint to establish authenticity.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .canonical import canonical_json, object_digest, sha256_hex
from .errors import LedgerError, ValidationError
from .ledger import DecisionLedger, ZERO_HASH
from .limits import loads_strict
from .models import Decision, parse_time

RECEIPT_SCHEMA = "shipcheck/receipt-v1"
VERIFICATION_SCHEMA = "shipcheck/receipt-verification-v1"
EXPLANATION_SCHEMA = "shipcheck/explanation-v1"
MAX_RECEIPT_BYTES = 2_097_152
MAX_CHAIN_ENTRIES = 500
INTEGRITY_SCOPE = (
    "internal_consistency_only: local SHA-256 hash-chain and local tail anchor; "
    "no signature, external checkpoint, transparency log, authorship, or non-repudiation"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ASSESSMENT_KEYS = {
    "schema_version", "engine_version", "candidate_digest", "evidence_digest",
    "policy_digest", "trust_digest", "assurance_profile", "source_kinds",
    "policy_summary", "waiver_digests", "decision",
}
ENTRY_KEYS = {
    "sequence", "entry_hash", "previous_hash", "idempotency_key_digest",
    "request_digest", "entry_type", "payload_digest", "created_at",
}
BINDING_KEYS = {
    "candidate_digest", "evidence_digest", "policy_digest", "trust_digest",
    "waiver_digests", "assurance_profile", "source_kinds", "policy_summary_digest",
}
POLICY_SUMMARY_KEYS = {
    "required_checks", "required_matrix", "required_test_suites", "required_artifacts",
    "expected_environment", "expected_version", "max_evidence_age_hours", "max_diff_risk",
    "minimum_test_count", "minimum_flake_samples", "maximum_flake_rate",
    "minimum_reproducible_builds", "minimum_reproducible_authorities",
    "require_artifact", "require_sbom", "require_changelog", "require_rollback",
    "require_deploy_observation", "rollback_max_age_hours", "maximum_rollback_minutes",
}


def _bounded_object(raw: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    """Normalize every input, including Python mappings, through strict JSON."""

    if isinstance(raw, (bytes, str)):
        value = loads_strict(raw, max_bytes=MAX_RECEIPT_BYTES)
    elif isinstance(raw, Mapping):
        try:
            encoded = canonical_json(dict(raw))
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise ValidationError("receipt mapping is not bounded canonical JSON") from exc
        value = loads_strict(encoded, max_bytes=MAX_RECEIPT_BYTES)
    else:
        raise ValidationError("receipt must be a JSON object")
    if not isinstance(value, dict):
        raise ValidationError("receipt must be a JSON object")
    return value


def _require_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _assessment(envelope: Any) -> tuple[dict[str, Any], Decision]:
    if not isinstance(envelope, dict) or set(envelope) != ASSESSMENT_KEYS:
        raise ValidationError("assessment envelope has unknown or missing fields")
    if envelope["schema_version"] != "shipcheck/assessment-v1" or envelope["engine_version"] != "0.1.0":
        raise ValidationError("unsupported assessment envelope version")
    for name in ("candidate_digest", "evidence_digest", "policy_digest", "trust_digest"):
        _require_sha(envelope[name], f"assessment.{name}")
    if envelope["assurance_profile"] not in {"LAB", "PRODUCTION"}:
        raise ValidationError("assessment.assurance_profile is invalid")
    source_kinds = envelope["source_kinds"]
    if (
        not isinstance(source_kinds, list)
        or not source_kinds
        or source_kinds != sorted(set(source_kinds))
        or any(item not in {"synthetic", "supplied", "observed", "attested"} for item in source_kinds)
    ):
        raise ValidationError("assessment.source_kinds is invalid")
    summary = envelope["policy_summary"]
    if not isinstance(summary, dict) or set(summary) != POLICY_SUMMARY_KEYS:
        raise ValidationError("assessment.policy_summary has unknown or missing fields")
    for name in ("required_checks", "required_matrix", "required_test_suites", "required_artifacts"):
        values = summary[name]
        if not isinstance(values, list) or not values or len(values) > 100 or any(not isinstance(item, str) or not item or len(item) > 256 for item in values) or len(values) != len(set(values)):
            raise ValidationError(f"assessment.policy_summary.{name} is invalid")
    for name in ("expected_environment", "expected_version"):
        if not isinstance(summary[name], str) or not summary[name] or len(summary[name]) > 256:
            raise ValidationError(f"assessment.policy_summary.{name} is invalid")
    for name in (
        "max_evidence_age_hours", "max_diff_risk", "minimum_test_count", "minimum_flake_samples",
        "minimum_reproducible_builds", "minimum_reproducible_authorities", "rollback_max_age_hours",
        "maximum_rollback_minutes",
    ):
        if type(summary[name]) is not int or summary[name] < 0 or summary[name] > 100_000_000:
            raise ValidationError(f"assessment.policy_summary.{name} is invalid")
    rate = summary["maximum_flake_rate"]
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0 <= rate <= 1:
        raise ValidationError("assessment.policy_summary.maximum_flake_rate is invalid")
    for name in ("require_artifact", "require_sbom", "require_changelog", "require_rollback", "require_deploy_observation"):
        if type(summary[name]) is not bool:
            raise ValidationError(f"assessment.policy_summary.{name} is invalid")
    waivers = envelope["waiver_digests"]
    if not isinstance(waivers, list) or len(waivers) > 100:
        raise ValidationError("assessment.waiver_digests exceeds bounds")
    for index, digest in enumerate(waivers):
        _require_sha(digest, f"assessment.waiver_digests[{index}]")
    if len(waivers) != len(set(waivers)):
        raise ValidationError("assessment.waiver_digests must be unique")
    decision = Decision.from_dict(envelope["decision"])
    if (
        decision.candidate_digest != envelope["candidate_digest"]
        or decision.evidence_digest != envelope["evidence_digest"]
        or decision.policy_digest != envelope["policy_digest"]
        or decision.assurance_profile != envelope["assurance_profile"]
    ):
        raise ValidationError("decision and assessment envelope bindings disagree")
    return envelope, decision


def _entry_hash(receipt: Mapping[str, Any]) -> str:
    body = {
        "sequence": receipt["sequence"],
        "idempotency_key_digest": receipt["idempotency_key_digest"],
        "request_digest": receipt["request_digest"],
        "entry_type": receipt["entry_type"],
        "payload_digest": receipt["payload_digest"],
        "previous_hash": receipt["previous_hash"],
        "created_at": receipt["created_at"],
    }
    return sha256_hex(canonical_json(body))


def _validate_entry(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != ENTRY_KEYS:
        raise ValidationError(f"ledger chain item {index} fields are invalid")
    if type(item["sequence"]) is not int or not 1 <= item["sequence"] <= 2**63 - 1:
        raise ValidationError(f"ledger chain item {index} sequence is invalid")
    for name in ("entry_hash", "previous_hash", "idempotency_key_digest", "request_digest", "payload_digest"):
        _require_sha(item[name], f"ledger.chain[{index}].{name}")
    entry_type = item["entry_type"]
    if not isinstance(entry_type, str) or not entry_type or len(entry_type) > 64:
        raise ValidationError(f"ledger chain item {index} entry_type is invalid")
    parse_time(item["created_at"], f"ledger.chain[{index}].created_at")
    return item


def export_receipt(ledger: DecisionLedger, sequence: int) -> dict[str, Any]:
    if type(sequence) is not int or sequence < 1:
        raise ValidationError("receipt sequence must be a positive integer")
    integrity = ledger.verify()
    if not integrity["ok"]:
        raise LedgerError("cannot export from an invalid ledger", detail="; ".join(integrity["errors"]))
    entry = ledger.get_entry(sequence)
    if entry["receipt"]["entry_type"] != "EVALUATED_DECISION":
        raise ValidationError("receipt export requires an EVALUATED_DECISION sequence")
    envelope, decision = _assessment(entry["payload"])
    assessment_payload_digest = object_digest(envelope)
    if assessment_payload_digest != entry["receipt"]["payload_digest"]:
        raise LedgerError("assessment envelope does not match ledger payload digest")

    # A portable chain is self-contained only when replay starts at genesis.
    chain_entries = ledger.list_entries(after=0, limit=MAX_CHAIN_ENTRIES)
    if not chain_entries or chain_entries[0]["receipt"]["sequence"] != 1:
        raise LedgerError("receipt chain genesis is missing")
    if chain_entries[-1]["receipt"]["sequence"] != integrity["entries"]:
        raise LedgerError(f"receipt chain exceeds portable limit of {MAX_CHAIN_ENTRIES} entries")
    chain = [item["receipt"] for item in chain_entries]
    if entry["receipt"] not in chain:
        raise LedgerError("evaluated decision entry is missing from exported chain")

    bindings = {
        "candidate_digest": envelope["candidate_digest"],
        "evidence_digest": envelope["evidence_digest"],
        "policy_digest": envelope["policy_digest"],
        "trust_digest": envelope["trust_digest"],
        "waiver_digests": list(envelope["waiver_digests"]),
        "assurance_profile": envelope["assurance_profile"],
        "source_kinds": list(envelope["source_kinds"]),
        "policy_summary_digest": object_digest(envelope["policy_summary"]),
    }
    body: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "assessment_envelope": envelope,
        "assessment_payload_digest": assessment_payload_digest,
        "decision_digest": decision.digest,
        "bindings": bindings,
        "ledger": {"entry": entry["receipt"], "chain": chain, "anchor": integrity["anchor"]},
        "integrity_scope": INTEGRITY_SCOPE,
        "authenticity_established": False,
    }
    body["receipt_digest"] = object_digest(body)
    if len(canonical_json(body)) > MAX_RECEIPT_BYTES:
        raise LedgerError("portable receipt exceeds the 2 MiB public limit")
    return body


def render_receipt(ledger: DecisionLedger, sequence: int) -> bytes:
    return canonical_json(export_receipt(ledger, sequence)) + b"\n"


def verify_receipt(raw: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    value: dict[str, Any] = {}
    decision: Decision | None = None
    try:
        value = _bounded_object(raw)
        required = {
            "schema_version", "assessment_envelope", "assessment_payload_digest",
            "decision_digest", "bindings", "ledger", "integrity_scope",
            "authenticity_established", "receipt_digest",
        }
        if set(value) != required:
            raise ValidationError("receipt has unknown or missing top-level fields")
        if value["schema_version"] != RECEIPT_SCHEMA:
            raise ValidationError("unsupported receipt schema_version")
        if value["integrity_scope"] != INTEGRITY_SCOPE:
            raise ValidationError("receipt integrity_scope is invalid")
        if value["authenticity_established"] is not False:
            raise ValidationError("portable local receipt cannot establish authenticity")

        claimed_receipt_digest = _require_sha(value["receipt_digest"], "receipt.receipt_digest")
        unsigned = dict(value)
        unsigned.pop("receipt_digest")
        if claimed_receipt_digest != object_digest(unsigned):
            errors.append("receipt digest mismatch")

        envelope, decision = _assessment(value["assessment_envelope"])
        assessment_digest = object_digest(envelope)
        if _require_sha(value["assessment_payload_digest"], "receipt.assessment_payload_digest") != assessment_digest:
            errors.append("assessment payload digest mismatch")
        if _require_sha(value["decision_digest"], "receipt.decision_digest") != decision.digest:
            errors.append("decision digest mismatch")

        bindings = value["bindings"]
        if not isinstance(bindings, dict) or set(bindings) != BINDING_KEYS:
            raise ValidationError("receipt bindings have unknown or missing fields")
        expected_bindings = {
            "candidate_digest": envelope["candidate_digest"],
            "evidence_digest": envelope["evidence_digest"],
            "policy_digest": envelope["policy_digest"],
            "trust_digest": envelope["trust_digest"],
            "waiver_digests": list(envelope["waiver_digests"]),
            "assurance_profile": envelope["assurance_profile"],
            "source_kinds": list(envelope["source_kinds"]),
            "policy_summary_digest": object_digest(envelope["policy_summary"]),
        }
        if bindings != expected_bindings:
            errors.append("receipt bindings do not match assessment envelope")

        ledger = value["ledger"]
        if not isinstance(ledger, dict) or set(ledger) != {"entry", "chain", "anchor"}:
            raise ValidationError("receipt ledger section has unknown or missing fields")
        chain = ledger["chain"]
        if not isinstance(chain, list) or not 1 <= len(chain) <= MAX_CHAIN_ENTRIES:
            raise ValidationError("ledger receipt chain is empty or exceeds bounds")
        validated_chain = [_validate_entry(item, index) for index, item in enumerate(chain)]
        entry = _validate_entry(ledger["entry"], -1)
        anchor = ledger["anchor"]
        if not isinstance(anchor, dict) or set(anchor) != {"sequence", "entry_hash"}:
            raise ValidationError("ledger anchor fields are invalid")
        if type(anchor["sequence"]) is not int or anchor["sequence"] < 1:
            raise ValidationError("ledger anchor sequence is invalid")
        _require_sha(anchor["entry_hash"], "ledger.anchor.entry_hash")

        if validated_chain[0]["sequence"] != 1 or validated_chain[0]["previous_hash"] != ZERO_HASH:
            errors.append("ledger chain does not start at genesis")
        previous_sequence = 0
        previous_hash = ZERO_HASH
        for index, item in enumerate(validated_chain):
            if item["sequence"] != previous_sequence + 1:
                errors.append(f"ledger chain sequence gap at item {index}")
            if item["previous_hash"] != previous_hash:
                errors.append(f"ledger chain previous hash mismatch at item {index}")
            if item["entry_hash"] != _entry_hash(item):
                errors.append(f"ledger chain entry hash mismatch at item {index}")
            previous_sequence = item["sequence"]
            previous_hash = item["entry_hash"]
        matches = [item for item in validated_chain if item["sequence"] == entry["sequence"]]
        if len(matches) != 1 or matches[0] != entry:
            errors.append("evaluated decision entry is absent or differs from chain")
        if entry["entry_type"] != "EVALUATED_DECISION":
            errors.append("receipt ledger entry is not an evaluated decision")
        if entry["payload_digest"] != assessment_digest:
            errors.append("ledger entry does not bind exact assessment envelope")
        expected_request = {
            "operation": "evaluate_and_record",
            "candidate_digest": envelope["candidate_digest"],
            "evidence_digest": envelope["evidence_digest"],
            "policy_digest": envelope["policy_digest"],
            "trust_digest": envelope["trust_digest"],
            "assurance_profile": envelope["assurance_profile"],
            "waiver_digests": envelope["waiver_digests"],
            "engine_version": envelope["engine_version"],
        }
        expected_request_digest = object_digest({"entry_type": "EVALUATED_DECISION", "context": expected_request})
        if entry["request_digest"] != expected_request_digest:
            errors.append("ledger entry request digest does not bind assessment request")
        if anchor["sequence"] != previous_sequence or anchor["entry_hash"] != previous_hash:
            errors.append("ledger chain does not terminate at exported anchor")
    except (ValidationError, TypeError, ValueError, KeyError, UnicodeError, RecursionError) as exc:
        errors.append(str(exc))

    return {
        "schema_version": VERIFICATION_SCHEMA,
        "internally_consistent": not errors,
        "authenticity_established": False,
        "integrity_scope": INTEGRITY_SCOPE,
        "errors": errors,
        "outcome": decision.outcome if decision is not None else None,
        "assurance_profile": decision.assurance_profile if decision is not None else None,
        "production_ready": decision.production_ready if decision is not None else False,
        "receipt_digest": value.get("receipt_digest") if isinstance(value.get("receipt_digest"), str) else None,
    }


def explain_receipt(raw: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    verification = verify_receipt(raw)
    decision: Decision | None = None
    if verification["internally_consistent"]:
        try:
            value = _bounded_object(raw)
            _, decision = _assessment(value["assessment_envelope"])
        except (ValidationError, TypeError, ValueError, KeyError, UnicodeError, RecursionError):
            decision = None
    non_pass = [] if decision is None else [gate.to_dict() for gate in decision.gates if gate.status != "pass"]
    return {
        "schema_version": EXPLANATION_SCHEMA,
        "internally_consistent": verification["internally_consistent"],
        "authenticity_established": False,
        "integrity_scope": INTEGRITY_SCOPE,
        "verification_errors": verification["errors"],
        "outcome": decision.outcome if decision is not None else None,
        "assurance_profile": decision.assurance_profile if decision is not None else None,
        "production_ready": decision.production_ready if decision is not None else False,
        "non_pass_gates": non_pass,
    }
