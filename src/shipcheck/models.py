"""Versioned public contracts for release evidence and decisions."""

from __future__ import annotations

import dataclasses
import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .canonical import object_digest
from .errors import ValidationError
from .redaction import redact

SCHEMA_VERSION = "shipcheck/v1"
DECISIONS = {"READY", "BLOCKED", "UNKNOWN"}
STATUSES = {"pass", "fail", "unknown", "pending", "cancelled", "skipped", "warn"}
REQUIRED_GATE_NAMES = {
    "subject_binding", "freshness", "authenticity", "diff_risk", "ci_matrix", "ci_cache", "flakiness",
    "tests", "artifact", "reproducibility", "sbom", "changelog", "provenance", "rollback", "deploy_truth",
}
OBSERVATION_KINDS = {
    "artifact",
    "build_manifest",
    "changelog",
    "ci_run",
    "deploy_observation",
    "diff",
    "provenance",
    "sbom",
    "test_summary",
    "rollback_drill",
}
TRUST_LEVELS = {"self_declared", "verified_attestation"}
HEX_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")


class _FrozenDict(dict):
    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("Shipcheck contract values are immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable


class _FrozenList(list):
    def _immutable(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("Shipcheck contract values are immutable")

    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = __iadd__ = __imul__ = _immutable


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze_json(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


def _object(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be an object")
    return value


def _string(value: Any, name: str, *, limit: int = 256, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ValidationError(f"{name} must be a non-empty string of at most {limit} characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ValidationError(f"{name} has an invalid format")
    return value


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ValidationError(f"{name} must be a boolean")
    return value


def _int(value: Any, name: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _number(value: Any, name: str, *, minimum: float = 0, maximum: float = 1_000_000) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{name} must be numeric")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValidationError(f"{name} is outside the supported numeric range") from exc
    if not minimum <= result <= maximum:
        raise ValidationError(f"{name} must be in [{minimum}, {maximum}]")
    return result


def _keys(value: Mapping[str, Any], name: str, *, required: set[str], optional: set[str] = frozenset()) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ValidationError(f"{name} missing keys: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"{name} unknown keys: {', '.join(sorted(unknown))}")


def parse_time(value: Any, name: str) -> dt.datetime:
    text = _string(value, name, limit=64)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{name} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Candidate:
    repository: str
    base_commit: str
    head_commit: str
    tree_digest: str
    ref: str

    def __post_init__(self) -> None:
        repository = _string(self.repository, "candidate.repository", limit=256)
        if any(character.isspace() for character in repository) or repository.startswith(("/", ".")):
            raise ValidationError("candidate.repository must be a stable repository identifier")
        _string(self.base_commit, "candidate.base_commit", pattern=HEX_RE)
        _string(self.head_commit, "candidate.head_commit", pattern=HEX_RE)
        _string(self.tree_digest, "candidate.tree_digest", pattern=SHA256_RE)
        _string(self.ref, "candidate.ref", limit=256)

    @classmethod
    def from_dict(cls, raw: Any) -> "Candidate":
        value = _object(raw, "candidate")
        _keys(value, "candidate", required={"repository", "base_commit", "head_commit", "tree_digest", "ref"})
        repository = _string(value["repository"], "candidate.repository", limit=256)
        if any(c.isspace() for c in repository) or repository.startswith(("/", ".")):
            raise ValidationError("candidate.repository must be a stable repository identifier")
        return cls(
            repository=repository,
            base_commit=_string(value["base_commit"], "candidate.base_commit", pattern=HEX_RE),
            head_commit=_string(value["head_commit"], "candidate.head_commit", pattern=HEX_RE),
            tree_digest=_string(value["tree_digest"], "candidate.tree_digest", pattern=SHA256_RE),
            ref=_string(value["ref"], "candidate.ref", limit=256),
        )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @property
    def digest(self) -> str:
        return object_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class Attestation:
    level: str
    authority: str | None = None
    key_id: str | None = None
    mac: str | None = None
    issuer: str | None = None
    workflow: str | None = None

    def __post_init__(self) -> None:
        if self.level not in TRUST_LEVELS:
            raise ValidationError(f"unsupported trust level: {self.level}")
        for name in ("authority", "key_id", "issuer", "workflow"):
            value = getattr(self, name)
            if value is not None:
                _string(value, f"trust.{name}", limit=256)
        if self.mac is not None:
            _string(self.mac, "trust.mac", pattern=SHA256_RE)
        if self.level == "verified_attestation" and not all((self.authority, self.key_id, self.mac)):
            raise ValidationError("verified_attestation requires authority, key_id, and mac")

    @classmethod
    def from_dict(cls, raw: Any) -> "Attestation":
        value = _object(raw, "trust")
        _keys(
            value,
            "trust",
            required={"level"},
            optional={"authority", "key_id", "mac", "issuer", "workflow"},
        )
        level = _string(value["level"], "trust.level", limit=32)
        if level not in TRUST_LEVELS:
            raise ValidationError(f"unsupported trust level: {level}")
        strings: dict[str, str | None] = {}
        for key in ("authority", "key_id", "issuer", "workflow"):
            item = value.get(key)
            strings[key] = None if item is None else _string(item, f"trust.{key}", limit=256)
        mac = value.get("mac")
        if mac is not None:
            mac = _string(mac, "trust.mac", pattern=SHA256_RE)
        if level == "verified_attestation" and not all((strings["authority"], strings["key_id"], mac)):
            raise ValidationError("verified_attestation requires authority, key_id, and mac")
        return cls(level=level, mac=mac, **strings)

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in dataclasses.asdict(self).items() if value is not None}


@dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    kind: str
    source_kind: str
    subject_candidate_digest: str
    subject_commit: str
    collected_at: dt.datetime
    trust: Attestation
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _string(self.observation_id, "observation.observation_id", pattern=ID_RE)
        if self.kind not in OBSERVATION_KINDS:
            raise ValidationError(f"unsupported observation kind: {self.kind}")
        if self.source_kind not in {"synthetic", "supplied", "observed", "attested"}:
            raise ValidationError(f"unsupported source_kind: {self.source_kind}")
        _string(self.subject_candidate_digest, "observation.subject_candidate_digest", pattern=SHA256_RE)
        _string(self.subject_commit, "observation.subject_commit", pattern=HEX_RE)
        if not isinstance(self.collected_at, dt.datetime) or self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValidationError("observation.collected_at must be timezone-aware")
        if not isinstance(self.trust, Attestation):
            raise ValidationError("observation.trust must be an Attestation")
        if not isinstance(self.payload, dict):
            raise ValidationError("observation.payload must be an object")
        object.__setattr__(self, "collected_at", self.collected_at.astimezone(dt.timezone.utc))
        object.__setattr__(self, "payload", _freeze_json(dict(self.payload)))

    @classmethod
    def from_dict(cls, raw: Any) -> "Observation":
        value = _object(raw, "observation")
        _keys(
            value,
            "observation",
            required={"observation_id", "kind", "source_kind", "subject_candidate_digest", "subject_commit", "collected_at", "trust", "payload"},
        )
        kind = _string(value["kind"], "observation.kind", limit=32)
        if kind not in OBSERVATION_KINDS:
            raise ValidationError(f"unsupported observation kind: {kind}")
        source_kind = _string(value["source_kind"], "observation.source_kind", limit=32)
        if source_kind not in {"synthetic", "supplied", "observed", "attested"}:
            raise ValidationError(f"unsupported source_kind: {source_kind}")
        payload = _object(value["payload"], "observation.payload")
        return cls(
            observation_id=_string(value["observation_id"], "observation.observation_id", pattern=ID_RE),
            kind=kind,
            source_kind=source_kind,
            subject_candidate_digest=_string(value["subject_candidate_digest"], "observation.subject_candidate_digest", pattern=SHA256_RE),
            subject_commit=_string(value["subject_commit"], "observation.subject_commit", pattern=HEX_RE),
            collected_at=parse_time(value["collected_at"], "observation.collected_at"),
            trust=Attestation.from_dict(value["trust"]),
            payload=dict(payload),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        trust = self.trust.to_dict()
        trust.pop("mac", None)
        return {
            "observation_id": self.observation_id,
            "kind": self.kind,
            "source_kind": self.source_kind,
            "subject_candidate_digest": self.subject_candidate_digest,
            "subject_commit": self.subject_commit,
            "collected_at": format_time(self.collected_at),
            "trust": trust,
            # Trust and identity bind the exact payload consumed by the gates.
            # Redaction is a report projection only and must never alter hashing.
            "payload": dict(self.payload),
        }

    def to_dict(self) -> dict[str, Any]:
        value = self.unsigned_dict()
        if self.trust.mac is not None:
            value["trust"]["mac"] = self.trust.mac
        return value

    @property
    def digest(self) -> str:
        return object_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    release_id: str
    created_at: dt.datetime
    candidate: Candidate
    observations: tuple[Observation, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValidationError(f"unsupported schema_version: {self.schema_version!r}")
        _string(self.release_id, "release_id", pattern=ID_RE)
        if not isinstance(self.created_at, dt.datetime) or self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValidationError("created_at must be timezone-aware")
        if not isinstance(self.candidate, Candidate):
            raise ValidationError("candidate must be a Candidate")
        observations = tuple(self.observations)
        if len(observations) > 500 or any(not isinstance(item, Observation) for item in observations):
            raise ValidationError("observations must contain at most 500 Observation values")
        identifiers = [item.observation_id for item in observations]
        if len(identifiers) != len(set(identifiers)):
            raise ValidationError("observation_id values must be unique")
        object.__setattr__(self, "created_at", self.created_at.astimezone(dt.timezone.utc))
        object.__setattr__(self, "observations", observations)

    @classmethod
    def from_dict(cls, raw: Any) -> "ReleaseEvidence":
        value = _object(raw, "evidence")
        _keys(value, "evidence", required={"schema_version", "release_id", "created_at", "candidate", "observations"})
        if value["schema_version"] != SCHEMA_VERSION:
            raise ValidationError(f"unsupported schema_version: {value['schema_version']!r}")
        observations_raw = value["observations"]
        if not isinstance(observations_raw, list) or len(observations_raw) > 500:
            raise ValidationError("observations must be an array of at most 500 items")
        observations = tuple(Observation.from_dict(item) for item in observations_raw)
        ids = [item.observation_id for item in observations]
        if len(ids) != len(set(ids)):
            raise ValidationError("observation_id values must be unique")
        return cls(
            release_id=_string(value["release_id"], "release_id", pattern=ID_RE),
            created_at=parse_time(value["created_at"], "created_at"),
            candidate=Candidate.from_dict(value["candidate"]),
            observations=observations,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "release_id": self.release_id,
            "created_at": format_time(self.created_at),
            "candidate": self.candidate.to_dict(),
            "observations": [item.to_dict() for item in self.observations],
        }

    @property
    def digest(self) -> str:
        return object_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class Waiver:
    waiver_id: str
    reason_code: str
    candidate_digest: str
    policy_digest: str
    gate: str
    expires_at: dt.datetime
    justification: str
    approver: str
    trust: Attestation

    def __post_init__(self) -> None:
        _string(self.waiver_id, "waiver.waiver_id", pattern=ID_RE)
        _string(self.reason_code, "waiver.reason_code", pattern=ID_RE)
        _string(self.candidate_digest, "waiver.candidate_digest", pattern=SHA256_RE)
        _string(self.policy_digest, "waiver.policy_digest", pattern=SHA256_RE)
        _string(self.gate, "waiver.gate", pattern=ID_RE)
        _string(self.justification, "waiver.justification", limit=2_000)
        _string(self.approver, "waiver.approver", limit=256)
        if not isinstance(self.expires_at, dt.datetime) or self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValidationError("waiver.expires_at must be timezone-aware")
        if not isinstance(self.trust, Attestation):
            raise ValidationError("waiver.trust must be an Attestation")
        object.__setattr__(self, "expires_at", self.expires_at.astimezone(dt.timezone.utc))

    @classmethod
    def from_dict(cls, raw: Any) -> "Waiver":
        value = _object(raw, "waiver")
        _keys(value, "waiver", required={"waiver_id", "reason_code", "candidate_digest", "policy_digest", "gate", "expires_at", "justification", "approver", "trust"})
        return cls(
            waiver_id=_string(value["waiver_id"], "waiver.waiver_id", pattern=ID_RE),
            reason_code=_string(value["reason_code"], "waiver.reason_code", pattern=ID_RE),
            candidate_digest=_string(value["candidate_digest"], "waiver.candidate_digest", pattern=SHA256_RE),
            policy_digest=_string(value["policy_digest"], "waiver.policy_digest", pattern=SHA256_RE),
            gate=_string(value["gate"], "waiver.gate", pattern=ID_RE),
            expires_at=parse_time(value["expires_at"], "waiver.expires_at"),
            justification=_string(value["justification"], "waiver.justification", limit=2_000),
            approver=_string(value["approver"], "waiver.approver", limit=256),
            trust=Attestation.from_dict(value["trust"]),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        trust = self.trust.to_dict()
        trust.pop("mac", None)
        value = {
            "waiver_id": self.waiver_id,
            "reason_code": self.reason_code,
            "candidate_digest": self.candidate_digest,
            "policy_digest": self.policy_digest,
            "gate": self.gate,
            "expires_at": format_time(self.expires_at),
            "justification": self.justification,
            "approver": self.approver,
            "trust": trust,
        }
        return value

    def to_dict(self) -> dict[str, Any]:
        value = self.unsigned_dict()
        if self.trust.mac is not None:
            value["trust"]["mac"] = self.trust.mac
        return value


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    policy_id: str
    required_checks: tuple[str, ...]
    required_matrix: tuple[str, ...]
    required_test_suites: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    expected_environment: str
    expected_version: str
    assurance_profile: str
    max_evidence_age_hours: int = 24
    max_diff_risk: int = 50
    minimum_test_count: int = 1
    minimum_flake_samples: int = 2
    maximum_flake_rate: float = 0.0
    minimum_reproducible_builds: int = 2
    minimum_reproducible_authorities: int = 2
    require_artifact: bool = True
    require_sbom: bool = True
    require_changelog: bool = True
    require_rollback: bool = True
    require_deploy_observation: bool = False
    rollback_max_age_hours: int = 168
    maximum_rollback_minutes: int = 30
    allowed_authorities: tuple[str, ...] = ()
    allowed_issuers: tuple[str, ...] = ()
    allowed_workflows: tuple[str, ...] = ()
    allowed_source_kinds: tuple[str, ...] = ("attested",)
    allowed_waiver_authorities: tuple[str, ...] = ()
    waivable_reason_codes: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValidationError(f"unsupported policy schema_version: {self.schema_version!r}")
        _string(self.policy_id, "policy.policy_id", pattern=ID_RE)
        sequence_fields = (
            "required_checks", "required_matrix", "required_test_suites", "required_artifacts",
            "allowed_authorities", "allowed_issuers", "allowed_workflows", "allowed_source_kinds",
            "allowed_waiver_authorities", "waivable_reason_codes",
        )
        for name in sequence_fields:
            raw = getattr(self, name)
            if not isinstance(raw, (list, tuple)) or len(raw) > 100:
                raise ValidationError(f"policy.{name} must be an array of at most 100 strings")
            items = tuple(_string(item, f"policy.{name}[]", pattern=ID_RE) for item in raw)
            if len(items) != len(set(items)):
                raise ValidationError(f"policy.{name} must not contain duplicates")
            object.__setattr__(self, name, items)
        for name in ("required_checks", "required_matrix", "required_test_suites", "required_artifacts"):
            if not getattr(self, name):
                raise ValidationError(f"policy.{name} must not be empty")
        if any(item not in {"synthetic", "supplied", "observed", "attested"} for item in self.allowed_source_kinds):
            raise ValidationError("policy.allowed_source_kinds contains an unsupported value")
        _string(self.expected_environment, "policy.expected_environment", pattern=ID_RE)
        _string(self.expected_version, "policy.expected_version", limit=128)
        if self.assurance_profile not in {"LAB", "PRODUCTION"}:
            raise ValidationError("policy.assurance_profile must be LAB or PRODUCTION")
        if self.assurance_profile == "PRODUCTION" and "synthetic" in self.allowed_source_kinds:
            raise ValidationError("PRODUCTION policy must never allow synthetic evidence")
        integer_fields = {
            "max_evidence_age_hours": (1, 8_760), "max_diff_risk": (0, 100),
            "minimum_test_count": (1, 10_000_000), "minimum_flake_samples": (1, 100),
            "minimum_reproducible_builds": (2, 20), "minimum_reproducible_authorities": (1, 20),
            "rollback_max_age_hours": (1, 8_760), "maximum_rollback_minutes": (1, 10_080),
        }
        for name, (minimum, maximum) in integer_fields.items():
            _int(getattr(self, name), f"policy.{name}", minimum=minimum, maximum=maximum)
        object.__setattr__(self, "maximum_flake_rate", _number(
            self.maximum_flake_rate, "policy.maximum_flake_rate", maximum=1,
        ))
        for name in ("require_artifact", "require_sbom", "require_changelog", "require_rollback", "require_deploy_observation"):
            _bool(getattr(self, name), f"policy.{name}")

    @classmethod
    def from_dict(cls, raw: Any) -> "ReleasePolicy":
        value = _object(raw, "policy")
        required = {"schema_version", "policy_id", "required_checks", "required_matrix", "required_test_suites", "required_artifacts", "expected_environment", "expected_version", "assurance_profile"}
        optional = {
            "max_evidence_age_hours", "max_diff_risk", "minimum_test_count", "minimum_flake_samples",
            "maximum_flake_rate", "minimum_reproducible_builds", "minimum_reproducible_authorities", "require_artifact", "require_sbom",
            "require_changelog", "require_rollback", "require_deploy_observation", "rollback_max_age_hours",
            "maximum_rollback_minutes", "allowed_authorities", "allowed_issuers", "allowed_workflows",
            "allowed_source_kinds", "allowed_waiver_authorities", "waivable_reason_codes",
        }
        _keys(value, "policy", required=required, optional=optional)
        if value["schema_version"] != SCHEMA_VERSION:
            raise ValidationError("unsupported policy schema_version")

        def strings(key: str, *, maximum: int = 100) -> tuple[str, ...]:
            raw_items = value.get(key, [])
            if not isinstance(raw_items, list) or len(raw_items) > maximum:
                raise ValidationError(f"policy.{key} must be an array of at most {maximum} strings")
            result = tuple(_string(item, f"policy.{key}[]", pattern=ID_RE) for item in raw_items)
            if len(result) != len(set(result)):
                raise ValidationError(f"policy.{key} must not contain duplicates")
            return result

        kwargs: dict[str, Any] = {
            "policy_id": _string(value["policy_id"], "policy.policy_id", pattern=ID_RE),
            "required_checks": strings("required_checks"),
            "required_matrix": strings("required_matrix"),
            "required_test_suites": strings("required_test_suites"),
            "required_artifacts": strings("required_artifacts"),
            "expected_environment": _string(value["expected_environment"], "policy.expected_environment", pattern=ID_RE),
            "expected_version": _string(value["expected_version"], "policy.expected_version", limit=128),
            "assurance_profile": _string(value["assurance_profile"], "policy.assurance_profile", limit=16),
            "allowed_authorities": strings("allowed_authorities"),
            "allowed_issuers": strings("allowed_issuers"),
            "allowed_workflows": strings("allowed_workflows"),
            "allowed_waiver_authorities": strings("allowed_waiver_authorities"),
            "waivable_reason_codes": strings("waivable_reason_codes"),
        }
        for key in ("required_checks", "required_matrix", "required_test_suites", "required_artifacts"):
            if not kwargs[key]:
                raise ValidationError(f"policy.{key} must not be empty")
        if "allowed_source_kinds" in value:
            source_kinds = strings("allowed_source_kinds")
            if any(item not in {"synthetic", "supplied", "observed", "attested"} for item in source_kinds):
                raise ValidationError("policy.allowed_source_kinds contains an unsupported value")
            kwargs["allowed_source_kinds"] = source_kinds
        int_fields = {
            "max_evidence_age_hours": (1, 8_760), "max_diff_risk": (0, 100), "minimum_test_count": (1, 10_000_000),
            "minimum_flake_samples": (1, 100), "minimum_reproducible_builds": (2, 20),
            "minimum_reproducible_authorities": (1, 20),
            "rollback_max_age_hours": (1, 8_760), "maximum_rollback_minutes": (1, 10_080),
        }
        for key, (minimum, maximum) in int_fields.items():
            if key in value:
                kwargs[key] = _int(value[key], f"policy.{key}", minimum=minimum, maximum=maximum)
        if "maximum_flake_rate" in value:
            kwargs["maximum_flake_rate"] = _number(value["maximum_flake_rate"], "policy.maximum_flake_rate", maximum=1)
        for key in ("require_artifact", "require_sbom", "require_changelog", "require_rollback", "require_deploy_observation"):
            if key in value:
                kwargs[key] = _bool(value[key], f"policy.{key}")
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "required_checks": list(self.required_checks),
            "required_matrix": list(self.required_matrix),
            "required_test_suites": list(self.required_test_suites),
            "required_artifacts": list(self.required_artifacts),
            "expected_environment": self.expected_environment,
            "expected_version": self.expected_version,
            "assurance_profile": self.assurance_profile,
            "max_evidence_age_hours": self.max_evidence_age_hours,
            "max_diff_risk": self.max_diff_risk,
            "minimum_test_count": self.minimum_test_count,
            "minimum_flake_samples": self.minimum_flake_samples,
            "maximum_flake_rate": self.maximum_flake_rate,
            "minimum_reproducible_builds": self.minimum_reproducible_builds,
            "minimum_reproducible_authorities": self.minimum_reproducible_authorities,
            "require_artifact": self.require_artifact,
            "require_sbom": self.require_sbom,
            "require_changelog": self.require_changelog,
            "require_rollback": self.require_rollback,
            "require_deploy_observation": self.require_deploy_observation,
            "rollback_max_age_hours": self.rollback_max_age_hours,
            "maximum_rollback_minutes": self.maximum_rollback_minutes,
            "allowed_authorities": list(self.allowed_authorities),
            "allowed_issuers": list(self.allowed_issuers),
            "allowed_workflows": list(self.allowed_workflows),
            "allowed_source_kinds": list(self.allowed_source_kinds),
            "allowed_waiver_authorities": list(self.allowed_waiver_authorities),
            "waivable_reason_codes": list(self.waivable_reason_codes),
        }

    @property
    def digest(self) -> str:
        return object_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class GateResult:
    gate: str
    status: str
    reason_code: str
    message: str
    evidence_ids: tuple[str, ...] = ()
    waived_by: str | None = None
    original_status: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _string(self.gate, "gate.gate", pattern=ID_RE)
        if self.status not in STATUSES:
            raise ValidationError(f"invalid gate status: {self.status}")
        _string(self.reason_code, "gate.reason_code", pattern=ID_RE)
        _string(self.message, "gate.message", limit=2_000)
        if not isinstance(self.evidence_ids, (list, tuple)) or len(self.evidence_ids) > 500:
            raise ValidationError("gate.evidence_ids must be an array of at most 500 IDs")
        evidence_ids = tuple(_string(item, "gate.evidence_ids[]", pattern=ID_RE) for item in self.evidence_ids)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValidationError("gate.evidence_ids must not contain duplicates")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        if not isinstance(self.details, dict):
            raise ValidationError("gate.details must be an object")
        object.__setattr__(self, "details", _freeze_json(dict(self.details)))
        if self.status == "warn":
            if self.waived_by is None or self.original_status not in {"fail", "unknown"}:
                raise ValidationError("warn gate status requires a waiver and original fail/unknown status")
            _string(self.waived_by, "gate.waived_by", pattern=ID_RE)
        elif self.waived_by is not None or self.original_status is not None:
            raise ValidationError("waiver metadata is allowed only on warn gates")

    @classmethod
    def from_dict(cls, raw: Any) -> "GateResult":
        value = _object(raw, "gate")
        _keys(value, "gate", required={"gate", "status", "reason_code", "message", "evidence_ids", "details"}, optional={"waived_by", "original_status"})
        evidence_ids = value["evidence_ids"]
        if not isinstance(evidence_ids, list) or len(evidence_ids) > 500:
            raise ValidationError("gate.evidence_ids must be an array of at most 500 IDs")
        details = _object(value["details"], "gate.details")
        waived_by = value.get("waived_by")
        original = value.get("original_status")
        return cls(
            _string(value["gate"], "gate.gate", pattern=ID_RE),
            _string(value["status"], "gate.status", limit=16),
            _string(value["reason_code"], "gate.reason_code", pattern=ID_RE),
            _string(value["message"], "gate.message", limit=2_000),
            tuple(_string(item, "gate.evidence_ids[]", pattern=ID_RE) for item in evidence_ids),
            None if waived_by is None else _string(waived_by, "gate.waived_by", pattern=ID_RE),
            None if original is None else _string(original, "gate.original_status", limit=16),
            dict(details),
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "gate": self.gate,
            "status": self.status,
            "reason_code": self.reason_code,
            "message": self.message,
            "evidence_ids": list(self.evidence_ids),
            "details": redact(dict(self.details)),
        }
        if self.waived_by is not None:
            value["waived_by"] = self.waived_by
        if self.original_status is not None:
            value["original_status"] = self.original_status
        return value


@dataclass(frozen=True, slots=True)
class Decision:
    decision_id: str
    release_id: str
    outcome: str
    evaluated_at: dt.datetime
    candidate_digest: str
    evidence_digest: str
    policy_id: str
    policy_digest: str
    assurance_profile: str
    gates: tuple[GateResult, ...]
    applied_waivers: tuple[str, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValidationError(f"unsupported decision schema_version: {self.schema_version!r}")
        _string(self.decision_id, "decision.decision_id", limit=64)
        _string(self.release_id, "decision.release_id", pattern=ID_RE)
        if self.outcome not in DECISIONS:
            raise ValidationError(f"invalid decision outcome: {self.outcome}")
        if not isinstance(self.evaluated_at, dt.datetime) or self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None:
            raise ValidationError("decision.evaluated_at must be timezone-aware")
        object.__setattr__(self, "evaluated_at", self.evaluated_at.astimezone(dt.timezone.utc))
        _string(self.candidate_digest, "decision.candidate_digest", pattern=SHA256_RE)
        _string(self.evidence_digest, "decision.evidence_digest", pattern=SHA256_RE)
        _string(self.policy_id, "decision.policy_id", pattern=ID_RE)
        _string(self.policy_digest, "decision.policy_digest", pattern=SHA256_RE)
        if self.assurance_profile not in {"LAB", "PRODUCTION"}:
            raise ValidationError("decision assurance_profile must be LAB or PRODUCTION")
        if not isinstance(self.gates, (list, tuple)) or len(self.gates) > 500 or any(not isinstance(gate, GateResult) for gate in self.gates):
            raise ValidationError("decision.gates must contain at most 500 GateResult values")
        if not isinstance(self.applied_waivers, (list, tuple)) or len(self.applied_waivers) > 100:
            raise ValidationError("decision.applied_waivers must contain at most 100 IDs")
        gates = tuple(self.gates)
        applied_waivers = tuple(_string(item, "decision.applied_waivers[]", pattern=ID_RE) for item in self.applied_waivers)
        object.__setattr__(self, "gates", gates)
        object.__setattr__(self, "applied_waivers", applied_waivers)
        derived = "BLOCKED" if any(gate.status == "fail" for gate in self.gates) else (
            "UNKNOWN" if any(gate.status in {"unknown", "pending", "cancelled", "skipped"} for gate in self.gates) else "READY"
        )
        if self.outcome != derived:
            raise ValidationError(f"decision outcome {self.outcome} is inconsistent with gate statuses ({derived})")
        names = [gate.gate for gate in self.gates]
        if len(names) != len(set(names)):
            raise ValidationError("decision gate names must be unique")
        if set(names) - {"waivers"} != REQUIRED_GATE_NAMES:
            raise ValidationError("decision must contain the complete Shipcheck 0.1 gate set")
        waived = [gate.waived_by for gate in self.gates if gate.waived_by is not None]
        if len(waived) != len(set(waived)) or set(waived) != set(self.applied_waivers):
            raise ValidationError("decision applied_waivers must exactly match unique waived gate IDs")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision_id": self.decision_id,
            "release_id": self.release_id,
            "outcome": self.outcome,
            "evaluated_at": format_time(self.evaluated_at),
            "candidate_digest": self.candidate_digest,
            "evidence_digest": self.evidence_digest,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "assurance_profile": self.assurance_profile,
            "production_ready": self.production_ready,
            "gates": [gate.to_dict() for gate in self.gates],
            "applied_waivers": list(self.applied_waivers),
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "Decision":
        value = _object(raw, "decision")
        _keys(value, "decision", required={"schema_version", "decision_id", "release_id", "outcome", "evaluated_at", "candidate_digest", "evidence_digest", "policy_id", "policy_digest", "assurance_profile", "production_ready", "gates", "applied_waivers"})
        if value["schema_version"] != SCHEMA_VERSION:
            raise ValidationError("unsupported decision schema_version")
        gates = value["gates"]
        waivers = value["applied_waivers"]
        if not isinstance(gates, list) or len(gates) > 500 or not isinstance(waivers, list) or len(waivers) > 100:
            raise ValidationError("decision gates or waivers exceed bounds")
        decision = cls(
            decision_id=_string(value["decision_id"], "decision.decision_id", limit=64),
            release_id=_string(value["release_id"], "decision.release_id", pattern=ID_RE),
            outcome=_string(value["outcome"], "decision.outcome", limit=16),
            evaluated_at=parse_time(value["evaluated_at"], "decision.evaluated_at"),
            candidate_digest=_string(value["candidate_digest"], "decision.candidate_digest", pattern=SHA256_RE),
            evidence_digest=_string(value["evidence_digest"], "decision.evidence_digest", pattern=SHA256_RE),
            policy_id=_string(value["policy_id"], "decision.policy_id", pattern=ID_RE),
            policy_digest=_string(value["policy_digest"], "decision.policy_digest", pattern=SHA256_RE),
            assurance_profile=_string(value["assurance_profile"], "decision.assurance_profile", limit=16),
            gates=tuple(GateResult.from_dict(item) for item in gates),
            applied_waivers=tuple(_string(item, "decision.applied_waivers[]", pattern=ID_RE) for item in waivers),
        )
        if type(value["production_ready"]) is not bool or value["production_ready"] != decision.production_ready:
            raise ValidationError("decision.production_ready does not match outcome and assurance_profile")
        return decision

    @property
    def production_ready(self) -> bool:
        return self.outcome == "READY" and self.assurance_profile == "PRODUCTION"

    @property
    def digest(self) -> str:
        return object_digest(self.to_dict())


def group_observations(evidence: ReleaseEvidence, kind: str) -> tuple[Observation, ...]:
    return tuple(item for item in evidence.observations if item.kind == kind)


def ensure_mapping(value: Any, name: str) -> Mapping[str, Any]:
    return _object(value, name)


def require_keys(value: Mapping[str, Any], name: str, required: Iterable[str], optional: Iterable[str] = ()) -> None:
    _keys(value, name, required=set(required), optional=set(optional))


def require_string(value: Any, name: str, *, limit: int = 256, pattern: re.Pattern[str] | None = None) -> str:
    return _string(value, name, limit=limit, pattern=pattern)


def require_int(value: Any, name: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    return _int(value, name, minimum=minimum, maximum=maximum)


def require_number(value: Any, name: str, *, minimum: float = 0, maximum: float = 1_000_000) -> float:
    return _number(value, name, minimum=minimum, maximum=maximum)


def require_bool(value: Any, name: str) -> bool:
    return _bool(value, name)
