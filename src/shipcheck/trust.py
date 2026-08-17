"""HMAC-backed local attestation verification.

The HMAC establishes integrity relative to an explicitly configured trust store. It is
not a public signature and Shipcheck reports that limitation rather than conflating a
digest with identity.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import canonical_json
from .canonical import object_digest, sha256_hex
from .errors import ValidationError
from .models import Observation, Waiver, format_time


@dataclass(frozen=True, slots=True)
class TrustKey:
    key_id: str
    authority: str
    secret: bytes
    usages: tuple[str, ...] = ("evidence",)


class TrustStore:
    def __init__(self, keys: Mapping[str, TrustKey] | None = None) -> None:
        self._keys = dict(keys or {})

    @classmethod
    def from_dict(cls, raw: Any) -> "TrustStore":
        if not isinstance(raw, dict) or set(raw) != {"schema_version", "keys"}:
            raise ValidationError("trust store must contain exactly schema_version and keys")
        if raw["schema_version"] != "shipcheck/trust-v1":
            raise ValidationError("unsupported trust store schema_version")
        items = raw["keys"]
        if not isinstance(items, list) or len(items) > 100:
            raise ValidationError("trust store keys must be an array of at most 100 items")
        output: dict[str, TrustKey] = {}
        for index, item in enumerate(items):
            if not isinstance(item, dict) or set(item) != {"key_id", "authority", "secret_base64", "usages"}:
                raise ValidationError(f"trust store key {index} has invalid fields")
            for field in ("key_id", "authority", "secret_base64"):
                if not isinstance(item[field], str) or not item[field] or len(item[field]) > 512:
                    raise ValidationError(f"trust store key {index}.{field} is invalid")
            if item["key_id"] in output:
                raise ValidationError("duplicate trust store key_id")
            try:
                secret = base64.b64decode(item["secret_base64"], validate=True)
            except ValueError as exc:
                raise ValidationError("trust store secret_base64 is invalid") from exc
            if not 32 <= len(secret) <= 128:
                raise ValidationError("trust store secrets must contain 32 to 128 bytes")
            usages = item["usages"]
            if not isinstance(usages, list) or not usages or len(usages) > 2 or any(value not in {"evidence", "waiver"} for value in usages) or len(usages) != len(set(usages)):
                raise ValidationError("trust store key usages must contain evidence and/or waiver without duplicates")
            output[item["key_id"]] = TrustKey(item["key_id"], item["authority"], secret, tuple(usages))
        return cls(output)

    def get(self, key_id: str) -> TrustKey | None:
        return self._keys.get(key_id)

    @property
    def digest(self) -> str:
        return object_digest([
            {"key_id": key.key_id, "authority": key.authority, "usages": list(key.usages), "secret_digest": sha256_hex(key.secret)}
            for key in sorted(self._keys.values(), key=lambda value: value.key_id)
        ])

    def verify(self, observation: Observation) -> tuple[bool, str]:
        return self.verify_signed(observation.trust, observation.unsigned_dict(), required_usage="evidence")

    def verify_waiver(self, waiver: Waiver) -> tuple[bool, str]:
        return self.verify_signed(waiver.trust, waiver.unsigned_dict(), required_usage="waiver")

    def verify_signed(self, trust: Any, unsigned: Mapping[str, Any], *, required_usage: str) -> tuple[bool, str]:
        if trust.level != "verified_attestation":
            return False, "evidence is self-declared"
        if trust.key_id is None or trust.mac is None or trust.authority is None:
            return False, "attestation fields are incomplete"
        key = self.get(trust.key_id)
        if key is None:
            return False, "attestation key is not trusted"
        if required_usage not in key.usages:
            return False, f"attestation key is not authorized for {required_usage}"
        if not hmac.compare_digest(key.authority, trust.authority):
            return False, "attestation authority does not match trust store"
        expected = hmac.new(key.secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, trust.mac):
            return False, "attestation MAC verification failed"
        return True, "attestation verified by configured local HMAC trust store"


def sign_observation(observation: Observation, key: TrustKey) -> Observation:
    from .models import Attestation

    # Build the exact unsigned wire representation directly.  A partially signed
    # ``verified_attestation`` is deliberately not a valid public model value.
    # This keeps direct constructors strict without weakening the signing path.
    trust: dict[str, Any] = {
        "level": "verified_attestation",
        "authority": key.authority,
        "key_id": key.key_id,
    }
    if observation.trust.issuer is not None:
        trust["issuer"] = observation.trust.issuer
    if observation.trust.workflow is not None:
        trust["workflow"] = observation.trust.workflow
    unsigned = {
        "observation_id": observation.observation_id,
        "kind": observation.kind,
        "source_kind": observation.source_kind,
        "subject_candidate_digest": observation.subject_candidate_digest,
        "subject_commit": observation.subject_commit,
        "collected_at": format_time(observation.collected_at),
        "trust": trust,
        "payload": dict(observation.payload),
    }
    mac = hmac.new(key.secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
    return Observation(
        observation_id=observation.observation_id,
        kind=observation.kind,
        source_kind=observation.source_kind,
        subject_candidate_digest=observation.subject_candidate_digest,
        subject_commit=observation.subject_commit,
        collected_at=observation.collected_at,
        trust=Attestation(
            level="verified_attestation",
            authority=key.authority,
            key_id=key.key_id,
            mac=mac,
            issuer=observation.trust.issuer,
            workflow=observation.trust.workflow,
        ),
        payload=observation.payload,
    )


def sign_waiver(waiver: Waiver, key: TrustKey) -> Waiver:
    from .models import Attestation

    trust: dict[str, Any] = {
        "level": "verified_attestation",
        "authority": key.authority,
        "key_id": key.key_id,
    }
    unsigned = {
        "waiver_id": waiver.waiver_id,
        "reason_code": waiver.reason_code,
        "candidate_digest": waiver.candidate_digest,
        "policy_digest": waiver.policy_digest,
        "gate": waiver.gate,
        "expires_at": format_time(waiver.expires_at),
        "justification": waiver.justification,
        "approver": waiver.approver,
        "trust": trust,
    }
    mac = hmac.new(key.secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
    return Waiver(
        waiver_id=waiver.waiver_id,
        reason_code=waiver.reason_code,
        candidate_digest=waiver.candidate_digest,
        policy_digest=waiver.policy_digest,
        gate=waiver.gate,
        expires_at=waiver.expires_at,
        justification=waiver.justification,
        approver=waiver.approver,
        trust=Attestation("verified_attestation", authority=key.authority, key_id=key.key_id, mac=mac),
    )
