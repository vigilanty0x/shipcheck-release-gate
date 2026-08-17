from __future__ import annotations

import dataclasses
import datetime as dt
from collections.abc import Callable

from shipcheck.demo import build_demo
from shipcheck.models import Attestation, Observation, ReleaseEvidence
from shipcheck.trust import TrustKey, TrustStore, sign_observation


def demo():
    return build_demo(now=dt.datetime(2026, 8, 17, 12, tzinfo=dt.timezone.utc))


def mutate_observation(
    evidence: ReleaseEvidence,
    store: TrustStore,
    kind: str,
    mutate: Callable[[Observation], Observation],
    *,
    occurrence: int = 0,
    resign: bool = True,
    signer: TrustKey | None = None,
) -> ReleaseEvidence:
    output = []
    seen = 0
    for item in evidence.observations:
        if item.kind == kind and seen == occurrence:
            changed = mutate(item)
            if resign:
                key = signer or store.get(item.trust.key_id or "")
                if key is None:
                    raise AssertionError("fixture signing key missing")
                changed = sign_observation(changed, key)
            output.append(changed)
            seen += 1
        else:
            output.append(item)
            if item.kind == kind:
                seen += 1
    if seen <= occurrence:
        raise AssertionError(f"observation kind not found: {kind}/{occurrence}")
    return dataclasses.replace(evidence, observations=tuple(output))


def payload_change(**changes):
    def mutate(item: Observation) -> Observation:
        payload = dict(item.payload)
        payload.update(changes)
        return dataclasses.replace(item, payload=payload)

    return mutate


def remove_kind(evidence: ReleaseEvidence, kind: str) -> ReleaseEvidence:
    return dataclasses.replace(evidence, observations=tuple(item for item in evidence.observations if item.kind != kind))


def add_observation(evidence: ReleaseEvidence, item: Observation) -> ReleaseEvidence:
    return dataclasses.replace(evidence, observations=evidence.observations + (item,))

