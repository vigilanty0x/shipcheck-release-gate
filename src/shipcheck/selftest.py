"""Small deterministic contract test shipped in wheel and sdist."""

from __future__ import annotations

import datetime as dt

from . import __version__
from .adapters import normalize_junit
from .demo import build_demo
from .engine import DecisionEngine
from .errors import ValidationError
from .limits import loads_strict


def run_selftest() -> dict[str, object]:
    now = dt.datetime(2026, 8, 17, 10, tzinfo=dt.timezone.utc)
    observed: dict[str, str] = {}
    checks = 0
    for scenario, expected in (("ready-lab", "READY"), ("blocked", "BLOCKED"), ("unknown", "UNKNOWN")):
        evidence, policy, store, _ = build_demo(now=now, scenario=scenario)
        decision = DecisionEngine(trust_store=store, clock=lambda: now).evaluate(evidence, policy)
        if decision.outcome != expected or decision.assurance_profile != "LAB" or decision.production_ready:
            raise RuntimeError(f"selftest scenario failed: {scenario}")
        observed[scenario] = decision.outcome
        checks += 1
    try:
        loads_strict(b'{"duplicate":1,"duplicate":2}')
    except ValidationError:
        checks += 1
    else:
        raise RuntimeError("strict JSON duplicate-key selftest failed")
    normalized = normalize_junit(b'<testsuite name="selftest" tests="1"><testcase/></testsuite>')
    if normalized["trust_level"] != "self_declared" or normalized["records"][0]["payload"]["passed"] != 1:
        raise RuntimeError("offline adapter selftest failed")
    checks += 1
    return {
        "schema_version": "shipcheck/selftest-v1",
        "shipcheck_version": __version__,
        "ok": True,
        "checks": checks,
        "scenarios": observed,
        "assurance_profile": "LAB",
        "production_ready": False,
    }
