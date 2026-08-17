"""Bounded, inert normalizers for common CI evidence formats.

Adapters parse caller-supplied bytes only. They never discover files, execute a
command, access a network, or claim that normalized data is authenticated.
Their output is intentionally marked ``supplied``/``self_declared`` and must be
bound and authenticated by a separate protected CI step before a PRODUCTION
policy can become READY.
"""

from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Mapping

from .canonical import canonical_json, object_digest, sha256_hex
from .errors import ValidationError
from .limits import loads_strict
from .models import SHA256_RE

NORMALIZED_SCHEMA = "shipcheck/normalized-evidence-v1"
BUNDLE_SCHEMA = "shipcheck/normalized-bundle-v1"
MAX_INPUT_BYTES = 2_097_152
MAX_XML_NODES = 10_000
MAX_RECORDS = 10_000
_XML_FORBIDDEN = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _bytes(raw: bytes | str) -> bytes:
    if isinstance(raw, str):
        try:
            value = raw.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise ValidationError("adapter input is not valid UTF-8") from exc
    elif isinstance(raw, bytes):
        value = raw
    else:
        raise ValidationError("adapter input must be bytes or text")
    if not value or len(value) > MAX_INPUT_BYTES:
        raise ValidationError("adapter input must contain 1 byte to 2 MiB")
    return value


def _document(adapter: str, source: bytes, records: list[dict[str, Any]], *, summary: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not records or len(records) > MAX_RECORDS:
        raise ValidationError("normalized record count is outside supported bounds")
    result: dict[str, Any] = {
        "schema_version": NORMALIZED_SCHEMA,
        "adapter": adapter,
        "source_kind": "supplied",
        "trust_level": "self_declared",
        "source_digest": sha256_hex(source),
        "records": records,
    }
    if summary is not None:
        result["summary"] = dict(summary)
    # Make sure adapter output itself stays within the same public JSON bound.
    if len(canonical_json(result)) > MAX_INPUT_BYTES:
        raise ValidationError("normalized output exceeds 2 MiB")
    return result


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _duration(value: str | None, name: str) -> float:
    if value in (None, ""):
        return 0.0
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValidationError(f"{name} must be a finite non-negative number") from exc
    if not math.isfinite(parsed) or not 0 <= parsed <= 604_800:
        raise ValidationError(f"{name} must be in [0, 604800]")
    return parsed


def normalize_junit(raw: bytes | str, *, run_id: str = "supplied-junit") -> dict[str, Any]:
    source = _bytes(raw)
    if _XML_FORBIDDEN.search(source):
        raise ValidationError("JUnit XML must not contain DTD or ENTITY declarations")
    try:
        root = ET.fromstring(source)
    except (ET.ParseError, ValueError, RecursionError) as exc:
        raise ValidationError("JUnit XML is malformed") from exc
    nodes = list(root.iter())
    if len(nodes) > MAX_XML_NODES:
        raise ValidationError("JUnit XML exceeds the 10,000-node limit")
    if any(len(node.attrib) > 100 for node in nodes):
        raise ValidationError("JUnit XML node has too many attributes")
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise ValidationError("JUnit run_id must be 1 to 128 characters")

    root_name = _local(root.tag)
    if root_name == "testsuite":
        suites = [root]
    elif root_name == "testsuites":
        suites = [child for child in root if _local(child.tag) == "testsuite"]
        if len(suites) != len(list(root)):
            raise ValidationError("JUnit testsuites may contain testsuite elements only")
    else:
        raise ValidationError("JUnit root must be testsuite or testsuites")
    if not suites or len(suites) > 1_000:
        raise ValidationError("JUnit must contain 1 to 1,000 suites")

    records: list[dict[str, Any]] = []
    names: set[str] = set()
    aggregate = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
    for index, suite in enumerate(suites):
        if any(_local(child.tag) == "testsuite" for child in suite):
            raise ValidationError("nested JUnit testsuites are not supported")
        name = suite.attrib.get("name") or f"suite-{index + 1}"
        if not name or len(name) > 128 or name in names:
            raise ValidationError("JUnit suite names must be unique and at most 128 characters")
        names.add(name)
        cases = [child for child in suite if _local(child.tag) == "testcase"]
        if len(cases) > MAX_RECORDS:
            raise ValidationError("JUnit suite exceeds the testcase limit")
        passed = failed = skipped = 0
        duration = 0.0
        for case_index, case in enumerate(cases):
            duration += _duration(case.attrib.get("time"), f"JUnit testcase {case_index} time")
            child_kinds = {_local(child.tag) for child in case}
            if "failure" in child_kinds or "error" in child_kinds:
                failed += 1
            elif "skipped" in child_kinds:
                skipped += 1
            else:
                passed += 1
        total = len(cases)
        declared = suite.attrib.get("tests")
        if declared is not None:
            try:
                declared_count = int(declared, 10)
            except (TypeError, ValueError) as exc:
                raise ValidationError("JUnit declared tests count is invalid") from exc
            if declared_count != total:
                raise ValidationError("JUnit declared tests count does not match testcase elements")
        payload = {
            "suite": name,
            "run_id": f"{run_id}:{index + 1}",
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "duration_seconds": round(duration, 6),
            "truncated": False,
        }
        records.append({"kind": "test_summary", "payload": payload})
        for key in aggregate:
            aggregate[key] += payload[key]
    return _document("junit-xml", source, records, summary=aggregate)


def normalize_sarif(raw: bytes | str) -> dict[str, Any]:
    source = _bytes(raw)
    value = loads_strict(source, max_bytes=MAX_INPUT_BYTES)
    if not isinstance(value, dict) or not {"version", "runs"}.issubset(value) or set(value) - {"version", "$schema", "runs"}:
        raise ValidationError("SARIF top-level fields are invalid")
    if value["version"] != "2.1.0":
        raise ValidationError("only SARIF 2.1.0 is supported")
    runs = value["runs"]
    if not isinstance(runs, list) or not runs or len(runs) > 100:
        raise ValidationError("SARIF must contain 1 to 100 runs")
    levels = {"error": 0, "warning": 0, "note": 0, "none": 0}
    declared_rules: set[str] = set()
    used_rules: set[str] = set()
    result_count = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValidationError(f"SARIF run {run_index} must be an object")
        tool = run.get("tool")
        if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
            raise ValidationError(f"SARIF run {run_index} has no tool.driver")
        rules = tool["driver"].get("rules", [])
        if not isinstance(rules, list) or len(rules) > MAX_RECORDS:
            raise ValidationError("SARIF rules exceed bounds")
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"] or len(rule["id"]) > 256:
                raise ValidationError("SARIF rule id is invalid")
            declared_rules.add(rule["id"])
        results = run.get("results", [])
        if not isinstance(results, list) or len(results) > MAX_RECORDS or result_count + len(results) > MAX_RECORDS:
            raise ValidationError("SARIF results exceed the 10,000-result limit")
        result_count += len(results)
        for result in results:
            if not isinstance(result, dict):
                raise ValidationError("SARIF result must be an object")
            level = result.get("level", "warning")
            if level not in levels:
                raise ValidationError("SARIF result level is invalid")
            levels[level] += 1
            rule_id = result.get("ruleId")
            if rule_id is not None:
                if not isinstance(rule_id, str) or not rule_id or len(rule_id) > 256:
                    raise ValidationError("SARIF result ruleId is invalid")
                used_rules.add(rule_id)
    payload = {
        "version": "2.1.0",
        "run_count": len(runs),
        "result_count": result_count,
        "levels": levels,
        "declared_rule_count": len(declared_rules),
        "used_rule_count": len(used_rules),
        "undeclared_rule_ids": sorted(used_rules - declared_rules),
    }
    return _document("sarif-json", source, [{"kind": "sarif_summary", "payload": payload}], summary=payload)


def normalize_cyclonedx(raw: bytes | str, *, artifact_name: str, artifact_digest: str) -> dict[str, Any]:
    source = _bytes(raw)
    value = loads_strict(source, max_bytes=MAX_INPUT_BYTES)
    allowed = {
        "bomFormat", "specVersion", "serialNumber", "version", "metadata", "components",
        "services", "dependencies", "vulnerabilities", "compositions", "properties",
        "formulation", "annotations", "signature", "externalReferences",
    }
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValidationError("CycloneDX top-level fields are invalid")
    if value.get("bomFormat") != "CycloneDX":
        raise ValidationError("CycloneDX bomFormat is required")
    spec = value.get("specVersion")
    if not isinstance(spec, str) or re.fullmatch(r"1\.[3-9]", spec) is None:
        raise ValidationError("unsupported CycloneDX specVersion")
    if not isinstance(artifact_name, str) or not artifact_name or len(artifact_name) > 256:
        raise ValidationError("artifact_name must be 1 to 256 characters")
    if not isinstance(artifact_digest, str) or SHA256_RE.fullmatch(artifact_digest) is None:
        raise ValidationError("artifact_digest must be a lowercase SHA-256 digest")
    components = value.get("components", [])
    if not isinstance(components, list) or len(components) > MAX_RECORDS:
        raise ValidationError("CycloneDX components exceed bounds")
    references: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise ValidationError("CycloneDX component must be an object")
        reference = component.get("bom-ref")
        if reference is not None:
            if not isinstance(reference, str) or not reference or len(reference) > 512 or reference in references:
                raise ValidationError("CycloneDX bom-ref must be unique and bounded")
            references.add(reference)
    payload = {
        "format": "cyclonedx-json",
        "document_digest": sha256_hex(source),
        "artifact_name": artifact_name,
        "artifact_digest": artifact_digest,
        "component_count": len(components),
    }
    return _document("cyclonedx-json", source, [{"kind": "sbom", "payload": payload}], summary={"component_count": len(components), "spec_version": spec})


def normalize_bundle(documents: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    normalized: list[dict[str, Any]] = []
    for index, document in enumerate(documents):
        if index >= 100:
            raise ValidationError("normalized bundle may contain at most 100 documents")
        try:
            value = loads_strict(canonical_json(dict(document)), max_bytes=MAX_INPUT_BYTES)
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise ValidationError("normalized bundle document is not bounded JSON") from exc
        required = {"schema_version", "adapter", "source_kind", "trust_level", "source_digest", "records"}
        if not isinstance(value, dict) or not required.issubset(value) or set(value) - (required | {"summary"}):
            raise ValidationError("normalized bundle document fields are invalid")
        if value["schema_version"] != NORMALIZED_SCHEMA or value["source_kind"] != "supplied" or value["trust_level"] != "self_declared":
            raise ValidationError("normalized bundle document trust boundary is invalid")
        if not isinstance(value["source_digest"], str) or SHA256_RE.fullmatch(value["source_digest"]) is None:
            raise ValidationError("normalized bundle source digest is invalid")
        if not isinstance(value["records"], list) or not value["records"] or len(value["records"]) > MAX_RECORDS:
            raise ValidationError("normalized bundle records are invalid")
        normalized.append(value)
    if not normalized:
        raise ValidationError("normalized bundle requires at least one document")
    body = {
        "schema_version": BUNDLE_SCHEMA,
        "source_kind": "supplied",
        "trust_level": "self_declared",
        "documents": normalized,
    }
    body["bundle_digest"] = object_digest(body)
    if len(canonical_json(body)) > MAX_INPUT_BYTES:
        raise ValidationError("normalized bundle exceeds 2 MiB")
    return body
