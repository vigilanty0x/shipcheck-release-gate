"""Deterministic JSON, Markdown, HTML, and SARIF decision reports."""

from __future__ import annotations

import html
import json
from typing import Any

from .canonical import canonical_json
from .models import Decision, ReleaseEvidence
from .redaction import redact


def report_data(decision: Decision, evidence: ReleaseEvidence | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"report_schema": "shipcheck/report-v1", "decision": decision.to_dict()}
    if evidence is not None:
        data["evidence_summary"] = {
            "release_id": evidence.release_id,
            "candidate": evidence.candidate.to_dict(),
            "candidate_digest": evidence.candidate.digest,
            "evidence_digest": evidence.digest,
            "observation_count": len(evidence.observations),
            "source_kinds": sorted({item.source_kind for item in evidence.observations}),
            "observation_kinds": sorted({item.kind for item in evidence.observations}),
        }
    return redact(data)


def render_json(decision: Decision, evidence: ReleaseEvidence | None = None) -> bytes:
    return canonical_json(report_data(decision, evidence)) + b"\n"


def _md(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def render_markdown(decision: Decision, evidence: ReleaseEvidence | None = None) -> bytes:
    lines = [
        "# Shipcheck release decision", "", f"**Outcome:** `{_md(decision.outcome)}`  ",
        f"**Release:** `{_md(decision.release_id)}`  ", f"**Candidate:** `{decision.candidate_digest}`  ",
        f"**Policy:** `{_md(decision.policy_id)}` (`{decision.policy_digest}`)  ",
        f"**Evidence:** `{decision.evidence_digest}`  ",
        f"**Assurance profile:** `{decision.assurance_profile}`  ",
        f"**Production ready:** `{str(decision.production_ready).lower()}`", "", "## Gates", "",
        "| Gate | Status | Reason | Message |", "|---|---:|---|---|",
    ]
    for gate in decision.gates:
        suffix = f" (waived by {_md(gate.waived_by)})" if gate.waived_by else ""
        lines.append(f"| {_md(gate.gate)} | {_md(gate.status)}{suffix} | {_md(gate.reason_code)} | {_md(gate.message)} |")
    if evidence is not None:
        lines.extend(["", "## Evidence boundary", "", f"- Observations: {len(evidence.observations)}", f"- Source kinds: {', '.join(_md(x) for x in sorted({i.source_kind for i in evidence.observations}))}", "- Integrity note: configured local MACs are not public signatures or non-repudiation."])
    lines.extend(["", "Shipcheck decides and records. It does not merge, execute builds, deploy, or mutate a forge.", ""])
    return "\n".join(lines).encode("utf-8")


def render_html(decision: Decision, evidence: ReleaseEvidence | None = None) -> bytes:
    rows = []
    for gate in decision.gates:
        status = html.escape(gate.status)
        waived = f"<small>waived by {html.escape(gate.waived_by)}</small>" if gate.waived_by else ""
        rows.append(f"<tr><td>{html.escape(gate.gate)}</td><td><span class='status {status}'>{status}</span>{waived}</td><td><code>{html.escape(gate.reason_code)}</code></td><td>{html.escape(gate.message)}</td></tr>")
    source = ""
    if evidence is not None:
        kinds = ", ".join(html.escape(x) for x in sorted({item.source_kind for item in evidence.observations}))
        source = f"<p><b>{len(evidence.observations)}</b> observations · source kinds: {kinds}</p>"
    document = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Shipcheck {html.escape(decision.assurance_profile)} {html.escape(decision.outcome)}</title><style>body{{font:15px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem;color:#172033}}h1{{letter-spacing:-.03em}}.hero{{border:1px solid #ccd4e0;border-radius:16px;padding:1.2rem;background:#f8fafc}}table{{border-collapse:collapse;width:100%;margin-top:1.5rem}}td,th{{text-align:left;border-bottom:1px solid #dde3ec;padding:.7rem}}code{{font-size:.85em}}.status{{font-weight:700;margin-right:.4rem}}.pass{{color:#087a43}}.fail{{color:#b42318}}.unknown{{color:#8a5200}}small{{display:block}}footer{{margin-top:2rem;color:#556}}</style></head><body><main><div class='hero'><h1>{html.escape(decision.assurance_profile)} / {html.escape(decision.outcome)}</h1><p>Production ready: <strong>{str(decision.production_ready).lower()}</strong></p><p>Release <code>{html.escape(decision.release_id)}</code></p><p>Candidate <code>{decision.candidate_digest}</code></p>{source}</div><table><thead><tr><th>Gate</th><th>Status</th><th>Reason</th><th>Message</th></tr></thead><tbody>{''.join(rows)}</tbody></table></main><footer>Shipcheck decides and records; it never merges or deploys. Local MAC ≠ public signature.</footer></body></html>"""
    return document.encode("utf-8")


def render_sarif(decision: Decision, evidence: ReleaseEvidence | None = None) -> bytes:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level = {"fail": "error", "unknown": "warning", "warn": "note", "pass": "none"}
    for gate in decision.gates:
        rules.setdefault(gate.reason_code, {"id": gate.reason_code, "name": gate.gate, "shortDescription": {"text": gate.message}})
        if gate.status != "pass":
            results.append({"ruleId": gate.reason_code, "level": level.get(gate.status, "warning"), "message": {"text": gate.message}, "properties": {"gate": gate.gate, "status": gate.status, "evidenceIds": list(gate.evidence_ids), "waivedBy": gate.waived_by}})
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Shipcheck", "semanticVersion": "0.1.0", "informationUri": "https://github.com/vigilanty0x/shipcheck-release-gate", "rules": list(rules.values())}}, "results": results, "properties": {"outcome": decision.outcome, "assurance_profile": decision.assurance_profile, "production_ready": decision.production_ready, "candidate_digest": decision.candidate_digest, "evidence_digest": decision.evidence_digest, "policy_digest": decision.policy_digest}}]}
    return canonical_json(redact(sarif)) + b"\n"


RENDERERS = {"json": render_json, "markdown": render_markdown, "html": render_html, "sarif": render_sarif}


def render(decision: Decision, format_name: str, evidence: ReleaseEvidence | None = None) -> bytes:
    try:
        renderer = RENDERERS[format_name]
    except KeyError as exc:
        raise ValueError(f"unsupported report format: {format_name}") from exc
    return renderer(decision, evidence)
