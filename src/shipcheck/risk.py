"""Deterministic, versioned diff-risk scoring."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import unicodedata
from typing import Any, Mapping

from .errors import ValidationError
from .models import require_bool, require_int, require_keys, require_string

RISK_VERSION = "shipcheck/diff-risk-v1"


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: int
    reasons: tuple[Mapping[str, Any], ...]
    file_count: int
    changed_lines: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": RISK_VERSION,
            "score": self.score,
            "file_count": self.file_count,
            "changed_lines": self.changed_lines,
            "reasons": [dict(item) for item in self.reasons],
        }


def normalize_repo_path(raw: Any) -> str:
    value = require_string(raw, "diff.files[].path", limit=512)
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ValidationError("paths must already be NFC-normalized")
    if "\\" in value or "\x00" in value or ":" in value or value.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError("diff paths must be relative portable POSIX paths")
    path = PurePosixPath(value)
    if value in {".", ".."} or any(part in {"", ".", ".."} for part in path.parts):
        raise ValidationError("diff paths must not contain empty, dot, or parent segments")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    for part in path.parts:
        if part.endswith((".", " ")) or part.split(".", 1)[0].upper() in reserved:
            raise ValidationError("path contains a Windows-reserved or ambiguous segment")
    return path.as_posix()


def score_diff(payload: Mapping[str, Any]) -> RiskAssessment:
    require_keys(payload, "diff payload", {"version", "files"}, {"claimed_score"})
    if payload["version"] != RISK_VERSION:
        raise ValidationError("unsupported diff risk version")
    files = payload["files"]
    if not isinstance(files, list) or len(files) > 2_000:
        raise ValidationError("diff.files must contain at most 2,000 entries")
    seen: set[str] = set()
    changed_lines = 0
    binary_count = 0
    paths: list[str] = []
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValidationError(f"diff.files[{index}] must be an object")
        require_keys(item, f"diff.files[{index}]", {"path", "status", "additions", "deletions", "binary"})
        path = normalize_repo_path(item["path"])
        collision_key = path.casefold()
        if collision_key in seen:
            raise ValidationError(f"duplicate diff path: {path}")
        seen.add(collision_key)
        paths.append(path)
        status = require_string(item["status"], f"diff.files[{index}].status", limit=16)
        if status not in {"added", "modified", "deleted", "renamed"}:
            raise ValidationError(f"invalid diff status: {status}")
        additions = require_int(item["additions"], f"diff.files[{index}].additions", maximum=10_000_000)
        deletions = require_int(item["deletions"], f"diff.files[{index}].deletions", maximum=10_000_000)
        if changed_lines + additions + deletions > 100_000_000:
            raise ValidationError("diff changed-line count exceeds 100,000,000")
        changed_lines += additions + deletions
        binary_count += int(require_bool(item["binary"], f"diff.files[{index}].binary"))

    score = 0
    reasons: list[Mapping[str, Any]] = []

    def add(code: str, points: int, detail: str) -> None:
        nonlocal score
        score += points
        reasons.append({"code": code, "points": points, "detail": detail})

    if files:
        points = min(20, max(1, len(files) // 5 + 1))
        add("CHANGE_VOLUME_FILES", points, f"{len(files)} changed files")
    if changed_lines:
        points = min(20, max(1, changed_lines // 250 + 1))
        add("CHANGE_VOLUME_LINES", points, f"{changed_lines} changed lines")
    lowered = [path.casefold() for path in paths]
    categories = [
        ("WORKFLOW_CHANGE", 20, lambda p: p.startswith(".github/workflows/") or p.startswith(".gitlab-ci")),
        ("MIGRATION_CHANGE", 18, lambda p: "migration" in p or "/migrations/" in f"/{p}"),
        ("AUTH_CHANGE", 18, lambda p: any(word in p for word in ("auth", "permission", "rbac", "oauth"))),
        ("SECRET_BOUNDARY_CHANGE", 20, lambda p: any(word in p for word in ("secret", "credential", "keyring"))),
        ("DEPENDENCY_CHANGE", 12, lambda p: p.endswith((".lock", "requirements.txt", "pyproject.toml", "package.json"))),
        ("PUBLIC_API_CHANGE", 10, lambda p: any(word in p for word in ("/api/", "schema", "openapi"))),
    ]
    for code, points, predicate in categories:
        matched = [path for path in lowered if predicate(path)]
        if matched:
            add(code, points, f"{len(matched)} matching path(s)")
    if binary_count:
        add("BINARY_CHANGE", min(10, binary_count * 2), f"{binary_count} binary file(s)")
    score = min(100, score)
    claimed = payload.get("claimed_score")
    if claimed is not None and require_int(claimed, "diff.claimed_score", maximum=100) != score:
        raise ValidationError("diff.claimed_score does not match deterministic score")
    return RiskAssessment(score, tuple(reasons), len(files), changed_lines)
