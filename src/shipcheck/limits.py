"""Strict, bounded JSON parsing for untrusted evidence."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from .errors import ValidationError

MAX_JSON_BYTES = 1_048_576
MAX_DEPTH = 32
MAX_NODES = 10_000
MAX_STRING = 16_384
MAX_LIST = 2_000
MAX_OBJECT = 2_000


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValidationError(f"non-finite JSON number is forbidden: {value}")


def _parse_int(value: str) -> int:
    if len(value.lstrip("-")) > 128:
        raise ValidationError("JSON integer exceeds 128 digits")
    try:
        return int(value)
    except (ValueError, OverflowError) as exc:
        raise ValidationError("invalid JSON integer") from exc


def _parse_float(value: str) -> float:
    if len(value) > 128:
        raise ValidationError("JSON number exceeds 128 characters")
    try:
        result = float(value)
    except (ValueError, OverflowError) as exc:
        raise ValidationError("invalid JSON number") from exc
    if not math.isfinite(result):
        raise ValidationError("non-finite JSON number is forbidden")
    return result


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _validate_tree(root: Any) -> None:
    stack: list[tuple[Any, int]] = [(root, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ValidationError(f"JSON exceeds {MAX_NODES} nodes")
        if depth > MAX_DEPTH:
            raise ValidationError(f"JSON exceeds depth {MAX_DEPTH}")
        if isinstance(value, str):
            if len(value) > MAX_STRING:
                raise ValidationError(f"JSON string exceeds {MAX_STRING} characters")
            if _has_surrogate(value):
                raise ValidationError("JSON strings must not contain surrogate code points")
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise ValidationError("non-finite JSON number is forbidden")
        elif isinstance(value, list):
            if len(value) > MAX_LIST:
                raise ValidationError(f"JSON array exceeds {MAX_LIST} items")
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, dict):
            if len(value) > MAX_OBJECT:
                raise ValidationError(f"JSON object exceeds {MAX_OBJECT} keys")
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValidationError("JSON keys must be strings")
                if len(key) > 256:
                    raise ValidationError("JSON key exceeds 256 characters")
                if _has_surrogate(key):
                    raise ValidationError("JSON keys must not contain surrogate code points")
                stack.append((item, depth + 1))
        elif value is not None and not isinstance(value, (bool, int)):
            raise ValidationError(f"unsupported JSON type: {type(value).__name__}")


def loads_strict(data: bytes | str, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    try:
        raw = data.encode("utf-8", errors="strict") if isinstance(data, str) else data
    except UnicodeEncodeError as exc:
        raise ValidationError("JSON must be valid Unicode") from exc
    if len(raw) > max_bytes:
        raise ValidationError(f"JSON exceeds {max_bytes} bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except UnicodeDecodeError as exc:
        raise ValidationError("JSON must be valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON at line {exc.lineno}, column {exc.colno}") from exc
    except RecursionError as exc:
        raise ValidationError("JSON nesting exceeds parser limits") from exc
    except (TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError("invalid JSON value") from exc
    _validate_tree(value)
    return value


def load_json_file(path: str | Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    from .secureio import read_regular_file

    return loads_strict(read_regular_file(path, max_bytes=max_bytes), max_bytes=max_bytes)
