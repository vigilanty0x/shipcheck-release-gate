"""Canonical serialization and hashing primitives."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON; non-finite floats are rejected."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def object_digest(value: Any) -> str:
    return sha256_hex(canonical_json(value))

