"""Deterministic canonical JSON encoding.

Every hash and signature in this project is computed over ``canonical_bytes``
so that any independent verifier reproduces the exact same bytes:

* object keys are sorted by Unicode code point,
* no insignificant whitespace,
* UTF-8, no ASCII escaping,
* integers only (booleans/None allowed, floats rejected),
* ``\\n`` line terminator is *not* part of the encoding (callers add it).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalError(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"non-string key at {path}: {k!r}")
            _check(v, f"{path}.{k}")
        return
    raise CanonicalError(f"unsupported type at {path}: {type(value).__name__}")


def canonical_text(obj: Any) -> str:
    _check(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    return canonical_text(obj).encode("utf-8")


def digest(obj: Any) -> str:
    """``sha256:<hex>`` of the canonical encoding of *obj*."""
    return "sha256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()
