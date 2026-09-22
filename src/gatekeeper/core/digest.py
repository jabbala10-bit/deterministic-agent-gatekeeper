"""Domain-separated SHA-256 over canonical JSON.

The tag keeps hashes of different kinds of object apart: an action and a snapshot that happen to
serialise identically still get different digests."""

from __future__ import annotations

import hashlib
from typing import Any

from .strictjson import jcs


def digest(tag: str, value: Any) -> str:
    if not tag.isascii() or "\x00" in tag:
        raise ValueError("digest tags are ASCII without NUL")
    hasher = hashlib.sha256()
    hasher.update(tag.encode("ascii"))
    hasher.update(b"\x00")
    hasher.update(jcs(value).encode("utf-8"))
    return "sha256:" + hasher.hexdigest()
