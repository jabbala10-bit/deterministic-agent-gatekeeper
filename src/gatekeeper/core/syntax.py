"""Shared lexical rules. Anything that reaches the policy engine or a record must match one."""

import re

ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
TYPE_RE = re.compile(r"[A-Z][A-Za-z0-9]{0,63}\Z")
TOOL_RE = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){1,3}\Z")
BUNDLE_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
POLICY_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
HASH_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
LOCAL_PART_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}\Z")
DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def matches(pattern: re.Pattern[str], value: object) -> bool:
    return type(value) is str and pattern.match(value) is not None
