"""URL canonicalisation: parse once, strictly, and pass structure rather than a string.

Most real gate bypasses are representation tricks, and URLs are the richest source of them. The gate
parses with its own strict grammar instead of reusing a convenience parser, so the two can be
compared (tests/test_differential.py). Anything this module cannot canonicalise is refused.

What it deliberately does NOT do: resolve names. DNS is nondeterministic, so `decide()` rules on the
canonical host and the executor pins the resolved address and refuses private space at connect time
(phase 4). A host such as 127.0.0.1.nip.io is therefore an executor problem, not a parser problem.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

import idna

from .errors import Rejection

MAX_URL_LENGTH = 2048
SCHEME_DEFAULT_PORT = {"http": 80, "https": 443}

_URL_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://(?P<authority>[^/?#]*)(?P<path>[^?#]*)"
    r"(?:\?(?P<query>[^#]*))?(?:#(?P<fragment>.*))?\Z",
    re.DOTALL,
)
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
# Real top-level labels are alphabetic or punycode. Requiring that refuses every numeric host
# spelling the OS resolver would accept but `ipaddress` does not, such as 0x7f.0.0.0x1 or 127.1.
_TLD_RE = re.compile(r"(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})\Z")
_PORT_RE = re.compile(r"[0-9]{1,5}\Z")
_NUMERIC_HOST_RE = re.compile(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)\Z")
_HEX = "0123456789ABCDEFabcdef"

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_SUB_DELIMS = frozenset("!$&'()*+,;=")
_PATH_LITERAL = _UNRESERVED | _SUB_DELIMS | frozenset(":@/")
_QUERY_LITERAL = _PATH_LITERAL | frozenset("?")


def _percent_normalise(text: str, allowed: frozenset[str]) -> str:
    """RFC 3986 normalisation: decode only unreserved escapes, upper-case the rest, refuse the
    characters parsers disagree about. %2F stays encoded, so it can never become a path separator."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "%":
            if index + 2 >= len(text) or text[index + 1] not in _HEX or text[index + 2] not in _HEX:
                raise Rejection("invalid_percent_encoding")
            byte = int(text[index + 1:index + 3], 16)
            decoded = chr(byte)
            if decoded in _UNRESERVED:
                out.append(decoded)
            else:
                out.append(f"%{byte:02X}")
            index += 3
            continue
        if char in allowed:
            out.append(char)
        elif ord(char) > 0x7F:
            out.extend(f"%{b:02X}" for b in char.encode("utf-8"))
        else:
            raise Rejection("illegal_character")
        index += 1
    return "".join(out)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4. Runs after unreserved decoding, so %2e%2e%2f is handled too."""
    segments: list[str] = []
    for segment in path.split("/")[1:]:
        if segment == ".":
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def canonical_host(text: str, *, allow_ip: bool = False) -> str:
    """Lower-case ASCII (A-label) host. Raises Rejection for anything ambiguous."""
    if not text:
        raise Rejection("empty_host")
    if text.startswith("["):
        if not allow_ip:
            raise Rejection("ip_literal_not_allowed")
        if not text.endswith("]"):
            raise Rejection("bad_host")
        try:
            return "[" + str(ipaddress.IPv6Address(text[1:-1])) + "]"
        except ValueError:
            raise Rejection("bad_host") from None
    host = unicodedata.normalize("NFC", text)
    if host.endswith("."):
        host = host[:-1]
    try:
        host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        raise Rejection("bad_host") from None
    labels = host.split(".")
    if len(labels) < 2:
        raise Rejection("ip_literal_not_allowed" if _NUMERIC_HOST_RE.match(host) else "bad_host")
    if len(host) > 253:
        raise Rejection("bad_host")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise Rejection("bad_host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not allow_ip:
            raise Rejection("ip_literal_not_allowed")
        return host
    if not _TLD_RE.match(labels[-1]):
        # Numeric or hex final label: the resolver would read this as an address.
        raise Rejection("ip_literal_not_allowed" if _NUMERIC_HOST_RE.match(labels[-1]) else "bad_host")
    return host


def host_suffixes(host: str) -> list[str]:
    """['a.b.example', 'b.example'] for 'a.b.example': every suffix down to two labels.

    Used to hang the resource entity under the suffix entities a bundle allowlists, so a policy can
    allow a domain and its subdomains without string matching. A suffix is only ever a proper
    right-hand part, so customer.example.attacker.test never lands under customer.example."""
    if host.startswith("["):
        return [host]
    labels = host.split(".")
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]


def canonical_path(value: object, *, under: str | None = None) -> str:
    """An absolute POSIX path with dot segments removed and duplicate separators collapsed.

    The gate enforces the sandbox itself rather than trusting the tool to do it, so
    /srv/allowed/../../etc/passwd is refused here, not at the far end."""
    if type(value) is not str:
        raise Rejection("not_text")
    if len(value) > 4096:
        raise Rejection("too_long")
    text = unicodedata.normalize("NFC", value)
    for char in text:
        code = ord(char)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            raise Rejection("control_character")
        if char == "\\":
            raise Rejection("illegal_character")
        if unicodedata.category(char) == "Cn":
            raise Rejection("unassigned_code_point")
    if not text.startswith("/"):
        raise Rejection("path_must_be_absolute")
    collapsed = "/" + "/".join(segment for segment in text.split("/") if segment not in ("", "."))
    path = _remove_dot_segments(collapsed)
    if under is not None and path != under and not path.startswith(under.rstrip("/") + "/"):
        raise Rejection("path_outside_sandbox")
    return path


def canonical_url(value: object, *, schemes: tuple[str, ...], allow_ip: bool = False) -> dict[str, object]:
    if type(value) is not str:
        raise Rejection("not_text")
    if len(value) > MAX_URL_LENGTH:
        raise Rejection("too_long")
    for char in value:
        code = ord(char)
        # Tab, CR and LF are stripped by browser-style parsers and kept by others: refuse them.
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            raise Rejection("control_character")
        if char in " \\":
            raise Rejection("illegal_character")
        if unicodedata.category(char) == "Cn":
            raise Rejection("unassigned_code_point")
    match = _URL_RE.match(unicodedata.normalize("NFC", value))
    if match is None:
        raise Rejection("malformed_url")
    scheme = match.group("scheme").lower()
    if scheme not in schemes:
        raise Rejection("scheme_not_allowed")
    authority = match.group("authority")
    if "@" in authority:
        raise Rejection("credentials_in_url")  # https://trusted.example@evil.example/
    host_part, port_part = authority, None
    if authority.startswith("["):
        closing = authority.find("]")
        if closing == -1:
            raise Rejection("bad_host")
        host_part, rest = authority[:closing + 1], authority[closing + 1:]
        if rest.startswith(":"):
            port_part = rest[1:]
        elif rest:
            raise Rejection("bad_host")
    elif ":" in authority:
        host_part, _, port_part = authority.rpartition(":")
    host = canonical_host(host_part, allow_ip=allow_ip)
    if port_part is None or port_part == "":
        port = SCHEME_DEFAULT_PORT[scheme]
    else:
        if _PORT_RE.match(port_part) is None:
            raise Rejection("bad_port")
        port = int(port_part)
        if not 1 <= port <= 65535:
            raise Rejection("bad_port")
    path = _remove_dot_segments(_percent_normalise(match.group("path") or "", _PATH_LITERAL) or "/")
    query = _percent_normalise(match.group("query") or "", _QUERY_LITERAL)
    # The fragment is never sent to the server, so it is dropped rather than recorded as meaningful.
    return {"host": host, "path": path, "port": port, "query": query, "scheme": scheme}


def rebuild(url: dict[str, object]) -> str:
    """The canonical URL as text, for the executor and for differential tests."""
    scheme, host, port = url["scheme"], url["host"], url["port"]
    authority = f"{host}" if port == SCHEME_DEFAULT_PORT[scheme] else f"{host}:{port}"
    query = f"?{url['query']}" if url["query"] else ""
    return f"{scheme}://{authority}{url['path']}{query}"
