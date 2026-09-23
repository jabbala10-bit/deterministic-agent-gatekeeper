"""Executor-side egress control.

ADR-006 split the SSRF defence in two: `decide()` rules on the canonical host, because DNS is
nondeterministic and has no place in a pure function, and the executor pins the address it actually
resolved and refuses anything that is not public. A name such as 127.0.0.1.nip.io canonicalises
perfectly well and is stopped here, at connect time, which is the only place it can be stopped."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Callable, Iterable

from ..core.manifest import ToolSpec

Resolver = Callable[[str], Iterable[str]]


class EgressRefused(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def system_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise EgressRefused("host_does_not_resolve") from None
    return [info[4][0] for info in infos]


def classify(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "unparseable"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link_local"
    if parsed.is_private:
        return "private"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_reserved or parsed.is_unspecified:
        return "reserved"
    return "public"


def pin_host(host: str, resolver: Resolver = system_resolver) -> str:
    """Resolve once and return the address the request must be sent to, or refuse.

    Every answer has to be public: accepting a public address while a private one is also returned
    would leave the door open to whichever address the tool's own resolver happened to pick."""
    addresses = list(resolver(host))
    if not addresses:
        raise EgressRefused("host_does_not_resolve")
    for address in addresses:
        kind = classify(address)
        if kind != "public":
            raise EgressRefused(f"non_public_address:{kind}")
    return addresses[0]


def egress_pins(tool: ToolSpec, args: dict[str, Any], resolver: Resolver = system_resolver) -> dict[str, str]:
    """Pinned addresses for every URL argument of a canonical action, keyed by host."""
    pins: dict[str, str] = {}
    for name, spec in tool.args.items():
        if spec.kind == "url" and name in args:
            host = args[name]["host"]
            pins[host] = pin_host(host, resolver)
    return pins
