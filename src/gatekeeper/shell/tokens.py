"""Execution tokens: what turns "check equals execute" from a promise into a mechanism.

A token is an Ed25519 signature over the canonical payload {action_hash, expires_ms, reservation,
session_id}. Ed25519 is deterministic (RFC 8032), so the signature is a pure function of the payload
and the key: the ledger records the payload and never stores the signature, and anyone holding the
public key can re-derive it byte for byte from the record.

A token proves the gate allowed this exact canonical action in this session. It is single use
because the reservation it names is closed when the action settles, and it expires so that a
forgotten one cannot be redeemed later."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256, Hash

from ..core.strictjson import MAX_SAFE_INT, StrictJSONError, jcs, loads_strict
from ..core.syntax import HASH_RE, ID_RE, matches

PREFIX = "dag1"
DOMAIN = b"dag/token/v1\x00"
SIGNATURE_DOMAIN = b"dag/event-sig/v1\x00"


class TokenError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class TokenPayload:
    action_hash: str
    expires_ms: int
    reservation: int
    session_id: str

    def __post_init__(self) -> None:
        if not matches(HASH_RE, self.action_hash) or not matches(ID_RE, self.session_id):
            raise TokenError("bad_token_payload")
        if type(self.expires_ms) is not int or not 0 <= self.expires_ms <= MAX_SAFE_INT:
            raise TokenError("bad_token_payload")
        if type(self.reservation) is not int or self.reservation < 0:
            raise TokenError("bad_token_payload")

    def to_json(self) -> dict[str, Any]:
        return {"action_hash": self.action_hash, "expires_ms": self.expires_ms,
                "reservation": self.reservation, "session_id": self.session_id}

    @classmethod
    def from_json(cls, obj: Any) -> "TokenPayload":
        if type(obj) is not dict or sorted(obj) != ["action_hash", "expires_ms", "reservation", "session_id"]:
            raise TokenError("bad_token_payload")
        return cls(obj["action_hash"], obj["expires_ms"], obj["reservation"], obj["session_id"])

    def signing_input(self) -> bytes:
        return DOMAIN + jcs(self.to_json()).encode("utf-8")


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception:
        raise TokenError("malformed_token") from None


_b64, _unb64 = b64, unb64


def fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    digest = Hash(SHA256())
    digest.update(raw)
    return "ed25519:" + digest.finalize().hex()[:16]


class Verifier:
    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key
        self.key_id = fingerprint(public_key)

    def verify_bytes(self, signature: bytes, message: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
        except InvalidSignature:
            return False
        return True

    def verify(self, token: str, *, now_ms: int) -> TokenPayload:
        if type(token) is not str:
            raise TokenError("malformed_token")
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            raise TokenError("malformed_token")
        body, signature = _unb64(parts[1]), _unb64(parts[2])
        try:
            self._public_key.verify(signature, DOMAIN + body)
        except (InvalidSignature, UnicodeDecodeError, TypeError):
            raise TokenError("bad_signature") from None
        try:
            payload = TokenPayload.from_json(loads_strict(body.decode("utf-8"), max_bytes=4096))
        except StrictJSONError:
            raise TokenError("malformed_token") from None
        if jcs(payload.to_json()).encode("utf-8") != body:
            raise TokenError("non_canonical_token")
        if now_ms > payload.expires_ms:
            raise TokenError("token_expired")
        return payload


class KeyRing:
    """The gate's signing key. Generated once and kept next to the sessions it authorises."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self.verifier = Verifier(private_key.public_key())
        self.key_id = self.verifier.key_id

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyRing":
        """A key derived from a fixed seed, for fixtures that must be byte-identical every time.
        Never for anything that authorises real work."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def load_or_create(cls, path: str | Path) -> "KeyRing":
        target = Path(path)
        if target.exists():
            return cls(serialization.load_pem_private_key(target.read_bytes(), password=None))
        key = Ed25519PrivateKey.generate()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        target.chmod(0o600)
        return cls(key)

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def mint(self, payload: TokenPayload) -> str:
        body = jcs(payload.to_json()).encode("utf-8")
        signature = self._private_key.sign(DOMAIN + body)
        return f"{PREFIX}.{_b64(body)}.{_b64(signature)}"
