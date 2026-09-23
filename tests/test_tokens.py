import pytest

from gatekeeper.shell.tokens import KeyRing, TokenError, TokenPayload

NOW = 1_790_000_000_000
PAYLOAD = TokenPayload("sha256:" + "ab" * 32, NOW + 30_000, 7, "sess-1")


@pytest.fixture(scope="module")
def ring(tmp_path_factory):
    return KeyRing.load_or_create(tmp_path_factory.mktemp("keys") / "gate-key.pem")


def test_a_token_round_trips(ring):
    assert ring.verifier.verify(ring.mint(PAYLOAD), now_ms=NOW).to_json() == PAYLOAD.to_json()


def test_signing_is_deterministic_so_the_ledger_need_not_store_it(ring):
    # Ed25519 (RFC 8032) is deterministic: the same payload and key always give the same signature,
    # so a record of the payload is a record of the token.
    assert ring.mint(PAYLOAD) == ring.mint(PAYLOAD)


def test_a_key_survives_a_restart(tmp_path):
    path = tmp_path / "gate-key.pem"
    first = KeyRing.load_or_create(path)
    assert KeyRing.load_or_create(path).key_id == first.key_id
    assert path.stat().st_mode & 0o777 == 0o600


def test_another_key_cannot_mint_an_acceptable_token(ring, tmp_path):
    other = KeyRing.load_or_create(tmp_path / "other.pem")
    with pytest.raises(TokenError) as err:
        ring.verifier.verify(other.mint(PAYLOAD), now_ms=NOW)
    assert err.value.code == "bad_signature"


@pytest.mark.parametrize("mangle, code", [
    (lambda t: t[:-2] + ("ab" if not t.endswith("ab") else "cd"), "bad_signature"),
    (lambda t: t.replace("dag1", "dag2", 1), "malformed_token"),
    (lambda t: t.split(".")[1], "malformed_token"),
    (lambda t: "", "malformed_token"),
])
def test_mangled_tokens_are_refused(ring, mangle, code):
    with pytest.raises(TokenError) as err:
        ring.verifier.verify(mangle(ring.mint(PAYLOAD)), now_ms=NOW)
    assert err.value.code == code


def test_an_expired_token_is_refused(ring):
    with pytest.raises(TokenError) as err:
        ring.verifier.verify(ring.mint(PAYLOAD), now_ms=PAYLOAD.expires_ms + 1)
    assert err.value.code == "token_expired"


def test_the_payload_must_be_canonical(ring):
    import base64
    import json
    body = json.dumps({"session_id": "sess-1", "reservation": 7, "expires_ms": PAYLOAD.expires_ms,
                       "action_hash": PAYLOAD.action_hash}).encode()  # same fields, wrong order
    signature = ring._private_key.sign(b"dag/token/v1\x00" + body)
    token = "dag1." + base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + \
            base64.urlsafe_b64encode(signature).decode().rstrip("=")
    with pytest.raises(TokenError) as err:
        ring.verifier.verify(token, now_ms=NOW)
    assert err.value.code == "non_canonical_token"
