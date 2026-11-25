from __future__ import annotations

import hashlib
import json
import os
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from fastapi.testclient import TestClient
from jwcrypto import jwk

from mdoc_verifier.annex_c import decode_base64url
from mdoc_verifier.iso_session import MDL_DOCTYPE, MDL_NAMESPACE, PHOTO_ID_DOCTYPE, PHOTO_ID_NAMESPACE
from mdoc_verifier.openid4vp import session_transcript
from server.main import app
from smoke_annex_c import ORIGIN, b64url, demo_issuer, device_response

PROTOCOL = "openid4vp-v1-unsigned"


def published_transcript_vector() -> None:
    # OpenID4VP 1.0 Appendix B.2.6.2 example.
    key = jwk.JWK(
        kty="EC", crv="P-256", use="enc", alg="ECDH-ES", kid="1",
        x="DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
        y="XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
    )
    transcript = session_transcript(
        "https://example.com", "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA", key
    )
    assert cbor2.dumps(transcript[2]).hex() == (
        "82764f70656e4944345650444341504948616e646f7665725820"
        "fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
    )


def encrypt_wallet_response(payload: dict, recipient: dict) -> str:
    """Create a compact JWE independently with RFC 7518 primitives for the fixture."""
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    numbers = ephemeral.public_key().public_numbers()
    protected = b64url(json.dumps({
        "alg": "ECDH-ES", "enc": "A128GCM", "kid": recipient["kid"],
        "epk": {"kty": "EC", "crv": "P-256",
                "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))},
    }).encode())
    public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b"\x04" + decode_base64url(recipient["x"]) + decode_base64url(recipient["y"])
    )
    shared = ephemeral.exchange(ec.ECDH(), public)
    other_info = b"\x00\x00\x00\x07A128GCM" + bytes(8) + (128).to_bytes(4, "big")
    key = ConcatKDFHash(hashes.SHA256(), 16, other_info).derive(shared)
    iv = os.urandom(12)
    combined = AESGCM(key).encrypt(iv, json.dumps(payload).encode(), protected.encode())
    return ".".join([protected, "", b64url(iv), b64url(combined[:-16]), b64url(combined[-16:])])


def exercise_openid4vp(client: TestClient, issuer, expected_auth: str, doc_type: str) -> None:
    namespace = MDL_NAMESPACE if doc_type == MDL_DOCTYPE else PHOTO_ID_NAMESPACE
    claims_field = "mdl_elements" if doc_type == MDL_DOCTYPE else "photoid_elements"
    creation = client.post("/dc/session", json={
        "protocol": PROTOCOL, "doc_type": doc_type, claims_field: ["family_name"],
    })
    creation.raise_for_status()
    session = creation.json()
    entry, = session["request"]["requests"]
    assert entry["protocol"] == PROTOCOL
    data = entry["data"]
    assert data["response_mode"] == "dc_api.jwt"
    assert "client_id" not in data
    assert data["dcql_query"]["credentials"] == [{
        "id": "mdoc", "format": "mso_mdoc", "meta": {"doctype_value": doc_type},
        "claims": [{"path": [namespace, "family_name"], "intent_to_retain": False}],
    }]
    public, = data["client_metadata"]["jwks"]["keys"]
    assert "d" not in public
    thumbprint = hashlib.sha256(json.dumps(
        {name: public[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"), sort_keys=True,
    ).encode()).digest()

    def wallet_transcript(nonce, origin=ORIGIN, key_thumbprint=thumbprint):
        digest = hashlib.sha256(cbor2.dumps([origin, nonce, key_thumbprint])).digest()
        return [None, None, ["OpenID4VPDCAPIHandover", digest]]

    headers = {"Authorization": "Bearer " + session["access_token"]}
    response_url, status_url = session["response_url"], session["status_url"]
    assert client.get(status_url).status_code == 404

    def submit(payload, protocol=PROTOCOL):
        encrypted = encrypt_wallet_response(payload, public)
        return client.post(response_url, json={"protocol": protocol, "data": {"response": encrypted}}, headers=headers)

    for transcript in (
        wallet_transcript(data["nonce"], origin="https://other.example"),
        wallet_transcript(data["nonce"], key_thumbprint=bytes(32)),
        wallet_transcript("a-different-request"),
    ):
        payload = {"vp_token": {"mdoc": [b64url(device_response(issuer, transcript, doc_type=doc_type))]}}
        assert submit(payload).status_code == 422
    presentation = device_response(issuer, wallet_transcript(data["nonce"]), doc_type=doc_type)
    good_payload = {"vp_token": {"mdoc": [b64url(presentation)]}}
    assert submit(good_payload, protocol="org-iso-mdoc").status_code == 422
    assert submit({"vp_token": {"other": good_payload["vp_token"]["mdoc"]}}).status_code == 422
    assert not client.get(status_url, headers=headers).json()["response_received"]

    result = submit(good_payload)
    result.raise_for_status()
    assert result.json()["shared_attributes"] == {namespace: {"family_name": "Doe"}}
    status = client.get(status_url, headers=headers).json()
    assert status["response_received"] and status["last_error"] is None
    assert result.json()["validation"]["issuer_auth"] == status["validation"]["issuer_auth"] == expected_auth
    assert submit(good_payload).status_code == 409



def main() -> None:
    published_transcript_vector()
    with TemporaryDirectory() as temp:
        issuer = demo_issuer(temp)
        for ca, expected_auth in ((issuer[2], "verified"), ("", "unverified")):
            with patch.dict(os.environ, {
                "MDOC_PUBLIC_ORIGIN": ORIGIN, "MDOC_ISSUER_CA_PEM": ca,
                "MDOC_ISSUER_CRL_PEM": "", "MDOC_ALLOW_UNTRUSTED_ISSUER": "true",
            }):
                with TestClient(app, base_url=ORIGIN) as client:
                    for doc_type in (PHOTO_ID_DOCTYPE, MDL_DOCTYPE):
                        exercise_openid4vp(client, issuer, expected_auth, doc_type)
    print("OpenID4VP published transcript vector, encrypted presentation, and inspection passed")


if __name__ == "__main__":
    main()
