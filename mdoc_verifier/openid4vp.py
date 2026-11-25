"""OpenID4VP 1.0 over the Digital Credentials API for a single mdoc."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, ClassVar

import cbor2
from jwcrypto import jwe, jwk
from jwcrypto.common import JWException

from mdoc_verifier.annex_c import SESSION_TTL, AnnexCSessionConfig, decode_base64url
from mdoc_verifier.iso_session import generate_session_id
from mdoc_verifier.validation import ECDSA_ALGORITHMS, IssuerTrust, response_validation, verify_response

PROTOCOL = "openid4vp-v1-unsigned"
QUERY_ID = "mdoc"
JWE_ALGORITHM = "ECDH-ES"
JWE_ENCRYPTION = "A128GCM"
COSE_SIGNATURES = [*ECDSA_ALGORITHMS, -8, -19, -53]


def session_transcript(origin: str, nonce: str, public_key: jwk.JWK) -> list:
    thumbprint = decode_base64url(public_key.thumbprint())
    handover = hashlib.sha256(cbor2.dumps([origin, nonce, thumbprint])).digest()
    return [None, None, ["OpenID4VPDCAPIHandover", handover]]


def json_object(data: bytes) -> dict[str, Any]:
    def unique_members(pairs):
        members = dict(pairs)
        if len(members) != len(pairs):
            raise ValueError("Duplicate OpenID4VP JSON member")
        return members

    result = json.loads(data.decode("utf-8"), object_pairs_hook=unique_members)
    if not isinstance(result, dict):
        raise ValueError("Expected an OpenID4VP JSON object")
    return result


def decrypt_presentation(response: str, private_key: jwk.JWK) -> bytes:
    parts = response.split(".", 5)
    if len(parts) != 5 or parts[1] or any(not parts[i] for i in (0, 2, 3, 4)):
        raise ValueError("Expected a compact OpenID4VP JWE")
    if len(parts[0]) > 4096:
        raise ValueError("OpenID4VP JWE header is too large")
    try:
        header = json_object(decode_base64url(parts[0]))
        if (
            header.get("alg") != JWE_ALGORITHM or header.get("enc") != JWE_ENCRYPTION
            or "zip" in header or "crit" in header
            or ("kid" in header and header["kid"] != private_key["kid"])
        ):
            raise ValueError("Unsupported OpenID4VP JWE header")
        ephemeral_key = header.get("epk")
        if (
            not isinstance(ephemeral_key, dict) or ephemeral_key.get("kty") != "EC"
            or ephemeral_key.get("crv") != "P-256" or "d" in ephemeral_key
        ):
            raise ValueError("Expected a public P-256 ephemeral key")
        envelope = jwe.JWE(algs=[JWE_ALGORITHM, JWE_ENCRYPTION])
        envelope.deserialize(response, key=private_key)
        payload = json_object(envelope.payload)
    except (JWException, RecursionError) as exc:
        raise ValueError("Invalid or undecryptable OpenID4VP response") from exc
    vp_token = payload.get("vp_token")
    if "error" in payload or not isinstance(vp_token, dict) or vp_token.keys() != {QUERY_ID}:
        raise ValueError("Expected a VP token for the requested mdoc")
    presentations = vp_token[QUERY_ID]
    if not isinstance(presentations, list) or len(presentations) != 1 or not isinstance(presentations[0], str):
        raise ValueError("Expected one mdoc presentation")
    return decode_base64url(presentations[0])


@dataclass
class OpenId4VpSession:
    protocol: ClassVar[str] = PROTOCOL
    signed_request: ClassVar[bool] = False

    session_id: str
    access_token: str
    config: AnnexCSessionConfig
    origin: str
    nonce: str
    private_key: jwk.JWK | None
    public_key: jwk.JWK
    requested: dict[str, dict[str, bool]]
    expires_at: float = field(default_factory=lambda: time.time() + SESSION_TTL)
    completed: bool = False
    issuer_auth: str = "pending"
    shared_attributes: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_error: str | None = None

    @property
    def validation_status(self) -> dict[str, str]:
        return response_validation(self.issuer_auth)

    def request_object(self) -> dict[str, Any]:
        return {"requests": [{"protocol": PROTOCOL, "data": {
            "response_type": "vp_token",
            "response_mode": "dc_api.jwt",
            "nonce": self.nonce,
            "dcql_query": {"credentials": [{
                "id": QUERY_ID,
                "format": "mso_mdoc",
                "meta": {"doctype_value": self.config.doc_type},
                "claims": [
                    {"path": [namespace, claim], "intent_to_retain": retain}
                    for namespace, claims in self.requested.items() for claim, retain in claims.items()
                ],
            }]},
            "client_metadata": {
                "jwks": {"keys": [self.public_key.export_public(as_dict=True)]},
                "encrypted_response_enc_values_supported": [JWE_ENCRYPTION],
                "vp_formats_supported": {"mso_mdoc": {
                    "issuerauth_alg_values": COSE_SIGNATURES,
                    "deviceauth_alg_values": COSE_SIGNATURES,
                }},
            },
        }}]}

    def handle_response(self, response: str, trust: IssuerTrust) -> None:
        if self.private_key is None:
            raise ValueError("Session already completed")
        plaintext = decrypt_presentation(response, self.private_key)
        transcript = session_transcript(self.origin, self.nonce, self.public_key)
        claims = verify_response(plaintext, transcript, self.config.doc_type, self.requested, trust)
        if any(claims.get(namespace, {}).keys() != requested.keys()
               for namespace, requested in self.requested.items()):
            raise ValueError("The mdoc is missing a claim required by the OpenID4VP request")
        self.shared_attributes = claims
        self.issuer_auth = "unverified" if trust.inspection_mode else "verified"
        self.completed = True
        self.private_key = None
        self.last_error = None


def new_openid4vp_session(config: AnnexCSessionConfig, origin: str) -> OpenId4VpSession:
    requested = config.requested_elements()
    if not requested:
        raise ValueError("Select at least one claim")
    private_key = jwk.JWK.generate(
        kty="EC", crv="P-256", alg=JWE_ALGORITHM, use="enc", kid=secrets.token_urlsafe(16)
    )
    return OpenId4VpSession(
        session_id=generate_session_id(), access_token=secrets.token_urlsafe(32),
        config=config, origin=origin, nonce=secrets.token_urlsafe(32),
        private_key=private_key, public_key=private_key.public(), requested=requested,
    )
