"""ISO/IEC TS 18013-7:2025 Annex C, over the Digital Credentials API."""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from pyhpke.exceptions import PyHPKEError

from mdoc_verifier.iso_session import (
    PHOTO_ID_DOCTYPE,
    build_cose_key,
    default_requested_elements,
    export_public_key_hex as export_public_key_hex,
    generate_session_id,
)
from mdoc_verifier.validation import (
    IssuerTrust, decode_cbor, response_validation, sign_reader_auth, tagged_bytes, verify_response,
)

PROTOCOL = "org-iso-mdoc"
SESSION_TTL = 300
HPKE_SUITE = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_base64url(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Expected unpadded base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64url(decoded) != value:
        raise ValueError("Invalid base64url")
    return decoded


def session_transcript(encryption_info: str, origin: str) -> list:
    if not origin:
        raise ValueError("Annex C requires a verifier origin")
    handover = hashlib.sha256(cbor2.dumps([encryption_info, origin])).digest()
    return [None, None, ["dcapi", handover]]


@dataclass(frozen=True)
class ReaderIdentity:
    key: ec.EllipticCurvePrivateKey
    chain: list[x509.Certificate]


@dataclass
class AnnexCSessionConfig:
    verifier_id: str
    doc_type: str = PHOTO_ID_DOCTYPE
    photoid_elements: list[str] = field(default_factory=list)
    mdl_elements: list[str] = field(default_factory=list)
    custom_attributes: list[str] = field(default_factory=list)
    custom_photoid_attributes: list[str] = field(default_factory=list)
    custom_mdl_attributes: list[str] = field(default_factory=list)
    custom_namespace: str = ""
    custom_namespace_attributes: list[str] = field(default_factory=list)


def build_device_request(config: AnnexCSessionConfig, requested: dict[str, dict[str, bool]],
                         transcript: list, identity: ReaderIdentity | None) -> bytes:
    items = tagged_bytes(cbor2.dumps({"docType": config.doc_type, "nameSpaces": requested}))
    request = {"version": "1.0", "docRequests": [{"itemsRequest": items}]}
    if identity is not None:
        info = tagged_bytes(cbor2.dumps({"useCases": [{"mandatory": True, "documentSets": [[0]]}]}))
        authentication = tagged_bytes(cbor2.dumps(["ReaderAuthenticationAll", transcript, [items], info]))
        request.update(
            version="1.1",
            deviceRequestInfo=info,
            readerAuthAll=[sign_reader_auth(identity.key, identity.chain, cbor2.dumps(authentication))],
        )
    return cbor2.dumps(request)


def decrypt_envelope(response: str, recipient: ec.EllipticCurvePrivateKey, transcript: list) -> bytes:
    try:
        envelope = decode_cbor(decode_base64url(response))
    except cbor2.CBORError as exc:
        raise ValueError("Malformed Annex C response envelope") from exc
    if not isinstance(envelope, list) or len(envelope) != 2 or envelope[0] != "dcapi":
        raise ValueError("Expected a dcapi response envelope")
    fields = envelope[1]
    if not isinstance(fields, dict) or fields.keys() != {"enc", "cipherText"}:
        raise ValueError("Malformed Annex C response fields")
    enc, ciphertext = fields["enc"], fields["cipherText"]
    if not isinstance(enc, bytes) or len(enc) != 65 or enc[0] != 4:
        raise ValueError("Invalid HPKE encapsulated key")
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise ValueError("Invalid HPKE ciphertext")
    key = KEMKey.from_pem(recipient.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    try:
        return HPKE_SUITE.create_recipient_context(enc, key, info=cbor2.dumps(transcript)).open(ciphertext)
    except (PyHPKEError, ValueError) as exc:
        raise ValueError("Annex C decryption failed for this session and origin") from exc


@dataclass
class AnnexCSessionState:
    session_id: str
    access_token: str
    config: AnnexCSessionConfig
    origin: str
    recipient_private_key: ec.EllipticCurvePrivateKey | None
    recipient_public_key: ec.EllipticCurvePublicKey
    request_nonce: bytes
    device_request: bytes
    encryption_info: str
    requested: dict[str, dict[str, bool]]
    signed_request: bool
    expires_at: float = field(default_factory=lambda: time.time() + SESSION_TTL)
    completed: bool = False
    issuer_auth: str = "pending"
    shared_attributes: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_error: str | None = None

    @property
    def validation_status(self) -> dict[str, str]:
        return response_validation(self.issuer_auth)

    def request_object(self) -> dict[str, Any]:
        return {"requests": [{
            "protocol": PROTOCOL,
            "data": {"deviceRequest": b64url(self.device_request), "encryptionInfo": self.encryption_info},
        }]}

    def handle_response(self, response: str, trust: IssuerTrust) -> None:
        if self.recipient_private_key is None or self.completed:
            raise ValueError("Session already completed")
        transcript = session_transcript(self.encryption_info, self.origin)
        plaintext = decrypt_envelope(response, self.recipient_private_key, transcript)
        self.shared_attributes = verify_response(plaintext, transcript, self.config.doc_type, self.requested, trust)
        self.issuer_auth = "unverified" if trust.inspection_mode else "verified"
        self.completed = True
        self.recipient_private_key = None
        self.last_error = None


def new_annex_c_session(config: AnnexCSessionConfig, origin: str,
                        identity: ReaderIdentity | None = None) -> AnnexCSessionState:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    nonce = secrets.token_bytes(16)
    encryption_info = b64url(cbor2.dumps(["dcapi", {"nonce": nonce, "recipientPublicKey": build_cose_key(public_key)}]))
    transcript = session_transcript(encryption_info, origin)
    requested = default_requested_elements(
        config.doc_type, config.photoid_elements, config.mdl_elements, config.custom_attributes,
        config.custom_photoid_attributes, config.custom_mdl_attributes, config.custom_namespace,
        config.custom_namespace_attributes, False,
    )
    if not requested:
        raise ValueError("Select at least one claim")
    return AnnexCSessionState(
        session_id=generate_session_id(),
        access_token=secrets.token_urlsafe(32),
        config=config,
        origin=origin,
        recipient_private_key=private_key,
        recipient_public_key=public_key,
        request_nonce=nonce,
        device_request=build_device_request(config, requested, transcript, identity),
        encryption_info=encryption_info,
        requested=requested,
        signed_request=identity is not None,
    )
