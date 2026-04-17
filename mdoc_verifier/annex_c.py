"""Minimal Digital Credentials API / Annex C support for PhotoID demo flows.

This module intentionally focuses on a narrow MVP:
- PhotoID requests only (`org.iso.23220.photoid.1`)
- server-generated `deviceRequest` and `encryptionInfo`
- demo-grade HPKE-style envelope for encrypted responses
- extraction of issuer-signed attributes for UI/debugging

It is suitable for local experimentation and shaping a future verifier API, but
it does not yet implement issuer trust or device authentication validation.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mdoc_verifier.iso_session import (
    CBOR_TAG_ENCODED,
    COSE_CRV,
    COSE_CRV_P256,
    COSE_KTY,
    COSE_KTY_EC2,
    COSE_X,
    COSE_Y,
    PHOTO_ID_DOCTYPE,
    default_requested_elements,
    extract_shared_attributes,
    generate_session_id,
)


PHOTO_ID_NAMESPACE = "org.iso.23220.1"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _tagged_bytes(data: bytes) -> cbor2.CBORTag:
    return cbor2.CBORTag(CBOR_TAG_ENCODED, data)


def build_cose_key(public_key: ec.EllipticCurvePublicKey) -> dict[int, Any]:
    numbers = public_key.public_numbers()
    return {
        COSE_KTY: COSE_KTY_EC2,
        COSE_CRV: COSE_CRV_P256,
        COSE_X: numbers.x.to_bytes(32, "big"),
        COSE_Y: numbers.y.to_bytes(32, "big"),
    }


def cose_key_to_public_key(cose_key: dict[int, Any]) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(cose_key[COSE_X], "big")
    y = int.from_bytes(cose_key[COSE_Y], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def export_public_key_hex(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ).hex()


def build_device_request_bytes(
    requested_elements: dict[str, dict[str, bool]],
) -> bytes:
    items_request = {
        "docType": PHOTO_ID_DOCTYPE,
        "nameSpaces": requested_elements,
    }
    encoded_items_request = cbor2.dumps(items_request)
    device_request_info = cbor2.dumps(
        {
            "useCases": [
                {
                    "mandatory": True,
                    "documentSets": [[0]],
                }
            ]
        }
    )
    payload = {
        "version": "1.1",
        "docRequests": [
            {
                "itemsRequest": _tagged_bytes(encoded_items_request),
            }
        ],
        "deviceRequestInfo": _tagged_bytes(device_request_info),
    }
    return cbor2.dumps(payload)


def build_encryption_info_bytes(
    nonce: bytes,
    recipient_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    return cbor2.dumps(
        [
            "dcapi",
            {
                "nonce": nonce,
                "recipientPublicKey": build_cose_key(recipient_public_key),
            },
        ]
    )


def _annex_c_context(enc: bytes, recipient_pub: bytes, nonce: bytes) -> bytes:
    return b"annexc-demo-v1|" + enc + b"|" + recipient_pub + b"|" + nonce


def hpke_seal(
    recipient_public_key: ec.EllipticCurvePublicKey,
    nonce: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """Demo-grade HPKE-like envelope using P-256 ECDH + HKDF + AES-GCM."""

    sender_private = ec.generate_private_key(ec.SECP256R1())
    sender_public = sender_private.public_key()
    shared_secret = sender_private.exchange(ec.ECDH(), recipient_public_key)
    enc = sender_public.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    recipient_pub = recipient_public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    context = _annex_c_context(enc, recipient_pub, nonce)
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=44,
        salt=hashlib.sha256(context).digest(),
        info=b"annexc-demo-response",
    ).derive(shared_secret)
    key = key_material[:32]
    aes_nonce = key_material[32:]
    cipher_text = AESGCM(key).encrypt(aes_nonce, plaintext, context)
    return enc, cipher_text


def hpke_open(
    recipient_private_key: ec.EllipticCurvePrivateKey,
    nonce: bytes,
    enc: bytes,
    cipher_text: bytes,
) -> bytes:
    sender_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), enc)
    recipient_public_key = recipient_private_key.public_key()
    recipient_pub = recipient_public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    context = _annex_c_context(enc, recipient_pub, nonce)
    shared_secret = recipient_private_key.exchange(ec.ECDH(), sender_public)
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=44,
        salt=hashlib.sha256(context).digest(),
        info=b"annexc-demo-response",
    ).derive(shared_secret)
    key = key_material[:32]
    aes_nonce = key_material[32:]
    return AESGCM(key).decrypt(aes_nonce, cipher_text, context)


def build_device_response(document_attributes: dict[str, Any]) -> bytes:
    encoded_items = []
    for name, value in document_attributes.items():
        encoded_items.append(
            _tagged_bytes(
                cbor2.dumps(
                    {
                        "elementIdentifier": name,
                        "elementValue": value,
                    }
                )
            )
        )

    payload = {
        "version": "1.0",
        "documents": [
            {
                "docType": PHOTO_ID_DOCTYPE,
                "issuerSigned": {
                    "nameSpaces": {
                        PHOTO_ID_NAMESPACE: encoded_items,
                    }
                },
            }
        ],
        "status": 0,
    }
    return cbor2.dumps(payload)


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, cbor2.CBORTag):
        return {
            "type": "cbor_tag",
            "tag": value.tag,
            "value": _json_safe_value(value.value),
        }
    if isinstance(value, dict):
        return {str(key): _json_safe_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe_value(item) for item in value]
    return value


@dataclass
class AnnexCSessionConfig:
    verifier_id: str
    photoid_elements: list[str] = field(default_factory=list)
    custom_attributes: list[str] = field(default_factory=list)
    custom_photoid_attributes: list[str] = field(default_factory=list)
    custom_namespace: str = ""
    custom_namespace_attributes: list[str] = field(default_factory=list)


@dataclass
class AnnexCSessionState:
    session_id: str
    config: AnnexCSessionConfig
    recipient_private_key: ec.EllipticCurvePrivateKey
    recipient_public_key: ec.EllipticCurvePublicKey
    request_nonce: bytes
    device_request: bytes
    encryption_info: bytes
    created_at: float = field(default_factory=time.time)
    expires_in: int = 300
    response_envelope: bytes | None = None
    response_plaintext: bytes | None = None
    shared_attributes: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_error: str | None = None
    validation_status: dict[str, str] = field(
        default_factory=lambda: {
            "transport": "pending",
            "issuer_auth": "not_implemented",
            "device_auth": "not_implemented",
        }
    )

    @property
    def expires_at(self) -> float:
        return self.created_at + self.expires_in

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    def request_object(self) -> dict[str, str]:
        data = {
            "deviceRequest": _b64url(self.device_request),
            "encryptionInfo": _b64url(self.encryption_info),
        }
        return {
            "requests": [
                {
                    "protocol": "org-iso-mdoc",
                    "data": data,
                },
            ]
        }

    def _extract_standard_response(
        self,
        response_b64: str,
    ) -> tuple[bytes, bytes, bytes]:
        response_bytes = _b64url_decode(response_b64)
        decoded = cbor2.loads(response_bytes)
        if not isinstance(decoded, list) or len(decoded) < 2 or decoded[0] != "dcapi":
            raise ValueError("Response payload is not a dcapi envelope")
        encryption_parameters = decoded[1]
        if not isinstance(encryption_parameters, dict):
            raise ValueError("Response payload is missing dcapi encryption parameters")
        enc = encryption_parameters.get("enc")
        cipher_text = encryption_parameters.get("cipherText")
        if not isinstance(enc, bytes) or not isinstance(cipher_text, bytes):
            raise ValueError("Response payload is missing dcapi enc/cipherText bytes")
        return response_bytes, enc, cipher_text

    def handle_response(
        self,
        enc_b64: str | None = None,
        cipher_text_b64: str | None = None,
        response_b64: str | None = None,
    ) -> None:
        if self.expired:
            raise ValueError("Session expired")
        if self.response_plaintext is not None or self.response_envelope is not None:
            raise ValueError("Session already completed")

        used_standard_response = response_b64 is not None
        if response_b64 is not None:
            self.response_envelope, enc, cipher_text = self._extract_standard_response(response_b64)
        else:
            if enc_b64 is None or cipher_text_b64 is None:
                raise ValueError("Response payload must include enc and cipherText")
            enc = _b64url_decode(enc_b64)
            cipher_text = _b64url_decode(cipher_text_b64)

        try:
            plaintext = hpke_open(self.recipient_private_key, self.request_nonce, enc, cipher_text)
        except Exception:
            if not used_standard_response:
                raise
            self.validation_status["transport"] = "received_encrypted"
            self.last_error = (
                "Received a standards-formatted org-iso-mdoc response, but this demo verifier "
                "does not yet implement standards-based HPKE decryption."
            )
            return

        self.response_plaintext = plaintext
        self.shared_attributes = extract_shared_attributes(plaintext)
        self.validation_status["transport"] = "decrypted"
        self.last_error = None

    def response_preview(self) -> dict[str, Any] | None:
        payload = self.response_plaintext or self.response_envelope
        if payload is None:
            return None
        try:
            decoded = cbor2.loads(payload)
        except Exception:
            return None
        return _json_safe_value(decoded) if isinstance(decoded, dict) else None


def new_annex_c_session(config: AnnexCSessionConfig) -> AnnexCSessionState:
    recipient_private_key = ec.generate_private_key(ec.SECP256R1())
    recipient_public_key = recipient_private_key.public_key()
    request_nonce = os.urandom(16)
    requested = default_requested_elements(
        PHOTO_ID_DOCTYPE,
        config.photoid_elements,
        [],
        config.custom_attributes,
        config.custom_photoid_attributes,
        [],
        config.custom_namespace,
        config.custom_namespace_attributes,
        False,
    )
    device_request = build_device_request_bytes(requested)
    encryption_info = build_encryption_info_bytes(request_nonce, recipient_public_key)
    return AnnexCSessionState(
        session_id=generate_session_id(),
        config=config,
        recipient_private_key=recipient_private_key,
        recipient_public_key=recipient_public_key,
        request_nonce=request_nonce,
        device_request=device_request,
        encryption_info=encryption_info,
    )
