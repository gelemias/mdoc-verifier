"""Minimal ISO 18013-7 reverse-engagement session support for demo verifier flows."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PHOTO_ID_NAMESPACE = "org.iso.23220.1"
MDL_NAMESPACE = "org.iso.18013.5.1"
MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
PHOTO_ID_DOCTYPE = "org.iso.23220.photoid.1"

COSE_KTY = 1
COSE_CRV = -1
COSE_X = -2
COSE_Y = -3
COSE_KTY_EC2 = 2
COSE_CRV_P256 = 1
CBOR_TAG_ENCODED = 24


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_mdoc_uri(reader_engagement: bytes) -> str:
    return f"mdoc://{_b64url(reader_engagement)}"


def tagged_bytes(data: bytes) -> cbor2.CBORTag:
    return cbor2.CBORTag(CBOR_TAG_ENCODED, data)


def build_cose_key(public_key: ec.EllipticCurvePublicKey) -> dict[int, Any]:
    numbers = public_key.public_numbers()
    size = 32
    return {
        COSE_KTY: COSE_KTY_EC2,
        COSE_CRV: COSE_CRV_P256,
        COSE_X: numbers.x.to_bytes(size, "big"),
        COSE_Y: numbers.y.to_bytes(size, "big"),
    }


def cose_key_to_public_key(cose_key: dict[int, Any]) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(cose_key[COSE_X], "big")
    y = int.from_bytes(cose_key[COSE_Y], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def build_reader_engagement(
    public_key: ec.EllipticCurvePublicKey, request_url: str
) -> tuple[bytes, bytes]:
    e_reader_key_bytes = cbor2.dumps(build_cose_key(public_key))
    engagement = {
        0: "1.1",
        1: [1, tagged_bytes(e_reader_key_bytes)],
        2: [[4, 1, {0: request_url}]],
    }
    return cbor2.dumps(engagement), e_reader_key_bytes


def parse_device_engagement_message(message_data: bytes) -> bytes:
    decoded = cbor2.loads(message_data)
    tagged = decoded["deviceEngagementBytes"]
    if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != CBOR_TAG_ENCODED:
        raise ValueError("deviceEngagementBytes must be tag 24")
    if not isinstance(tagged.value, bytes):
        raise ValueError("deviceEngagementBytes tag must wrap bytes")
    return tagged.value


def parse_device_public_key(device_engagement: bytes) -> ec.EllipticCurvePublicKey:
    decoded = cbor2.loads(device_engagement)
    security = decoded[1]
    if security[0] != 1:
        raise ValueError("Unsupported cipher suite")
    tagged = security[1]
    if not isinstance(tagged, cbor2.CBORTag) or tagged.tag != CBOR_TAG_ENCODED:
        raise ValueError("Device key must be tag 24 COSE_Key")
    cose_key = cbor2.loads(tagged.value)
    return cose_key_to_public_key(cose_key)


def build_session_transcript(
    device_engagement: bytes,
    e_reader_key_bytes: bytes,
    reader_engagement: bytes,
) -> bytes:
    handover = hashlib.sha256(cbor2.dumps(tagged_bytes(reader_engagement))).digest()
    transcript = [
        tagged_bytes(device_engagement),
        tagged_bytes(e_reader_key_bytes),
        handover,
    ]
    return cbor2.dumps(transcript)


def _derive_key(shared_secret: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def derive_session_keys(
    reader_private_key: ec.EllipticCurvePrivateKey,
    device_public_key: ec.EllipticCurvePublicKey,
    session_transcript: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    shared_secret = reader_private_key.exchange(ec.ECDH(), device_public_key)
    salt = hashlib.sha256(cbor2.dumps(tagged_bytes(session_transcript))).digest()
    sk_device = _derive_key(shared_secret, salt, b"SKDevice")
    sk_reader = _derive_key(shared_secret, salt, b"SKReader")
    return shared_secret, salt, sk_device, sk_reader


def make_iv(role: str, counter: int) -> bytes:
    identifier = 0 if role == "reader_encrypt" else 1
    return b"\x00\x00\x00\x00" + identifier.to_bytes(4, "big") + counter.to_bytes(4, "big")


def encrypt_session_data(
    plaintext: bytes | None,
    key: bytes,
    counter: int,
    include_e_reader_key: bytes | None = None,
    status: int | None = None,
) -> bytes:
    message: dict[str, Any] = {}
    if include_e_reader_key is not None:
        message["eReaderKey"] = tagged_bytes(include_e_reader_key)
    if plaintext is not None:
        ciphertext = AESGCM(key).encrypt(make_iv("reader_encrypt", counter), plaintext, None)
        message["data"] = ciphertext
    if status is not None:
        message["status"] = status
    return cbor2.dumps(message)


def decrypt_session_data(message_data: bytes, key: bytes, counter: int) -> tuple[bytes | None, int | None]:
    message = cbor2.loads(message_data)
    plaintext = None
    if "data" in message:
        plaintext = AESGCM(key).decrypt(make_iv("reader_decrypt", counter), message["data"], None)
    status = message.get("status")
    return plaintext, status


def _decode_issuer_signed_item(item: Any) -> tuple[str | None, Any | None]:
    if isinstance(item, cbor2.CBORTag) and item.tag == CBOR_TAG_ENCODED and isinstance(item.value, bytes):
        item = cbor2.loads(item.value)
    elif isinstance(item, bytes):
        item = cbor2.loads(item)

    if not isinstance(item, dict):
        return None, None
    return item.get("elementIdentifier"), item.get("elementValue")


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


def extract_shared_attributes(response_plaintext: bytes | None) -> dict[str, dict[str, Any]]:
    if not response_plaintext:
        return {}

    try:
        decoded = cbor2.loads(response_plaintext)
    except Exception:
        return {}
    if not isinstance(decoded, dict):
        return {}

    documents = decoded.get("documents")
    if not isinstance(documents, list):
        return {}

    shared: dict[str, dict[str, Any]] = {}
    for document in documents:
        if not isinstance(document, dict):
            continue
        issuer_signed = document.get("issuerSigned")
        if not isinstance(issuer_signed, dict):
            continue
        name_spaces = issuer_signed.get("nameSpaces")
        if not isinstance(name_spaces, dict):
            continue

        for namespace, items in name_spaces.items():
            if not isinstance(namespace, str) or not isinstance(items, list):
                continue
            namespace_items = shared.setdefault(namespace, {})
            for item in items:
                key, value = _decode_issuer_signed_item(item)
                if key is not None:
                    namespace_items[key] = _json_safe_value(value)

    return shared


def build_device_request(
    doc_type: str,
    requested_elements: dict[str, dict[str, bool]],
) -> bytes:
    items_request = {
        "docType": doc_type,
        "nameSpaces": requested_elements,
    }
    encoded_items_request = cbor2.dumps(items_request)
    device_request = {
        "version": "1.0",
        "docRequests": [
            {
                "itemsRequest": tagged_bytes(encoded_items_request),
            }
        ],
    }
    return cbor2.dumps(device_request)


def default_requested_elements(
    doc_type: str,
    photoid_elements: list[str],
    mdl_elements: list[str],
    custom_attributes: list[str],
    custom_photoid_attributes: list[str],
    custom_mdl_attributes: list[str],
    custom_namespace: str,
    custom_namespace_attributes: list[str],
    include_mdl: bool,
) -> dict[str, dict[str, bool]]:
    primary_elements = list(
        dict.fromkeys([*photoid_elements, *custom_attributes, *custom_photoid_attributes])
    )
    secondary_mdl_elements = list(dict.fromkeys([*mdl_elements, *custom_mdl_attributes]))
    requests: dict[str, dict[str, bool]] = {}

    def add_namespace(namespace: str, elements: list[str]) -> None:
        if not namespace or not elements:
            return
        namespace_items = requests.setdefault(namespace, {})
        namespace_items.update({name: False for name in elements})

    if doc_type == PHOTO_ID_DOCTYPE:
        add_namespace(PHOTO_ID_NAMESPACE, primary_elements)
    elif doc_type == MDL_DOCTYPE:
        add_namespace(MDL_NAMESPACE, secondary_mdl_elements)
    else:
        add_namespace(PHOTO_ID_NAMESPACE, primary_elements)

    if include_mdl and doc_type != MDL_DOCTYPE:
        add_namespace(MDL_NAMESPACE, secondary_mdl_elements)
    add_namespace(custom_namespace.strip(), custom_namespace_attributes)
    return requests


@dataclass
class SessionConfig:
    verifier_id: str
    doc_type: str
    include_mdl: bool
    photoid_elements: list[str] = field(default_factory=list)
    mdl_elements: list[str] = field(default_factory=list)
    custom_attributes: list[str] = field(default_factory=list)
    custom_photoid_attributes: list[str] = field(default_factory=list)
    custom_mdl_attributes: list[str] = field(default_factory=list)
    custom_namespace: str = ""
    custom_namespace_attributes: list[str] = field(default_factory=list)


@dataclass
class SessionState:
    session_id: str
    request_url: str
    reader_private_key: ec.EllipticCurvePrivateKey
    reader_public_key: ec.EllipticCurvePublicKey
    e_reader_key_bytes: bytes
    reader_engagement: bytes
    config: SessionConfig
    created_at: float = field(default_factory=time.time)
    stage: int = 0
    device_public_key: ec.EllipticCurvePublicKey | None = None
    session_transcript: bytes | None = None
    transcript_salt: bytes | None = None
    shared_secret: bytes | None = None
    sk_device: bytes | None = None
    sk_reader: bytes | None = None
    response_plaintext: bytes | None = None
    shared_attributes: dict[str, dict[str, Any]] = field(default_factory=dict)

    def create_initial_response(self, message_data: bytes) -> bytes:
        device_engagement = parse_device_engagement_message(message_data)
        self.device_public_key = parse_device_public_key(device_engagement)
        self.session_transcript = build_session_transcript(
            device_engagement,
            self.e_reader_key_bytes,
            self.reader_engagement,
        )
        self.shared_secret, self.transcript_salt, self.sk_device, self.sk_reader = derive_session_keys(
            self.reader_private_key,
            self.device_public_key,
            self.session_transcript,
        )
        requested = default_requested_elements(
            self.config.doc_type,
            self.config.photoid_elements,
            self.config.mdl_elements,
            self.config.custom_attributes,
            self.config.custom_photoid_attributes,
            self.config.custom_mdl_attributes,
            self.config.custom_namespace,
            self.config.custom_namespace_attributes,
            self.config.include_mdl,
        )
        device_request = build_device_request(self.config.doc_type, requested)
        self.stage = 1
        return encrypt_session_data(device_request, self.sk_reader, counter=1)

    def handle_followup(self, message_data: bytes) -> bytes:
        if self.sk_device is None:
            raise ValueError("Session keys are not established")
        plaintext, _status = decrypt_session_data(message_data, self.sk_device, counter=1)
        self.response_plaintext = plaintext
        self.shared_attributes = extract_shared_attributes(plaintext)
        self.stage = 2
        return cbor2.dumps({"status": 20})


def new_session_state(session_id: str, request_url: str, config: SessionConfig) -> SessionState:
    reader_private_key = ec.generate_private_key(ec.SECP256R1())
    reader_public_key = reader_private_key.public_key()
    reader_engagement, e_reader_key_bytes = build_reader_engagement(reader_public_key, request_url)
    return SessionState(
        session_id=session_id,
        request_url=request_url,
        reader_private_key=reader_private_key,
        reader_public_key=reader_public_key,
        e_reader_key_bytes=e_reader_key_bytes,
        reader_engagement=reader_engagement,
        config=config,
    )


def export_public_key_hex(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ).hex()


def generate_session_id() -> str:
    return secrets.token_urlsafe(12)
