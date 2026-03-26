"""Utilities for building a compact CBOR-based verifier request payload."""

from __future__ import annotations

import base64
import os
from typing import Any

import cbor2


PHOTO_ID_NAMESPACE = "org.iso.23220.photoid.1"
MDL_NAMESPACE = "org.iso.18013.5.1"


def _default_requested_elements(include_mdl_core: bool) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = [
        {
            "doc_type": PHOTO_ID_NAMESPACE,
            "name_spaces": {
                PHOTO_ID_NAMESPACE: {
                    "family_name": False,
                    "given_name": False,
                    "birth_date": False,
                    "portrait": False,
                    "age_over_18": False,
                }
            },
        }
    ]

    if include_mdl_core:
        requests.append(
            {
                "doc_type": "org.iso.18013.5.1.mDL",
                "name_spaces": {
                    MDL_NAMESPACE: {
                        "family_name": False,
                        "given_name": False,
                        "birth_date": False,
                        "issuing_country": False,
                    }
                },
            }
        )

    return requests


def build_device_request(
    request_url: str,
    verifier_id: str = "urn:example:verifier",
    include_mdl_core: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    """Build a compact CBOR payload plus JSON-safe metadata for the API."""

    nonce = os.urandom(16)
    payload = {
        "version": "1.0",
        "type": "DeviceRequest",
        "request_url": request_url,
        "verifier_id": verifier_id,
        "nonce": nonce,
        "doc_requests": _default_requested_elements(include_mdl_core),
    }
    cbor_bytes = cbor2.dumps(payload)

    meta = {
        "request_url": request_url,
        "verifier_id": verifier_id,
        "include_mdl_core": include_mdl_core,
        "doc_types": [req["doc_type"] for req in payload["doc_requests"]],
        "nonce_hex": nonce.hex(),
        "cbor_hex": cbor_bytes.hex(),
        "cbor_size": len(cbor_bytes),
    }
    return cbor_bytes, meta


def build_mdoc_uri(cbor_bytes: bytes) -> str:
    """Encode CBOR bytes as an mdoc deep link."""

    encoded = base64.urlsafe_b64encode(cbor_bytes).rstrip(b"=").decode("ascii")
    return f"mdoc://{encoded}"
