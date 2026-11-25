from __future__ import annotations

import os
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from mdoc_verifier.iso_session import build_reader_engagement, build_session_transcript, derive_session_keys, make_iv, tagged_bytes
from server.main import app
from smoke_annex_c import ORIGIN, demo_issuer, device_response


def main() -> None:
    with TemporaryDirectory() as temp:
        issuer = demo_issuer(temp)
        for ca, expected_auth in ((issuer[2], "verified"), ("", "unverified")):
            with patch.dict(os.environ, {
                "MDOC_PUBLIC_ORIGIN": ORIGIN, "MDOC_ISSUER_CA_PEM": ca,
                "MDOC_ISSUER_CRL_PEM": "", "MDOC_ALLOW_UNTRUSTED_ISSUER": "true",
            }):
                with TestClient(app, base_url=ORIGIN) as client:
                    exercise_qr(client, issuer, expected_auth)


def exercise_qr(client, issuer, expected_auth: str):
    create = client.post(
        "/mdoc/session",
        json={
            "doc_type": "org.iso.23220.photoid.1",
            "verifier_id": "urn:test:verifier",
            "include_mdl": False,
            "photoid_elements": ["family_name", "given_name"],
            "mdl_elements": [],
            "custom_photoid_attributes": ["employee_id"],
            "custom_namespace": "org.example.employee.1",
            "custom_namespace_attributes": ["department"],
        },
    )
    create.raise_for_status()
    session = create.json()
    assert session["issuer_inspection_mode"] == (expected_auth == "unverified")

    transfer_path = session["request_url"].removeprefix(ORIGIN)
    reader_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(session["reader_public_key_hex"])
    )
    reader_engagement = bytes.fromhex(session["reader_engagement_hex"])

    device_private = ec.generate_private_key(ec.SECP256R1())
    device_public = device_private.public_key()
    device_engagement, _device_key_bytes = build_reader_engagement(device_public, session["request_url"])
    message_data = cbor2.dumps({"deviceEngagementBytes": tagged_bytes(device_engagement)})

    first = client.post(
        transfer_path,
        content=message_data,
        headers={"content-type": "application/cbor"},
    )
    first.raise_for_status()

    transcript = build_session_transcript(
        device_engagement,
        cbor2.loads(reader_engagement)[1][1].value,
        reader_engagement,
    )
    _shared_secret, _salt, sk_device, sk_reader = derive_session_keys(device_private, reader_public, transcript)
    first_payload = cbor2.loads(first.content)
    device_request = AESGCM(sk_reader).decrypt(make_iv("reader_encrypt", 1), first_payload["data"], None)
    decoded_request = cbor2.loads(device_request)
    items_request = cbor2.loads(decoded_request["docRequests"][0]["itemsRequest"].value)
    doc_type = items_request["docType"]
    requested_elements = items_request["nameSpaces"]["org.iso.23220.1"]
    custom_namespace_elements = items_request["nameSpaces"]["org.example.employee.1"]
    print("Decrypted docType:", doc_type)
    print("Custom attribute requested:", "employee_id" in requested_elements)
    print("Custom namespace requested:", "department" in custom_namespace_elements)

    plaintext = device_response(issuer, cbor2.loads(transcript), device_private)
    followup = cbor2.dumps(
        {"data": AESGCM(sk_device).encrypt(make_iv("reader_decrypt", 1), plaintext, None)}
    )
    second = client.post(
        transfer_path,
        content=followup,
        headers={"content-type": "application/cbor"},
    )
    second.raise_for_status()
    assert cbor2.loads(second.content) == {"status": 20}
    status_path = "/mdoc/session/" + session["session_id"]
    assert client.get(status_path).status_code == 404
    status = client.get(status_path, headers={"Authorization": "Bearer " + session["access_token"]})
    status.raise_for_status()
    assert status.json()["validation"]["issuer_auth"] == expected_auth
    assert status.json()["shared_attributes"] == {"org.iso.23220.1": {"family_name": "Doe"}}
    assert not any(key.startswith("debug_") for key in status.json())
    print(f"QR transfer and termination passed with issuer status {expected_auth}")


if __name__ == "__main__":
    main()
