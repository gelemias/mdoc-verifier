from __future__ import annotations

import cbor2
from fastapi.testclient import TestClient

from mdoc_verifier.annex_c import (
    build_device_response,
    build_encryption_info_bytes,
    cose_key_to_public_key,
    hpke_seal,
)
from server.main import app


def main() -> None:
    client = TestClient(app)

    create = client.post(
        "/dc/session",
        json={
            "verifier_id": "urn:test:web-verifier",
            "photoid_elements": ["family_name", "given_name", "portrait"],
            "custom_photoid_attributes": ["employee_id"],
            "custom_namespace": "org.example.employee.1",
            "custom_namespace_attributes": ["department"],
        },
    )
    create.raise_for_status()
    payload = create.json()
    request_entry = payload["request"]["requests"][0]["data"]

    encryption_info = cbor2.loads(
        __import__("base64").urlsafe_b64decode(request_entry["encryptionInfo"] + "==")
    )
    recipient_public_key = cose_key_to_public_key(encryption_info[1]["recipientPublicKey"])

    device_response = build_device_response(
        {
            "family_name": "Doe",
            "given_name": "Jane",
            "employee_id": "A-12345",
        }
    )
    enc, cipher_text = hpke_seal(
        recipient_public_key,
        bytes.fromhex(payload["request_nonce_hex"]),
        device_response,
    )

    submit = client.post(
        f"/dc/response/{payload['session_id']}",
        json={
            "enc": __import__("base64").urlsafe_b64encode(enc).rstrip(b"=").decode("ascii"),
            "cipherText": __import__("base64").urlsafe_b64encode(cipher_text).rstrip(b"=").decode("ascii"),
        },
    )
    submit.raise_for_status()

    status = client.get(f"/dc/session/{payload['session_id']}")
    status.raise_for_status()
    body = status.json()

    print("Annex C session:", payload["session_id"])
    print("Response received:", body["response_received"])
    print("Family name:", body["shared_attributes"]["org.iso.23220.1"]["family_name"])
    print("Validation status:", body["validation"])


if __name__ == "__main__":
    main()
