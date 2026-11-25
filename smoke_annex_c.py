from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from fastapi.testclient import TestClient
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from mdoc_verifier.annex_c import decrypt_envelope, session_transcript
from mdoc_verifier.iso_session import PHOTO_ID_DOCTYPE, PHOTO_ID_NAMESPACE, build_cose_key
from server.main import app

ORIGIN = "https://verifier.example"
KEY_USAGE = {
    "content_commitment": False, "key_encipherment": False, "data_encipherment": False,
    "key_agreement": False, "encipher_only": False, "decipher_only": False,
}


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def wrapped(value) -> cbor2.CBORTag:
    return cbor2.CBORTag(24, cbor2.dumps(value))


def sign(key, payload: bytes, unprotected: dict, *, attached: bool = False) -> list:
    header = cbor2.dumps({1: -7})
    der = key.sign(cbor2.dumps(["Signature1", header, b"", payload]), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return [header, unprotected, payload if attached else None, r.to_bytes(32, "big") + s.to_bytes(32, "big")]


def demo_issuer(directory: str):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test issuer CA")])
    leaf_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test document signer")])

    def issue(name, key, is_ca):
        return (
            x509.CertificateBuilder().subject_name(name).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=not is_ca, key_cert_sign=is_ca, crl_sign=is_ca, **KEY_USAGE
            ), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

    root = issue(ca_name, ca_key, True)
    leaf = issue(leaf_name, leaf_key, False)
    root_file = Path(directory) / "roots.pem"
    root_file.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    return leaf_key, leaf, str(root_file)


def device_response(issuer, transcript: list, device_key=None, *, claim: str = "Doe") -> bytes:
    issuer_key, certificate, _ = issuer
    now = datetime.now(timezone.utc)
    device = device_key or ec.generate_private_key(ec.SECP256R1())
    digest_item = wrapped({"digestID": 0, "random": b"\x01" * 16,
                           "elementIdentifier": "family_name", "elementValue": "Doe"})
    signed_item = wrapped({"digestID": 0, "random": b"\x01" * 16,
                           "elementIdentifier": "family_name", "elementValue": claim})
    mso = wrapped({
        "version": "1.0",
        "docType": PHOTO_ID_DOCTYPE,
        "digestAlgorithm": "SHA-256",
        "valueDigests": {PHOTO_ID_NAMESPACE: {0: hashlib.sha256(cbor2.dumps(digest_item)).digest()}},
        "deviceKeyInfo": {"deviceKey": build_cose_key(device.public_key())},
        "validityInfo": {
            "signed": now - timedelta(hours=2), "validFrom": now - timedelta(hours=1),
            "validUntil": now + timedelta(hours=1),
        },
    })
    namespaces = wrapped({})
    proof = wrapped(["DeviceAuthentication", transcript, PHOTO_ID_DOCTYPE, namespaces])
    return cbor2.dumps({
        "version": "1.0", "status": 0, "documents": [{
            "docType": PHOTO_ID_DOCTYPE,
            "issuerSigned": {
                "nameSpaces": {PHOTO_ID_NAMESPACE: [signed_item]},
                "issuerAuth": sign(issuer_key, cbor2.dumps(mso),
                                   {33: certificate.public_bytes(serialization.Encoding.DER)}, attached=True),
            },
            "deviceSigned": {"nameSpaces": namespaces,
                             "deviceAuth": {"deviceSignature": sign(device, cbor2.dumps(proof), {})}},
        }],
    })


def independent_vector() -> None:
    # walt.id ANNEXC-DETERMINISTIC-001 published interoperability fixture (synthetic key).
    # https://github.com/walt-id/waltid-identity/tree/main/waltid-libraries/protocols/waltid-18013-7-verifier
    encryption_info = (
        "gmVkY2FwaaJlbm9uY2VQAAECAwQFBgcICQoLDA0OD3JyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFY"
        "ILO0LJXwA8VAp7-rI9YIJvj1wfEQ122YdEjwxUFeYAFEIlgg0u68CgTFZk_nslWFmYhDMQQ6vdBNf2vwy3QHKI_80Js"
    )
    encrypted = (
        "gmVkY2FwaaJjZW5jWEEEG5gvoNUFmbbhxRtSl075PExgPLGtxDb9Hxu_VnVe03aaHuJ-vW219Yofq"
        "LJJGUHZKgrrjcEmoLYT0ur35BJCBGpjaXBoZXJUZXh0WCXUGzq3WpzY3INchUZw8cbzbz8bWJueKZ4PLW0LEvhDmmQPAKOa"
    )
    scalar = int("9baeb7b14495d7b69cbe751a98c7ee4ad36b41053da880fe00baa4bb5ce31372", 16)
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    transcript = session_transcript(encryption_info, ORIGIN)
    assert hashlib.sha256(cbor2.dumps(transcript)).hexdigest() == (
        "564a34efc36b9b5a5ccafb6bf2e923cd96cc4a9c3712407f887d1e84d3bb58e4"
    )
    assert hashlib.sha256(decrypt_envelope(encrypted, key, transcript)).hexdigest() == (
        "61ddbf1dd2e26100520b569946be8415790ec2e35a789172436ed4ac15445581"
    )


def main() -> None:
    independent_vector()
    with TemporaryDirectory() as temp:
        issuer = demo_issuer(temp)
        test_env = {"MDOC_PUBLIC_ORIGIN": ORIGIN, "MDOC_ISSUER_CRL_PEM": ""}
        for setting, expected_auth in (("false", None), ("true", "unverified")):
            with patch.dict(os.environ, {
                **test_env, "MDOC_ISSUER_CA_PEM": "", "MDOC_ALLOW_UNTRUSTED_ISSUER": setting,
            }):
                with TestClient(app, base_url=ORIGIN) as client:
                    exercise_annex_c(client, issuer, expected_auth)
        with patch.dict(os.environ, {
            **test_env, "MDOC_ISSUER_CA_PEM": issuer[2], "MDOC_ALLOW_UNTRUSTED_ISSUER": "true",
        }):
            with TestClient(app, base_url=ORIGIN) as client:
                exercise_annex_c(client, issuer)
            key, certificate, _ = issuer
            reader_key = Path(temp) / "reader.key"
            reader_cert = Path(temp) / "reader.pem"
            reader_key.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ))
            reader_cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            with patch.dict(os.environ, {"MDOC_READER_KEY_PEM": str(reader_key), "MDOC_READER_CHAIN_PEM": str(reader_cert)}):
                with TestClient(app, base_url=ORIGIN) as client:
                    exercise_reader_auth(client, key)
    print("Annex C vectors, signed requests, retry, strict verification and issuer inspection passed")


def exercise_annex_c(client: TestClient, issuer, expected_auth: str | None = "verified") -> None:
    creation = client.post("/dc/session", json={"photoid_elements": ["family_name"]})
    creation.raise_for_status()
    assert creation.headers["cache-control"] == "no-store"
    session = creation.json()
    assert session["issuer_inspection_mode"] == (expected_auth == "unverified")
    entry = session["request"]["requests"][0]
    assert entry["protocol"] == "org-iso-mdoc"
    request = cbor2.loads(base64.urlsafe_b64decode(entry["data"]["deviceRequest"] + "=="))
    assert request["version"] == "1.0" and "deviceRequestInfo" not in request
    encryption_info = entry["data"]["encryptionInfo"]
    key_map = cbor2.loads(base64.urlsafe_b64decode(encryption_info + "=="))[1]["recipientPublicKey"]
    key = KEMKey.from_jwk({"kty": "EC", "crv": "P-256", "x": b64url(key_map[-2]), "y": b64url(key_map[-3])})
    suite = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
    transcript = [None, None, ["dcapi", hashlib.sha256(cbor2.dumps([encryption_info, ORIGIN])).digest()]]
    headers = {"Authorization": "Bearer " + session["access_token"]}
    response_path = "/dc/response/" + session["session_id"]
    status_path = "/dc/session/" + session["session_id"]
    assert client.get(status_path).status_code == 404

    def submit(response: bytes, info: list = transcript):
        enc, sender = suite.create_sender_context(key, info=cbor2.dumps(info))
        encrypted = b64url(cbor2.dumps(["dcapi", {"enc": enc, "cipherText": sender.seal(response)}]))
        return client.post(response_path, json={"protocol": "org-iso-mdoc", "data": {"response": encrypted}},
                           headers=headers)

    valid = device_response(issuer, transcript)
    wrong_origin = [None, None, ["dcapi", hashlib.sha256(cbor2.dumps([encryption_info, "https://wallet.example"])).digest()]]
    assert submit(valid, wrong_origin).status_code == 422
    assert submit(device_response(issuer, wrong_origin)).status_code == 422
    assert submit(device_response(issuer, transcript, claim="Changed")).status_code == 422
    assert not client.get(status_path, headers=headers).json()["response_received"]
    result = submit(valid)
    status = client.get(status_path, headers=headers).json()
    if expected_auth is None:
        assert result.status_code == 422
        assert "No trusted issuer" in result.json()["detail"]
        assert not status["response_received"] and status["shared_attributes"] == {}
        return
    result.raise_for_status()
    assert result.json()["status"] == ("ok" if expected_auth == "verified" else "unverified")
    assert result.json()["shared_attributes"] == {PHOTO_ID_NAMESPACE: {"family_name": "Doe"}}
    assert result.json()["validation"] == status["validation"] == {
        "transport": "decrypted",
        "issuer_auth": expected_auth,
        "device_auth": "verified" if expected_auth == "verified" else "proof_checked",
    }
    assert status["last_error"] is None
    assert submit(valid).status_code == 409


def exercise_reader_auth(client: TestClient, key) -> None:
    from mdoc_verifier.validation import check_sign1

    response = client.post("/dc/session", json={"doc_type": "org.iso.18013.5.1.mDL"})
    response.raise_for_status()
    body = response.json()
    assert body["signed_request"]
    data = body["request"]["requests"][0]["data"]
    request_b64 = data["deviceRequest"]
    request = cbor2.loads(base64.urlsafe_b64decode(request_b64 + "=" * (-len(request_b64) % 4)))
    assert request["version"] == "1.1"
    items = request["docRequests"][0]["itemsRequest"]
    transcript = session_transcript(data["encryptionInfo"], ORIGIN)
    expected = wrapped(["ReaderAuthenticationAll", transcript, [items], request["deviceRequestInfo"]])
    check_sign1(request["readerAuthAll"][0], key.public_key(), cbor2.dumps(expected))


if __name__ == "__main__":
    main()
