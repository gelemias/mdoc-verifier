"""Verification of issuer-signed claims and holder proof in ISO mdoc responses."""
from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from io import BytesIO
from typing import Any

import cbor2
from OpenSSL import crypto
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
MDL_SIGNER_EKU = x509.ObjectIdentifier("1.0.18013.5.1.2")
ECDSA_ALGORITHMS = {
    -7: (ec.SECP256R1, hashes.SHA256),
    -35: (ec.SECP384R1, hashes.SHA384),
    -36: (ec.SECP521R1, hashes.SHA512),
    -9: (ec.SECP256R1, hashes.SHA256),
    -51: (ec.SECP384R1, hashes.SHA384),
    -52: (ec.SECP521R1, hashes.SHA512),
}
COSE_CURVES = {
    1: ec.SECP256R1,
    2: ec.SECP384R1,
    3: ec.SECP521R1,
}


def reject_cbor_reference(_value: Any, _shareable: bool = False) -> None:
    raise ValueError("CBOR references are not supported in mdoc messages")


def decode_cbor(data: bytes) -> Any:
    stream = BytesIO(data)
    try:
        result = cbor2.CBORDecoder(
            stream, max_depth=32, allow_indefinite=False, allow_duplicate_keys=False,
            semantic_decoders=dict.fromkeys((25, 28, 29, 256), reject_cbor_reference),
        ).decode()
    except OverflowError as exc:
        raise ValueError("Unsupported CBOR value") from exc
    if stream.read(1):
        raise ValueError("Unexpected trailing CBOR data")
    return result


def tagged_bytes(data: bytes) -> cbor2.CBORTag:
    return cbor2.CBORTag(24, data)


def encoded_value(value: Any) -> Any:
    if not isinstance(value, cbor2.CBORTag) or value.tag != 24 or not isinstance(value.value, bytes):
        raise ValueError("Expected tagged CBOR bytes")
    return decode_cbor(value.value)


def json_claim(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, cbor2.CBORTag):
        return {"type": "cbor_tag", "tag": value.tag, "value": json_claim(value.value)}
    if isinstance(value, Mapping):
        return {str(key): json_claim(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_claim(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError("Unsupported claim value")


def cose_parts(message: Any, tag: int) -> tuple[bytes, Mapping, Mapping, bytes | None, bytes]:
    if isinstance(message, cbor2.CBORTag) and message.tag == tag:
        message = message.value
    if not isinstance(message, (list, tuple)) or len(message) != 4:
        raise ValueError("Malformed COSE message")
    protected_bytes, unprotected, payload, signature = message
    if not isinstance(protected_bytes, bytes) or not isinstance(unprotected, Mapping):
        raise ValueError("Malformed COSE headers")
    if (payload is not None and not isinstance(payload, bytes)) or not isinstance(signature, bytes):
        raise ValueError("Malformed COSE payload or signature")
    protected = decode_cbor(protected_bytes) if protected_bytes else {}
    if not isinstance(protected, Mapping) or protected.keys() & unprotected.keys():
        raise ValueError("Invalid COSE header labels")
    if 2 in protected or 2 in unprotected:
        raise ValueError("Unsupported critical COSE headers")
    return protected_bytes, protected, unprotected, payload, signature


def check_sign1(message: Any, key: Any, detached: bytes | None = None) -> bytes:
    protected_bytes, protected, _, payload, signature = cose_parts(message, 18)
    if (payload is None) == (detached is None):
        raise ValueError("Invalid COSE signature payload")
    signed_payload = detached if payload is None else payload
    signed_data = cbor2.dumps(["Signature1", protected_bytes, b"", signed_payload])
    algorithm = protected.get(1)
    if isinstance(key, ec.EllipticCurvePublicKey) and algorithm in ECDSA_ALGORITHMS:
        curve, digest = ECDSA_ALGORITHMS[algorithm]
        width = (key.key_size + 7) // 8
        if not isinstance(key.curve, curve) or len(signature) != 2 * width:
            raise ValueError("ECDSA algorithm or signature size does not match its key")
        der = utils.encode_dss_signature(
            int.from_bytes(signature[:width], "big"), int.from_bytes(signature[width:], "big")
        )
        key.verify(der, signed_data, ec.ECDSA(digest()))
    elif (
        isinstance(key, ed25519.Ed25519PublicKey) and algorithm in (-8, -19)
        or isinstance(key, ed448.Ed448PublicKey) and algorithm in (-8, -53)
    ):
        key.verify(signature, signed_data)
    else:
        raise ValueError("Unsupported COSE signature algorithm")
    return signed_payload


def sign_reader_auth(key: ec.EllipticCurvePrivateKey, chain: list[x509.Certificate], payload: bytes) -> list:
    algorithm = next(
        alg for alg in (-7, -35, -36) if isinstance(key.curve, ECDSA_ALGORITHMS[alg][0])
    )
    certificates = [cert.public_bytes(serialization.Encoding.DER) for cert in chain]
    protected = cbor2.dumps({1: algorithm, 34: [-16, hashlib.sha256(certificates[0]).digest()]})
    signed = cbor2.dumps(["Signature1", protected, b"", payload])
    der = key.sign(signed, ec.ECDSA(ECDSA_ALGORITHMS[algorithm][1]()))
    width = (key.key_size + 7) // 8
    r, s = utils.decode_dss_signature(der)
    return [protected, {33: certificates[0] if len(certificates) == 1 else certificates}, None,
            r.to_bytes(width, "big") + s.to_bytes(width, "big")]


def device_public_key(key: Mapping) -> Any:
    curve_id = key.get(-1)
    x = key.get(-2)
    if key.get(1) == 2 and curve_id in COSE_CURVES and isinstance(x, bytes):
        curve = COSE_CURVES[curve_id]()
        width = (curve.key_size + 7) // 8
        y = key.get(-3)
        if len(x) == width and isinstance(y, bytes) and len(y) == width:
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, b"\x04" + x + y)
        if len(x) == width and isinstance(y, bool):
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, bytes([2 + y]) + x)
    if key.get(1) == 1 and isinstance(x, bytes):
        if curve_id == 6:
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        if curve_id == 7:
            return ed448.Ed448PublicKey.from_public_bytes(x)
    raise ValueError("Unsupported device key")


@dataclass(frozen=True)
class IssuerTrust:
    roots: tuple[x509.Certificate, ...] = ()
    crls: tuple[x509.CertificateRevocationList, ...] = ()
    allow_untrusted_issuer: bool = False

    @property
    def inspection_mode(self) -> bool:
        return self.allow_untrusted_issuer and not self.roots and not self.crls

    def check(self, issuer_auth: Any, doc_type: str) -> x509.Certificate:
        _, protected, unprotected, _, _ = cose_parts(issuer_auth, 18)
        chain = protected.get(33, unprotected.get(33))
        if isinstance(chain, bytes):
            chain = [chain]
        if not isinstance(chain, (list, tuple)) or not 1 <= len(chain) <= 8:
            raise ValueError("Missing or oversized issuer certificate chain")
        leaf, *intermediates = (x509.load_der_x509_certificate(encoded) for encoded in chain)
        thumbprint = protected.get(34, unprotected.get(34))
        if thumbprint is not None:
            if not isinstance(thumbprint, (list, tuple)) or len(thumbprint) != 2:
                raise ValueError("Invalid issuer certificate thumbprint")
            algorithm, expected = thumbprint
            digest = {-16: hashes.SHA256, -43: hashes.SHA384, -44: hashes.SHA512}.get(algorithm)
            if digest is None or leaf.fingerprint(digest()) != expected:
                raise ValueError("Issuer certificate thumbprint mismatch")
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.digital_signature or usage.key_cert_sign:
            raise ValueError("Issuer certificate does not permit document signing")
        if doc_type == MDL_DOCTYPE:
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if MDL_SIGNER_EKU not in eku:
                raise ValueError("Issuer certificate lacks the mDL document signer purpose")
        if self.inspection_mode:
            now = datetime.now(timezone.utc)
            if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
                raise ValueError("Document signer certificate is outside its validity period")
            return leaf
        if not self.roots:
            raise ValueError("No trusted issuer certificates are configured")
        store = crypto.X509Store()
        for cert in self.roots:
            store.add_cert(crypto.X509.from_cryptography(cert))
        for crl in self.crls:
            store.add_crl(crl)
        if self.crls:
            store.set_flags(crypto.X509StoreFlags.CRL_CHECK | crypto.X509StoreFlags.CRL_CHECK_ALL)
        crypto.X509StoreContext(
            store,
            crypto.X509.from_cryptography(leaf),
            [crypto.X509.from_cryptography(cert) for cert in intermediates],
        ).verify_certificate()
        return leaf


def response_validation(issuer_auth: str) -> dict[str, str]:
    device_auth = {"pending": "pending", "verified": "verified", "unverified": "proof_checked"}
    return {
        "transport": "pending" if issuer_auth == "pending" else "decrypted",
        "issuer_auth": issuer_auth,
        "device_auth": device_auth[issuer_auth],
    }


def verify_device_auth(device_signed: Mapping, device_info: Mapping, transcript: list,
                       doc_type: str, reader_key: ec.EllipticCurvePrivateKey | None) -> None:
    namespaces = device_signed["nameSpaces"]
    if not isinstance(encoded_value(namespaces), Mapping):
        raise ValueError("Malformed device namespaces")
    detached = cbor2.dumps(tagged_bytes(cbor2.dumps([
        "DeviceAuthentication", transcript, doc_type, namespaces,
    ])))
    auth = device_signed["deviceAuth"]
    key = device_public_key(device_info["deviceKey"])
    if auth.keys() == {"deviceSignature"}:
        check_sign1(auth["deviceSignature"], key, detached)
        return
    if auth.keys() != {"deviceMac"} or reader_key is None or not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Unsupported device authentication")
    protected_bytes, protected, _, payload, tag = cose_parts(auth["deviceMac"], 17)
    if protected.get(1) != 5 or payload is not None:
        raise ValueError("Invalid device MAC algorithm or payload")
    salt = hashlib.sha256(cbor2.dumps(tagged_bytes(cbor2.dumps(transcript)))).digest()
    mac_key = HKDF(hashes.SHA256(), 32, salt, b"EMacKey").derive(reader_key.exchange(ec.ECDH(), key))
    expected = hmac.digest(mac_key, cbor2.dumps(["MAC0", protected_bytes, b"", detached]), "sha256")
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Invalid device MAC")


def verify_response(plaintext: bytes, transcript: list, doc_type: str,
                    requested: Mapping[str, Mapping[str, bool]], trust: IssuerTrust,
                    reader_key: ec.EllipticCurvePrivateKey | None = None) -> dict[str, dict[str, Any]]:
    try:
        response = decode_cbor(plaintext)
        documents = response["documents"]
        if response["version"] != "1.0" or type(response["status"]) is not int or response["status"] != 0:
            raise ValueError("Wallet DeviceResponse did not report success")
        if not isinstance(documents, list) or len(documents) != 1:
            raise ValueError("Expected one requested document")
        document = documents[0]
        if document["docType"] != doc_type:
            raise ValueError("Unexpected document type")
        issuer_signed = document["issuerSigned"]
        issuer_auth = issuer_signed["issuerAuth"]
        leaf = trust.check(issuer_auth, doc_type)
        mso = encoded_value(decode_cbor(check_sign1(issuer_auth, leaf.public_key())))
        if mso["version"] != "1.0" or mso["docType"] != doc_type:
            raise ValueError("Invalid MSO version or document type")
        validity = mso["validityInfo"]
        signed, valid_from, valid_until = (validity[k] for k in ("signed", "validFrom", "validUntil"))
        now = datetime.now(timezone.utc)
        if not leaf.not_valid_before_utc <= signed <= leaf.not_valid_after_utc:
            raise ValueError("MSO signature time falls outside issuer certificate validity")
        if not signed <= valid_from <= now <= valid_until:
            raise ValueError("Mobile Security Object is outside its validity period")
        digest_algorithm = {"SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512"}.get(mso["digestAlgorithm"])
        if digest_algorithm is None:
            raise ValueError("Unsupported issuer digest algorithm")

        verified: dict[str, dict[str, Any]] = {}
        for namespace, items in issuer_signed["nameSpaces"].items():
            if namespace not in requested or not isinstance(items, list):
                raise ValueError("Unexpected claim namespace")
            claims = verified.setdefault(namespace, {})
            digest_ids = set()
            for tagged_item in items:
                item = encoded_value(tagged_item)
                digest_id = item["digestID"]
                name = item["elementIdentifier"]
                if not isinstance(item["random"], bytes) or len(item["random"]) < 16:
                    raise ValueError("Invalid issuer claim salt")
                if type(digest_id) is not int or digest_id < 0 or digest_id in digest_ids:
                    raise ValueError("Invalid or repeated issuer digest ID")
                if name not in requested[namespace] or name in claims:
                    raise ValueError("Unexpected or repeated claim")
                digest_ids.add(digest_id)
                expected = mso["valueDigests"][namespace][digest_id]
                if hashlib.new(digest_algorithm, cbor2.dumps(tagged_item)).digest() != expected:
                    raise ValueError("Issuer claim digest mismatch")
                claims[name] = json_claim(item["elementValue"])
        if not any(verified.values()):
            raise ValueError("The wallet returned no requested issuer-signed claims")
        verify_device_auth(document["deviceSigned"], mso["deviceKeyInfo"], transcript, doc_type, reader_key)
        return verified
    except InvalidSignature as exc:
        raise ValueError("Invalid issuer or device signature") from exc
    except crypto.X509StoreContextError as exc:
        raise ValueError("Issuer certificate chain is untrusted, expired, or revoked") from exc
    except (AttributeError, KeyError, TypeError, x509.ExtensionNotFound, cbor2.CBORError) as exc:
        raise ValueError("Malformed or incomplete mdoc response") from exc
