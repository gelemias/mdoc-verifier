from __future__ import annotations

import asyncio
import os
import secrets
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.datastructures import Headers, MutableHeaders

from mdoc_verifier.annex_c import (
    PROTOCOL as ANNEX_C_PROTOCOL, AnnexCSessionConfig, AnnexCSessionState, ReaderIdentity, new_annex_c_session,
)
from mdoc_verifier.iso_session import (
    MDL_DOCTYPE, PHOTO_ID_DOCTYPE, SessionConfig, build_mdoc_uri, export_public_key_hex,
    generate_session_id, new_session_state,
)
from mdoc_verifier.openid4vp import PROTOCOL as OPENID4VP_PROTOCOL, new_openid4vp_session
from mdoc_verifier.validation import IssuerTrust

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY = 1024 * 1024
MAX_SESSIONS = 256
DEFAULT_PHOTOID = ["portrait", "family_name", "given_name", "birth_date", "age_over_18"]
DEFAULT_MDL = ["family_name", "given_name", "birth_date", "issuing_country"]

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self' https: http:; img-src 'self' data: blob:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


class RequestLimits:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def add_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = "no-store"
                headers["Content-Security-Policy"] = CSP
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = "digital-credentials-get=(self)"
            await send(message)

        if scope["method"] == "POST":
            supplied_length = Headers(scope=scope).get("content-length")
            if supplied_length is not None and (
                not supplied_length.isdecimal() or len(supplied_length) > 10 or int(supplied_length) > MAX_BODY
            ):
                await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, add_headers)
                return

        total = 0

        async def limited_receive():
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > MAX_BODY:
                raise HTTPException(413, "Request body too large")
            return message

        await self.app(scope, limited_receive, add_headers)


def configured_origin() -> str | None:
    value = os.getenv("MDOC_PUBLIC_ORIGIN")
    if value is None:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or parsed.hostname is None or parsed.username is not None
        or parsed.path or parsed.query or parsed.fragment or value != exported_origin(parsed)
    ):
        raise ValueError("MDOC_PUBLIC_ORIGIN must be a serialized HTTPS origin without a trailing slash")
    return value


def exported_origin(url) -> str:
    host = url.hostname
    if host is None:
        raise ValueError("Missing origin host")
    if ":" in host:
        host = f"[{host}]"
    port = f":{url.port}" if url.port and url.port != (443 if url.scheme == "https" else 80) else ""
    return f"{url.scheme}://{host}{port}"


def load_issuer_trust() -> IssuerTrust:
    roots_path = os.getenv("MDOC_ISSUER_CA_PEM")
    crl_path = os.getenv("MDOC_ISSUER_CRL_PEM")
    roots = x509.load_pem_x509_certificates(Path(roots_path).read_bytes()) if roots_path else []
    if any(not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for root in roots):
        raise ValueError("MDOC_ISSUER_CA_PEM must contain only CA certificates")
    crls = [x509.load_pem_x509_crl(Path(crl_path).read_bytes())] if crl_path else []
    allow_untrusted = os.getenv("MDOC_ALLOW_UNTRUSTED_ISSUER", "").strip().lower() == "true"
    return IssuerTrust(tuple(roots), tuple(crls), allow_untrusted_issuer=allow_untrusted)


def load_reader_identity() -> ReaderIdentity | None:
    key_path = os.getenv("MDOC_READER_KEY_PEM")
    cert_path = os.getenv("MDOC_READER_CHAIN_PEM")
    if not key_path and not cert_path:
        return None
    if not (key_path and cert_path):
        raise ValueError("Set both MDOC_READER_KEY_PEM and MDOC_READER_CHAIN_PEM")
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    chain = x509.load_pem_x509_certificates(Path(cert_path).read_bytes())
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
    ):
        raise ValueError("Reader private key must use P-256, P-384 or P-521")
    if key.public_key() != chain[0].public_key():
        raise ValueError("Reader certificate does not match the private key")
    if len(chain) > 1 and chain[-1].issuer == chain[-1].subject:
        chain.pop()
    return ReaderIdentity(key, chain)


async def periodically_expire_sessions(app: FastAPI) -> None:
    while True:
        await asyncio.sleep(15)
        purge_sessions(app)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.origin = configured_origin()
    app.state.trust = load_issuer_trust()
    app.state.reader_identity = load_reader_identity()
    app.state.qr_sessions = {}
    app.state.dc_sessions = {}
    cleanup = asyncio.create_task(periodically_expire_sessions(app))
    try:
        yield
    finally:
        cleanup.cancel()
        with suppress(asyncio.CancelledError):
            await cleanup


app = FastAPI(title="mdoc Verifier API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(RequestLimits)


@app.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _exc: RequestValidationError):
    return JSONResponse({"detail": "Invalid request fields"}, status_code=422)



Claim = Annotated[str, Field(min_length=1, max_length=128)]
ClaimList = Annotated[list[Claim], Field(max_length=64)]
Identifier = Annotated[str, Field(max_length=256)]


class SessionCreateRequest(BaseModel):
    verifier_id: Identifier = "urn:example:verifier"
    doc_type: Identifier = PHOTO_ID_DOCTYPE
    include_mdl: bool = False
    photoid_elements: ClaimList = Field(default_factory=lambda: DEFAULT_PHOTOID.copy())
    mdl_elements: ClaimList = Field(default_factory=lambda: DEFAULT_MDL.copy())
    custom_attributes: ClaimList = Field(default_factory=list)
    custom_photoid_attributes: ClaimList = Field(default_factory=list)
    custom_mdl_attributes: ClaimList = Field(default_factory=list)
    custom_namespace: Identifier = ""
    custom_namespace_attributes: ClaimList = Field(default_factory=list)


DCProtocol = Literal[ANNEX_C_PROTOCOL, OPENID4VP_PROTOCOL]


class DigitalSessionCreateRequest(SessionCreateRequest):
    doc_type: Literal[PHOTO_ID_DOCTYPE, MDL_DOCTYPE] = PHOTO_ID_DOCTYPE
    protocol: DCProtocol = ANNEX_C_PROTOCOL


class DigitalSubmitRequest(BaseModel):
    protocol: DCProtocol | None = None
    response: str | None = Field(default=None, max_length=MAX_BODY)
    data: dict[str, str] | None = None

    def response_value(self) -> str:
        if self.response and self.data is None:
            return self.response
        if self.response is None and self.data and self.data.keys() == {"response"} and self.data["response"]:
            return self.data["response"]
        raise ValueError("Expected a Digital Credentials response in data.response")


def request_origin(request: Request) -> str:
    origin = request.app.state.origin
    if origin is None:
        parsed = urlsplit(str(request.url))
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise HTTPException(503, "Configure MDOC_PUBLIC_ORIGIN for this deployment")
        origin = exported_origin(parsed)
    supplied_origin = request.headers.get("origin")
    if supplied_origin is not None and supplied_origin != origin:
        raise HTTPException(403, "Browser origin does not match the verifier origin")
    return origin


def purge_sessions(app: FastAPI) -> int:
    now = time.time()
    stores = (app.state.qr_sessions, app.state.dc_sessions)
    for sessions in stores:
        for session_id in [key for key, state in sessions.items() if state.expires_at <= now]:
            del sessions[session_id]
    return sum(len(sessions) for sessions in stores)


def ensure_capacity(request: Request) -> None:
    if purge_sessions(request.app) >= MAX_SESSIONS:
        raise HTTPException(429, "Session capacity reached. Try again after current sessions expire.")


def read_session(request: Request, sessions, session_id: str, *, authenticated: bool = True):
    purge_sessions(request.app)
    state = sessions.get(session_id)
    if state is None or (authenticated and not secrets.compare_digest(
        request.headers.get("authorization", "").encode("utf-8"), f"Bearer {state.access_token}".encode("ascii")
    )):
        raise HTTPException(404, "Session not found or expired")
    return state


@app.get("/")
async def index():
    return FileResponse(ROOT / "index.html", media_type="text/html")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/mdoc/request")
async def request_info():
    return {"message": "Create a session at POST /mdoc/session and use the returned transfer URL."}


@app.post("/mdoc/session")
async def create_session(config: SessionCreateRequest, request: Request):
    origin = request_origin(request)
    ensure_capacity(request)
    session_id = generate_session_id()
    request_url = f"{origin}{request.url_for('wallet_transfer', session_id=session_id).path}"
    state = new_session_state(session_id, request_url, SessionConfig(**config.model_dump()))
    if not state.requested_elements():
        raise HTTPException(422, "Select at least one claim")
    request.app.state.qr_sessions[session_id] = state
    return {
        **config.model_dump(),
        "session_id": session_id,
        "access_token": state.access_token,
        "expires_at": state.expires_at,
        "request_url": request_url,
        "reader_engagement_hex": state.reader_engagement.hex(),
        "reader_engagement_size": len(state.reader_engagement),
        "reader_public_key_hex": export_public_key_hex(state.reader_public_key),
        "mdoc_uri": build_mdoc_uri(state.reader_engagement),
        "issuer_trust_configured": bool(request.app.state.trust.roots),
        "issuer_inspection_mode": request.app.state.trust.inspection_mode,
    }


@app.post("/dc/session")
async def create_digital_session(config: DigitalSessionCreateRequest, request: Request):
    origin = request_origin(request)
    ensure_capacity(request)
    session_config = AnnexCSessionConfig(**config.model_dump(exclude={"include_mdl", "protocol"}))
    try:
        if config.protocol == OPENID4VP_PROTOCOL:
            state = new_openid4vp_session(session_config, origin)
        else:
            state = new_annex_c_session(session_config, origin, request.app.state.reader_identity)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    request.app.state.dc_sessions[state.session_id] = state
    return {
        "session_id": state.session_id,
        "access_token": state.access_token,
        "doc_type": state.config.doc_type,
        "response_url": f"{origin}{request.url_for('digital_credentials_response', session_id=state.session_id).path}",
        "status_url": f"{origin}{request.url_for('digital_session_status', session_id=state.session_id).path}",
        "expires_at": state.expires_at,
        "protocol": state.protocol,
        **({
            "request_nonce_hex": state.request_nonce.hex(),
            "recipient_public_key_hex": export_public_key_hex(state.recipient_public_key),
        } if isinstance(state, AnnexCSessionState) else {"request_nonce": state.nonce}),
        "request": state.request_object(),
        "validation": state.validation_status,
        "signed_request": state.signed_request,
        "issuer_trust_configured": bool(request.app.state.trust.roots),
        "issuer_inspection_mode": request.app.state.trust.inspection_mode,
    }


@app.get("/dc/session/{session_id}", name="digital_session_status")
async def digital_session_status(session_id: str, request: Request):
    state = read_session(request, request.app.state.dc_sessions, session_id)
    return {
        "session_id": state.session_id,
        "doc_type": state.config.doc_type,
        "protocol": state.protocol,
        "expires_at": state.expires_at,
        "response_received": state.completed,
        "shared_attributes": state.shared_attributes,
        "validation": state.validation_status,
        "last_error": state.last_error,
    }


@app.get("/mdoc/session/{session_id}")
async def session_status(session_id: str, request: Request):
    state = read_session(request, request.app.state.qr_sessions, session_id)
    return {
        "session_id": state.session_id,
        "expires_at": state.expires_at,
        "stage": state.stage,
        "response_received": state.stage == 2 and state.last_error is None,
        "shared_attributes": state.shared_attributes,
        "validation": state.validation_status,
        "last_error": state.last_error,
    }


@app.post("/mdoc/request/{session_id}", name="wallet_transfer")
async def wallet_transfer(session_id: str, request: Request):
    body = await request.body()
    state = read_session(request, request.app.state.qr_sessions, session_id, authenticated=False)
    if not body:
        raise HTTPException(400, "Request body is empty")
    try:
        if state.stage == 0:
            payload = state.create_initial_response(body)
        elif state.stage == 1:
            payload = state.handle_followup(body, request.app.state.trust)
        else:
            raise HTTPException(409, "Session already completed")
    except (InvalidTag, ValueError, TypeError, KeyError, IndexError, cbor2.CBORError) as exc:
        raise HTTPException(400, "Invalid wallet transfer message") from exc
    return Response(content=payload, media_type="application/cbor")


@app.post("/dc/response/{session_id}", name="digital_credentials_response")
async def digital_credentials_response(session_id: str, payload: DigitalSubmitRequest, request: Request):
    request_origin(request)
    state = read_session(request, request.app.state.dc_sessions, session_id)
    if state.completed:
        raise HTTPException(409, "Session already completed")
    if (payload.protocol or ANNEX_C_PROTOCOL) != state.protocol:
        raise HTTPException(422, "Response protocol does not match the session")
    try:
        state.handle_response(payload.response_value(), request.app.state.trust)
    except ValueError as exc:
        state.last_error = str(exc)
        raise HTTPException(422, str(exc)) from exc
    return {
        "status": "unverified" if state.issuer_auth == "unverified" else "ok",
        "session_id": state.session_id,
        "response_received": True,
        "shared_attributes": state.shared_attributes,
        "validation": state.validation_status,
    }


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
