from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from mdoc_verifier.annex_c import (
    AnnexCSessionConfig,
    AnnexCSessionState,
    export_public_key_hex as export_annex_c_public_key_hex,
    new_annex_c_session,
)
from mdoc_verifier.iso_session import (
    SessionConfig,
    SessionState,
    build_mdoc_uri,
    export_public_key_hex,
    generate_session_id,
    new_session_state,
)


app = FastAPI(title="mdoc Verifier API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SessionCreateRequest(BaseModel):
    verifier_id: str = "urn:example:verifier"
    doc_type: str = "org.iso.23220.photoid.1"
    include_mdl: bool = False
    photoid_elements: list[str] = Field(
        default_factory=lambda: [
            "portrait",
            "family_name",
            "given_name",
            "birth_date",
            "age_over_18",
        ]
    )
    mdl_elements: list[str] = Field(
        default_factory=lambda: [
            "family_name",
            "given_name",
            "birth_date",
            "issuing_country",
        ]
    )
    custom_attributes: list[str] = Field(default_factory=list)
    custom_photoid_attributes: list[str] = Field(default_factory=list)
    custom_mdl_attributes: list[str] = Field(default_factory=list)
    custom_namespace: str = ""
    custom_namespace_attributes: list[str] = Field(default_factory=list)


SESSIONS: dict[str, SessionState] = {}
ANNEX_C_SESSIONS: dict[str, AnnexCSessionState] = {}


class AnnexCSessionCreateRequest(BaseModel):
    verifier_id: str = "urn:example:verifier"
    photoid_elements: list[str] = Field(
        default_factory=lambda: [
            "portrait",
            "family_name",
            "given_name",
            "birth_date",
            "age_over_18",
        ]
    )
    custom_attributes: list[str] = Field(default_factory=list)
    custom_photoid_attributes: list[str] = Field(default_factory=list)
    custom_namespace: str = ""
    custom_namespace_attributes: list[str] = Field(default_factory=list)


class AnnexCSubmitRequest(BaseModel):
    enc: str | None = None
    cipherText: str | None = None
    response: str | None = None
    protocol: str | None = None
    data: dict | None = None

    def extract_payload(self) -> tuple[str | None, str | None, str | None]:
        if self.enc and self.cipherText:
            return self.enc, self.cipherText, None
        if self.response:
            return None, None, self.response
        if isinstance(self.data, dict):
            response = self.data.get("response")
            if isinstance(response, str):
                return None, None, response
            enc = self.data.get("enc")
            cipher_text = self.data.get("cipherText")
            if isinstance(enc, str) and isinstance(cipher_text, str):
                return enc, cipher_text, None
        raise ValueError("Response payload must include enc/cipherText or data.response")


def _purge_expired_annex_c_sessions() -> None:
    expired = [session_id for session_id, state in ANNEX_C_SESSIONS.items() if state.expired]
    for session_id in expired:
        ANNEX_C_SESSIONS.pop(session_id, None)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/mdoc/session")
def create_session(config: SessionCreateRequest, request: Request):
    session_id = generate_session_id()
    request_url = str(request.url_for("wallet_transfer", session_id=session_id))
    state = new_session_state(
        session_id,
        request_url,
        SessionConfig(
            verifier_id=config.verifier_id,
            doc_type=config.doc_type,
            include_mdl=config.include_mdl,
            photoid_elements=config.photoid_elements,
            mdl_elements=config.mdl_elements,
            custom_attributes=config.custom_attributes,
            custom_photoid_attributes=config.custom_photoid_attributes,
            custom_mdl_attributes=config.custom_mdl_attributes,
            custom_namespace=config.custom_namespace,
            custom_namespace_attributes=config.custom_namespace_attributes,
        ),
    )
    SESSIONS[session_id] = state

    return {
        "session_id": session_id,
        "request_url": request_url,
        "verifier_id": config.verifier_id,
        "doc_type": config.doc_type,
        "include_mdl": config.include_mdl,
        "photoid_elements": config.photoid_elements,
        "mdl_elements": config.mdl_elements,
        "custom_attributes": config.custom_attributes,
        "custom_photoid_attributes": config.custom_photoid_attributes,
        "custom_mdl_attributes": config.custom_mdl_attributes,
        "custom_namespace": config.custom_namespace,
        "custom_namespace_attributes": config.custom_namespace_attributes,
        "reader_engagement_hex": state.reader_engagement.hex(),
        "reader_engagement_size": len(state.reader_engagement),
        "reader_public_key_hex": export_public_key_hex(state.reader_public_key),
        "mdoc_uri": build_mdoc_uri(state.reader_engagement),
    }


@app.post("/dc/session")
def create_annex_c_session(config: AnnexCSessionCreateRequest, request: Request):
    _purge_expired_annex_c_sessions()
    state = new_annex_c_session(
        AnnexCSessionConfig(
            verifier_id=config.verifier_id,
            photoid_elements=config.photoid_elements,
            custom_attributes=config.custom_attributes,
            custom_photoid_attributes=config.custom_photoid_attributes,
            custom_namespace=config.custom_namespace,
            custom_namespace_attributes=config.custom_namespace_attributes,
        )
    )
    ANNEX_C_SESSIONS[state.session_id] = state

    return {
        "session_id": state.session_id,
        "doc_type": "org.iso.23220.photoid.1",
        "response_url": str(request.url_for("digital_credentials_response", session_id=state.session_id)),
        "status_url": str(request.url_for("annex_c_session_status", session_id=state.session_id)),
        "expires_at": state.expires_at,
        "request_nonce_hex": state.request_nonce.hex(),
        "recipient_public_key_hex": export_annex_c_public_key_hex(state.recipient_public_key),
        "request": state.request_object(),
        "validation": state.validation_status,
        "notes": [
            "PhotoID-only Digital Credentials API MVP",
            "Response decryption is demo-grade and intended for local interoperability work",
            "Issuer authentication and device authentication validation are not implemented yet",
        ],
    }


@app.get("/mdoc/request")
def request_info():
    return {
        "message": "Create a session at POST /mdoc/session and use the returned transfer URL.",
    }


@app.get("/dc/session/{session_id}", name="annex_c_session_status")
def annex_c_session_status(session_id: str):
    _purge_expired_annex_c_sessions()
    state = ANNEX_C_SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": state.session_id,
        "doc_type": "org.iso.23220.photoid.1",
        "expired": state.expired,
        "expires_at": state.expires_at,
        "response_received": state.response_plaintext is not None or state.response_envelope is not None,
        "response_hex": (
            state.response_plaintext.hex()
            if state.response_plaintext
            else state.response_envelope.hex() if state.response_envelope else None
        ),
        "shared_attributes": state.shared_attributes,
        "response_preview": state.response_preview(),
        "validation": state.validation_status,
        "last_error": state.last_error,
        "request": state.request_object(),
    }


@app.get("/mdoc/session/{session_id}")
def session_status(session_id: str):
    state = SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": state.session_id,
        "request_url": state.request_url,
        "stage": state.stage,
        "response_received": state.response_plaintext is not None,
        "response_hex": state.response_plaintext.hex() if state.response_plaintext else None,
        "shared_attributes": state.shared_attributes,
        "debug_session_transcript_hex": state.session_transcript.hex() if state.session_transcript else None,
        "debug_transcript_salt_hex": state.transcript_salt.hex() if state.transcript_salt else None,
        "debug_shared_secret_hex": state.shared_secret.hex() if state.shared_secret else None,
        "debug_sk_device_hex": state.sk_device.hex() if state.sk_device else None,
        "debug_sk_reader_hex": state.sk_reader.hex() if state.sk_reader else None,
    }


@app.post("/mdoc/request/{session_id}", name="wallet_transfer")
async def wallet_transfer(session_id: str, request: Request):
    state = SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")

    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Request body is empty")

    try:
        if state.stage == 0:
            payload = state.create_initial_response(body)
        elif state.stage == 1:
            payload = state.handle_followup(body)
        else:
            payload = b""
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return Response(content=payload, media_type="application/cbor")


@app.post("/dc/response/{session_id}", name="digital_credentials_response")
def digital_credentials_response(session_id: str, payload: AnnexCSubmitRequest):
    _purge_expired_annex_c_sessions()
    state = ANNEX_C_SESSIONS.get(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        enc, cipher_text, response = payload.extract_payload()
        state.handle_response(enc, cipher_text, response)
    except ValueError as exc:
        state.last_error = str(exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        state.last_error = f"Decrypt failed: {exc}"
        raise HTTPException(status_code=400, detail="Decrypt failed") from exc

    return {
        "status": "ok",
        "session_id": state.session_id,
        "response_received": True,
        "shared_attributes": state.shared_attributes,
        "validation": state.validation_status,
    }


app.mount("/", StaticFiles(directory=".", html=True), name="static")
