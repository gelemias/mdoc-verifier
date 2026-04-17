from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

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


@app.get("/mdoc/request")
def request_info():
    return {
        "message": "Create a session at POST /mdoc/session and use the returned transfer URL.",
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


app.mount("/", StaticFiles(directory=".", html=True), name="static")
