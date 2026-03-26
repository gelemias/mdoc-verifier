from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel
from typing import Optional
import sys, os
 
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generate_photoid_request import build_device_request, build_mdoc_uri
 
app = FastAPI(title="mdoc Verifier API")
 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
 
class RequestConfig(BaseModel):
    request_url: str = "https://example.com/mdoc/request"
    verifier_id: str = "urn:example:verifier"
    include_mdl: Optional[bool] = False


def build_request_payload(config: RequestConfig):
    cbor_bytes, meta = build_device_request(
        request_url=config.request_url,
        verifier_id=config.verifier_id,
        include_mdl_core=config.include_mdl,
    )
    meta["mdoc_uri"] = build_mdoc_uri(cbor_bytes)
    return meta
 
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/mdoc/request")
def create_request_get(
    request_url: str = "https://example.com/mdoc/request",
    verifier_id: str = "urn:example:verifier",
    include_mdl: bool = False,
):
    return build_request_payload(
        RequestConfig(
            request_url=request_url,
            verifier_id=verifier_id,
            include_mdl=include_mdl,
        )
    )
 
@app.post("/mdoc/request")
def create_request(config: RequestConfig):
    return build_request_payload(config)
 
# Serve frontend at /
app.mount("/", StaticFiles(directory=".", html=True), name="static")
