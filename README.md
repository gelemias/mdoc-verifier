# mdoc-verifier

`mdoc-verifier` is a small FastAPI-based demo verifier for ISO 18013 web retrieval flows. It generates `mdoc://` QR/deep links, accepts CBOR posts from a wallet over HTTP, derives the session keys for the transfer, and returns a CBOR `DeviceRequest` inside the encrypted session response.

The project is intentionally narrow and demo-oriented. It is designed to help test wallet interoperability, especially for PhotoID-style requests, not to be a production-grade verifier service.

**What This Project Does**
It currently covers these main features:

- Serves a browser UI from `[index.html](/Users/<username>/Developer/mdoc-verifier/index.html)` for generating a fresh verifier session and rendering a QR code.
- Creates a server-owned session at `POST /mdoc/session`.
- Generates a unique per-session request URL in the form `/mdoc/request/{session_id}`.
- Generates a `ReaderEngagement` payload and wraps it as an `mdoc://` URI.
- Accepts wallet posts with `Content-Type: application/cbor`.
- Parses `deviceEngagementBytes` from the incoming CBOR message.
- Extracts the wallet/device ephemeral EC public key from the device engagement.
- Builds a session transcript and derives session keys.
- Encrypts and returns a `DeviceRequest` as CBOR `SessionData`.
- Accepts one follow-up encrypted wallet message and returns a termination status (`20`).
- Exposes session debug information at `GET /mdoc/session/{session_id}` to help with protocol troubleshooting.
- Includes a local smoke test in `[smoke_iso_session.py](/Users/<username>/Developer/mdoc-verifier/smoke_iso_session.py)` that exercises the session end to end without deploying.

**Protocol Notes**
This repo implements a minimal reverse-engagement style online retrieval flow inspired by the NIST / Google Identity Credential reference behavior.

High-level flow:

1. The browser asks the backend to create a session.
2. The backend generates an ephemeral reader key pair and a `ReaderEngagement`.
3. The frontend renders the returned `mdoc://` URI as a QR code.
4. The wallet scans the QR and posts a CBOR message containing `deviceEngagementBytes` to the session-specific request URL.
5. The server derives the session transcript and symmetric keys.
6. The server returns encrypted CBOR containing a `DeviceRequest`.
7. The wallet may send a follow-up encrypted message.
8. The server replies with a CBOR termination status.

This behavior lives primarily in:

- `[server/main.py](/Users/<username>/Developer/mdoc-verifier/server/main.py)`
- `[mdoc_verifier/iso_session.py](/Users/<username>/Developer/mdoc-verifier/mdoc_verifier/iso_session.py)`

**Hardcoded / Intentional Constraints**
Several protocol details are currently fixed in code. These are important to understand if you are testing interoperability.

- Curve: `P-256` / `secp256r1`
- COSE key type: `EC2`
- COSE curve id: `1` (`P-256`)
- Cipher suite in engagement: `1`
- ECDH: NIST P-256 ECDH using the reader ephemeral private key and device ephemeral public key
- HKDF hash: `SHA-256`
- Session encryption: `AES-GCM`
- Session key length: `32 bytes`
- Session labels:
  - `SKDevice`
  - `SKReader`
- CBOR semantic tag for embedded CBOR: `24`
- Reader engagement version: `"1.1"`
- Device request version: `"1.0"`
- First encrypted response is sent using the derived reader session key
- IV structure is fixed to the ISO 18013-style `12` byte format with a counter and role identifier
- Session storage is in-memory only
- Session lifecycle is very short and effectively single-use
- Current implementation returns one `DeviceRequest` and one termination response
- No reader authentication object (`readerAuth`) is included in the generated `DeviceRequest`
- No certificate-based reader authentication is performed
- No persistence layer is used for sessions or responses

**Endpoints**
Main HTTP endpoints:

- `GET /`
  Serves the browser UI.

- `GET /health`
  Simple health check.

- `POST /mdoc/session`
  Creates a new verifier session and returns JSON with:
  - `session_id`
  - `request_url`
  - `mdoc_uri`
  - `reader_engagement_hex`
  - `reader_public_key_hex`
  - request metadata

- `GET /mdoc/session/{session_id}`
  Returns session status and debug fields, including:
  - current stage
  - whether a device response has been received
  - transcript / key derivation debug values

- `POST /mdoc/request/{session_id}`
  Accepts wallet CBOR messages and returns CBOR.

- `GET /mdoc/request`
  A helper informational endpoint indicating that a real session must first be created.

**Project Layout**

- `[server/main.py](/Users/<username>/Developer/mdoc-verifier/server/main.py)`
  FastAPI app and HTTP endpoints.

- `[mdoc_verifier/iso_session.py](/Users/<username>/Developer/mdoc-verifier/mdoc_verifier/iso_session.py)`
  Session creation, engagement parsing, transcript building, HKDF, and AES-GCM helpers.

- `[index.html](/Users/<username>/Developer/mdoc-verifier/index.html)`
  Browser UI for generating sessions and rendering QR codes.

- `[smoke_iso_session.py](/Users/<username>/Developer/mdoc-verifier/smoke_iso_session.py)`
  Local dry-run test of the session flow.

- `[requirements.txt](/Users/<username>/Developer/mdoc-verifier/requirements.txt)`
  Python dependencies.

**Local Development**
Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the server locally:

```bash
uvicorn server.main:app --reload
```

Open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/health`

**Local Smoke Test**
To verify the backend session flow without deploying:

```bash
python3 smoke_iso_session.py
```

Expected output is similar to:

```text
Decrypted docType: org.iso.23220.photoid.1
Termination response: {'status': 20}
```

This test:

- creates a backend session
- simulates a device posting `deviceEngagementBytes`
- decrypts the backend response using the derived session key
- verifies the returned `DeviceRequest`
- sends a follow-up encrypted message
- confirms termination status

**Using The Web UI**
From the home page you can:

- choose a `docType`
- toggle whether mDL elements are included
- select the desired PhotoID and mDL data elements
- create a new backend session
- display an `mdoc://` URI and QR code
- inspect request/session debug data in the UI

Important behavior:

- the QR is generated from a server-created session, not from browser-only crypto
- every new request creates a new session id
- the QR should be regenerated for each wallet test

**Render.com Deployment**
This app works well as a simple Render web service.

Recommended settings:

- Environment: `Python`
- Build Command:

```bash
pip install -r requirements.txt
```

- Start Command:

```bash
uvicorn server.main:app --host 0.0.0.0 --port $PORT
```

Do not start it with `python main.py`. The entrypoint is the ASGI app in `[server/main.py](/Users/<username>/Developer/mdoc-verifier/server/main.py)`.

After deployment:

1. Open your Render URL.
2. Generate a fresh session from the UI.
3. Make sure the shown request URL includes `/mdoc/request/{session_id}`.
4. Scan the newly generated QR with the wallet.

Useful Render checks:

- Health check path: `/health`
- Main UI path: `/`
- Session creation is server-side, so stale instances or redeploys invalidate old QR codes

**Important Render Caveats**
Because sessions are stored in memory:

- redeploying the service invalidates active sessions
- instance restarts invalidate active sessions
- multiple replicas would not share session state
- free-tier sleep/spin-up behavior can break a scan if the app sleeps between QR generation and wallet POST

For stable multi-user or long-lived use, replace the in-memory `SESSIONS` map with shared storage such as Redis or a database.

**Debugging Interoperability**
If a wallet scan reaches the POST step but decryption/authentication fails, inspect:

- `GET /mdoc/session/{session_id}`

Debug fields include:

- `debug_session_transcript_hex`
- `debug_transcript_salt_hex`
- `debug_shared_secret_hex`
- `debug_sk_device_hex`
- `debug_sk_reader_hex`

These are useful for comparing your server state with wallet logs when troubleshooting:

- session transcript construction
- transcript hash / salt mismatches
- ECDH shared secret mismatches
- HKDF label / role mismatches
- first-message encryption key selection

**Current Limitations**
This project is intentionally incomplete relative to a production verifier.

- No persistent session store
- No replay protection beyond the in-memory session lifecycle
- No reader certificate chain or signed `readerAuth`
- No production-grade request validation
- No production logging / secrets management
- No support for multiple parallel requests within one session
- No complete `DeviceResponse` parsing and display pipeline yet
- No authentication, authorization, or rate limiting on the server

**Dependencies**
Current Python dependencies from `[requirements.txt](/Users/<username>/Developer/mdoc-verifier/requirements.txt)`:

- `fastapi`
- `uvicorn[standard]`
- `cbor2`
- `cryptography`
- `python-multipart`

**Status**
The codebase currently targets interoperability testing and reverse-engineering of working holder behavior. It is most useful as:

- a debugging harness for wallet/web retrieval experiments
- a compact example of server-owned QR session creation
- a testbed for comparing behavior with NIST-compatible flows
