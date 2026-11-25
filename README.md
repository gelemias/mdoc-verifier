# mdoc Verifier

A FastAPI interoperability tool for requesting and inspecting mobile identity documents. It supports the Digital Credentials API using ISO/IEC TS 18013-7:2025 Annex C and QR/deep-link reverse engagement. The browser also includes a CBOR inspector and session activity view.

## Run locally

Use Python 3.12 or newer.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn server.main:app --no-access-log
```

Open [localhost:8000](http://localhost:8000). Local session URLs use the loopback origin. The endpoint tester is shown on loopback hosts. A QR scanned on another device needs a reachable HTTPS deployment. Annex C needs a browser with Digital Credentials API support and a wallet that can present the requested document. Generate a request and then select **Open wallet** to launch the browser chooser.

## Configure verification and remote access

| Variable | Purpose |
| --- | --- |
| `MDOC_PUBLIC_ORIGIN` | External HTTPS origin as seen by the browser, such as `https://verifier.example`, without a path, trailing slash, or default port. Required for non-loopback deployments. |
| `MDOC_ISSUER_CA_PEM` | PEM bundle of trusted issuer CA certificates for the credentials you expect. Use a bundle dedicated to mdoc issuers. Strict verification requires an issuer CA. |
| `MDOC_ALLOW_UNTRUSTED_ISSUER` | Set to `true` to enable test inspection when an issuer CA and CRL are both absent. Strict verification is the default. |
| `MDOC_ISSUER_CRL_PEM` | Optional PEM issuer CRL. When set, OpenSSL requires valid CRL coverage across the issuer chain. Keep the CRL current. The app makes no online revocation requests. |
| `MDOC_READER_KEY_PEM` | Optional EC private key in PEM format for signed Annex C requests. Store it outside the static directory and give the service account read access only. |
| `MDOC_READER_CHAIN_PEM` | PEM certificate chain for the reader key, beginning with the reader certificate. Set it together with the key. Apple Wallet requires a certificate provisioned through Apple Business Connect. |

Annex C requests use document request version 1.0 when unsigned. Configuring a reader identity enables signed 1.1 requests with `readerAuthAll`. The UI supports PhotoID and mDL in Annex C. It decrypts the response, validates the issuer certificate and signature, checks the MSO and claim digests, and verifies the holder's proof. The QR path also supports ISO device MAC authentication.

For a Render test service, add `MDOC_ALLOW_UNTRUSTED_ISSUER=true` under **Environment**, deploy, and create a fresh request. Inspection still checks the document signature against the supplied signer certificate, claim digests, document validity, and device proof. It skips the issuer trust-chain check and labels the attributes **Unverified issuer** in the browser and `validation.issuer_auth: unverified` in the API. A configured CA always requires strict verification. Reader authentication remains separately configured.

Run one worker behind HTTPS because sessions are held in process memory and expire after five minutes. Forward HTTPS requests to the application from a trusted proxy, and set the public origin explicitly. The app serves its static files from `static/`. Session status requires the separately generated bearer token. Share the short-lived QR transfer URL only with the intended wallet and exclude session URLs from proxy access logs.

## Endpoints

| Endpoint | Use |
| --- | --- |
| `GET /health` | Health check |
| `POST /dc/session` | Create a Digital Credentials request and return its request object, session ID, and access token |
| `POST /dc/response/{session_id}` | Submit the browser's `org-iso-mdoc` credential with `Authorization: Bearer <access_token>`. The payload is `{"protocol":"org-iso-mdoc","data":{"response":"..."}}`. |
| `GET /dc/session/{session_id}` | Get Annex C status, claims and their verification result with the access token |
| `POST /mdoc/session` | Create a QR session and return the `mdoc://` URI, transfer URL, and access token |
| `POST /mdoc/request/{session_id}` | Exchange wallet CBOR over the QR transfer URL |
| `GET /mdoc/session/{session_id}` | Get QR status, claims and their verification result with the access token |

An Annex C response that fails decryption or authentication returns an error and leaves the session available for another response. Successful responses close the session. The former demo `enc` / `cipherText` JSON submission and raw response and key fields are removed.

## Checks

```sh
python -m pip install httpx2==2.16.2
python smoke_annex_c.py
python smoke_iso_session.py
```

The Annex C smoke test checks transcript and HPKE interoperability against an independently published synthetic vector and verifies a complete synthetic response under a local test CA. The QR smoke test exercises the encrypted transfer, claim validation, and termination. Neither test requires a real identity document.
