#!/usr/bin/env python3
"""ISO 23220-7 PhotoID Presentation Request Generator."""

import argparse
import json
from mdoc_verifier.core import build_device_request, build_mdoc_uri

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--qr", action="store_true")
    parser.add_argument("--request-url", default="https://example.com/mdoc/request")
    args = parser.parse_args()

    cbor_bytes, meta = build_device_request(request_url=args.request_url)

    mdoc_uri = build_mdoc_uri(cbor_bytes)

    if args.json:
        meta["mdoc_uri"] = mdoc_uri
        print(json.dumps(meta, indent=2))
    else:
        print("=== DeviceRequest ===")
        print(f"Size: {meta['cbor_size']} bytes")
        print(f"Hex: {meta['cbor_hex'][:120]}...")
        print()
        print("=== mdoc URI ===")
        print(mdoc_uri)

    if args.qr:
        try:
            import qrcode
            qr = qrcode.QRCode(border=1)
            qr.add_data(mdoc_uri)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            print("Install qrcode package to enable QR output")


if __name__ == "__main__":
    main()
