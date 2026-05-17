#!/usr/bin/env python3
"""
Autonomous QBO re-authorization — zero terminal interaction.

Opens Eric's default browser for each book (Intuit session cookies handle login).
Local HTTPS callback server captures the redirect automatically.
Eric just clicks "Connect" in the browser × 3 books.

Usage:
    cd ~/qbo-mcp && uv run python scripts/reauth_autonomous.py
    cd ~/qbo-mcp && uv run python scripts/reauth_autonomous.py --only ecre
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dotenv import load_dotenv
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes

# Load env
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

CLIENT_ID = os.getenv("QBO_CLIENT_ID")
CLIENT_SECRET = os.getenv("QBO_CLIENT_SECRET")
ENVIRONMENT = os.getenv("QBO_ENVIRONMENT", "production")
REDIRECT_URI = os.getenv("QBO_REDIRECT_URI", "https://localhost:8001/callback")
PROJECT_ID = os.getenv("GCP_PROJECT_ID", "gen-lang-client-0253282755")
CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"

INSTANCES = [
    {
        "key": "ecre",
        # DBA display name (Kem renamed in QBO 2026-05-17; legal name stays
        # 'EC Real Estate Enterprise, Inc.' for tax/compliance — see
        # [[reference_ecre-dba-bauhaus-property-management]])
        "name": "Bauhaus Property Management",
        "realm_id": "1321803265",
        "divisions": "GRIP, ENGINE, MARKET",
        "token_file": Path("/Users/ericcuevas/qbo-mcp/tokens/ecre.json"),
        "gcp_secret": "qbo-tokens-ecre",
    },
    {
        "key": "bcd",
        "name": "Bauhaus Construction & Development",
        "realm_id": "9341453029568098",
        "divisions": "STEP",
        "token_file": Path("/Users/ericcuevas/qbo-mcp/tokens/bcd.json"),
        "gcp_secret": "qbo-tokens-bcd",
    },
    {
        "key": "bmr",
        "name": "Bauhaus Maintenance & Repairs",
        "realm_id": "9341453243233117",
        "divisions": "HEALTH",
        "token_file": Path("/Users/ericcuevas/qbo-mcp/tokens/bmr.json"),
        "gcp_secret": "qbo-tokens-bmr",
    },
]


class CallbackHandler(BaseHTTPRequestHandler):
    """Captures OAuth callback with code + realmId."""
    code = None
    realm_id = None
    error = None
    done = threading.Event()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if "code" in params and "realmId" in params and parsed.path == "/callback":
            CallbackHandler.code = params["code"][0]
            CallbackHandler.realm_id = params["realmId"][0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='font-family:system-ui;text-align:center;padding:60px'>"
                b"<h1 style='color:#22c55e'>&#10003; Authorized</h1>"
                b"<p>You can close this tab. Next company will open automatically.</p>"
                b"</body></html>"
            )
            CallbackHandler.done.set()
        elif "error" in params:
            CallbackHandler.error = params.get("error", ["unknown"])[0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Auth failed</h1></body></html>")
            CallbackHandler.done.set()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress server logs


def reset_handler():
    CallbackHandler.code = None
    CallbackHandler.realm_id = None
    CallbackHandler.error = None
    CallbackHandler.done = threading.Event()


def save_to_gcp(secret_name: str, tokens: dict) -> bool:
    result = subprocess.run(
        ["gcloud", "secrets", "versions", "add", secret_name,
         f"--project={PROJECT_ID}", "--data-file=-"],
        input=json.dumps(tokens), capture_output=True, text=True,
    )
    return result.returncode == 0


def authorize_instance(info: dict, httpd: HTTPServer) -> dict | None:
    """Run OAuth for one QBO instance using local callback server."""
    reset_handler()

    print(f"\n{'='*60}")
    print(f"  [{info['key'].upper()}] {info['name']}")
    print(f"  Divisions: {info['divisions']}")
    print(f"  >>> SELECT THIS COMPANY IN THE BROWSER <<<")
    print(f"{'='*60}")

    auth_client = AuthClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        environment=ENVIRONMENT,
    )

    auth_url = auth_client.get_authorization_url(scopes=[Scopes.ACCOUNTING])
    print(f"  Opening browser... click Connect for: {info['name']}")
    webbrowser.open(auth_url)

    # Wait for callback (timeout 120s)
    if not CallbackHandler.done.wait(timeout=120):
        print(f"  TIMEOUT — no callback received in 120s")
        return None

    if CallbackHandler.error:
        print(f"  ERROR: {CallbackHandler.error}")
        return None

    code = CallbackHandler.code
    realm_id = CallbackHandler.realm_id

    if not code or not realm_id:
        print(f"  ERROR: Missing code or realmId")
        return None

    if realm_id != info["realm_id"]:
        print(f"  WARNING: Expected realm {info['realm_id']} but got {realm_id}")
        print(f"  Wrong company selected — skipping")
        return None

    print(f"  Exchanging code for tokens...")
    try:
        auth_client.get_bearer_token(code, realm_id=realm_id)
    except Exception as e:
        print(f"  ERROR: Token exchange failed: {e}")
        return None

    tokens = {
        "access_token": auth_client.access_token,
        "refresh_token": auth_client.refresh_token,
        "environment": ENVIRONMENT,
        "realm_id": realm_id,
    }

    if not tokens["access_token"] or not tokens["refresh_token"]:
        print("  ERROR: Missing tokens in response.")
        return None

    print(f"  SUCCESS — tokens obtained for {info['name']}")
    return tokens


def main():
    parser = argparse.ArgumentParser(description="Autonomous QBO OAuth re-auth")
    parser.add_argument("--only", choices=["ecre", "bcd", "bmr"])
    args = parser.parse_args()

    if not CLIENT_ID or not CLIENT_SECRET:
        print("ERROR: QBO_CLIENT_ID and QBO_CLIENT_SECRET must be set in .env")
        sys.exit(1)

    targets = [i for i in INSTANCES if not args.only or i["key"] == args.only]

    # Start HTTPS callback server
    parsed = urlparse(REDIRECT_URI)
    host = parsed.hostname or "localhost"
    port = parsed.port or 8001

    httpd = HTTPServer((host, port), CallbackHandler)
    cert_file = CERTS_DIR / "localhost.crt"
    key_file = CERTS_DIR / "localhost.key"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    print(f"  Callback server listening on {REDIRECT_URI}")

    results = {}

    for info in targets:
        tokens = authorize_instance(info, httpd)

        if tokens:
            # Save locally
            with open(info["token_file"], "w") as f:
                json.dump(tokens, f, indent=2)
            print(f"  Saved to: {info['token_file']}")

            # Save to GCP
            if save_to_gcp(info["gcp_secret"], tokens):
                print(f"  Saved to GCP: {info['gcp_secret']}")
            else:
                print(f"  GCP save failed (local is fine)")

            results[info["key"]] = "SUCCESS"
        else:
            results[info["key"]] = "FAILED"

        time.sleep(2)  # Brief pause between books

    httpd.shutdown()

    # Summary
    print(f"\n{'='*60}")
    print("  RESULTS")
    print(f"{'='*60}")
    for info in targets:
        status = results.get(info["key"], "FAILED")
        symbol = "+" if status == "SUCCESS" else "X"
        print(f"  [{symbol}] {info['key'].upper()} ({info['name']}): {status}")

    all_ok = all(results.get(i["key"]) == "SUCCESS" for i in targets)
    if all_ok:
        print(f"\n  All 3 QBO tokens refreshed. MCP servers will use new tokens on next request.")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
