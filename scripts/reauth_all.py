#!/usr/bin/env python3
"""
Re-authorize all 3 QBO instances in one streamlined session.

When refresh tokens are fully expired, this script handles the complete
OAuth re-authorization for all 3 QBO books (ECRE, BCD, BMR) in sequence.

Uses the Intuit OAuth2 Playground redirect URI (registered for production).
The user authorizes in the browser, then pastes the redirect URL back.

Usage:
    cd ~/qbo-mcp
    uv run python scripts/reauth_all.py

    # Or just one instance:
    uv run python scripts/reauth_all.py --only ecre
"""

import argparse
import json
import os
import subprocess
import sys
import webbrowser
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
PROJECT_ID = os.getenv("GCP_PROJECT_ID", "gen-lang-client-0253282755")

# Production-registered redirect URI
REDIRECT_URI = "https://developer.intuit.com/v2/OAuth2Playground/RedirectUrl"

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


def save_to_gcp(secret_name: str, tokens: dict) -> bool:
    """Push tokens to GCP Secret Manager."""
    result = subprocess.run(
        ["gcloud", "secrets", "versions", "add", secret_name,
         f"--project={PROJECT_ID}", "--data-file=-"],
        input=json.dumps(tokens), capture_output=True, text=True,
    )
    return result.returncode == 0


def authorize_instance(info: dict) -> dict | None:
    """Run OAuth for one QBO instance. Returns tokens dict or None."""
    print(f"\n{'='*65}")
    print(f"  [{info['key'].upper()}] {info['name']}")
    print(f"  Divisions: {info['divisions']}")
    print(f"  Expected Realm ID: {info['realm_id']}")
    print(f"{'='*65}")

    auth_client = AuthClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        environment=ENVIRONMENT,
    )

    auth_url = auth_client.get_authorization_url(scopes=[Scopes.ACCOUNTING])
    print(f"\n  Opening browser...")
    print(f"  >>> SELECT: {info['name']} <<<")
    webbrowser.open(auth_url)

    print(f"\n  After authorizing, you'll be redirected to the Intuit Playground.")
    print(f"  Copy the FULL URL from the browser address bar and paste it here.\n")

    callback_url = input("  Paste URL > ").strip()
    if not callback_url:
        print("  Skipped (no URL provided).")
        return None

    # Parse callback URL
    parsed = urlparse(callback_url)
    params = parse_qs(parsed.query)
    if not params and parsed.fragment:
        params = parse_qs(parsed.fragment)

    code = params.get("code", [None])[0]
    realm_id = params.get("realmId", [None])[0]

    if not code:
        print(f"  ERROR: No 'code' found in URL. Got params: {list(params.keys())}")
        return None
    if not realm_id:
        print(f"  ERROR: No 'realmId' found in URL.")
        return None

    # Warn if realm doesn't match
    if realm_id != info["realm_id"]:
        print(f"\n  WARNING: Expected realm {info['realm_id']} but got {realm_id}")
        resp = input("  Continue anyway? (y/N) > ").strip().lower()
        if resp != "y":
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

    print(f"  SUCCESS!")
    return tokens


def main():
    parser = argparse.ArgumentParser(description="Re-authorize QBO OAuth tokens")
    parser.add_argument("--only", choices=["ecre", "bcd", "bmr"],
                        help="Re-authorize only one specific instance")
    args = parser.parse_args()

    if not CLIENT_ID or not CLIENT_SECRET:
        print("ERROR: QBO_CLIENT_ID and QBO_CLIENT_SECRET must be set in .env")
        sys.exit(1)

    targets = [i for i in INSTANCES if not args.only or i["key"] == args.only]

    print("=" * 65)
    print("  QBO OAUTH RE-AUTHORIZATION")
    print("=" * 65)
    print(f"\n  Instances: {', '.join(i['key'].upper() for i in targets)}")
    print(f"  Environment: {ENVIRONMENT}")
    print(f"\n  For each company:")
    print(f"    1. Browser opens to Intuit")
    print(f"    2. Log in (if needed)")
    print(f"    3. Select the CORRECT company")
    print(f"    4. Click 'Connect'")
    print(f"    5. Copy the URL from the redirect page")
    print(f"    6. Paste it here")
    print(f"\n  Press Enter to begin...")
    input()

    results = {}

    for info in targets:
        tokens = authorize_instance(info)

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

    # Summary
    print(f"\n{'='*65}")
    print("  SUMMARY")
    print(f"{'='*65}")
    for info in targets:
        status = "OK" if results[info["key"]] == "SUCCESS" else "FAILED"
        symbol = "+" if status == "OK" else "X"
        print(f"  [{symbol}] {info['key'].upper()} ({info['name']}): {status}")

    all_ok = all(results[i["key"]] == "SUCCESS" for i in targets)
    if all_ok:
        print(f"\n  All tokens refreshed!")
        print(f"  MCP servers will use new tokens on next request.")
        print(f"\n  Verify with:")
        print(f"    cd ~/bauhaus-data && source venv/bin/activate")
        print(f"    python3 scripts/bg_score_ingest_qbo.py --dry-run")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
