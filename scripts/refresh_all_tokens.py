#!/usr/bin/env python3
"""
Refresh all 3 QBO OAuth tokens using GCP Secret Manager as the source.

The local token files may have stale refresh tokens (consumed by running MCP server
processes without saving back to disk). GCP Secret Manager often has the last-saved
version from when the MCP servers were healthy.

Usage:
    python3 scripts/refresh_all_tokens.py

This script will:
1. Read refresh tokens from GCP Secret Manager (qbo-tokens-{ecre,bcd,bmr})
2. Call the Intuit token endpoint to get new access + refresh tokens
3. Save new tokens to BOTH local files AND GCP Secret Manager
4. Report success/failure for each instance
"""

import json
import base64
import subprocess
import sys
import urllib.request
import urllib.parse
import ssl
from pathlib import Path

CLIENT_ID = "ABIGnvF0yJf5Kfamzng9ONwhnzw9yonrCTNt2Z7a14BHj38TXg"
CLIENT_SECRET = "lPMDHrLH3ZGLUOWQB7nJWRwPDsqDiVPMqAsneo8G"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
PROJECT_ID = "gen-lang-client-0253282755"

AUTH_STRING = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

INSTANCES = {
    "ecre": {
        "secret": "qbo-tokens-ecre",
        "local": Path("/Users/ericcuevas/qbo-mcp/tokens/ecre.json"),
        "realm_id": "1321803265",
        # DBA display (Kem renamed 2026-05-17; legal 'EC Real Estate Enterprise, Inc.' unchanged)
        "book": "Bauhaus Property Management",
    },
    "bcd": {
        "secret": "qbo-tokens-bcd",
        "local": Path("/Users/ericcuevas/qbo-mcp/tokens/bcd.json"),
        "realm_id": "9341453029568098",
        "book": "Bauhaus Construction & Development",
    },
    "bmr": {
        "secret": "qbo-tokens-bmr",
        "local": Path("/Users/ericcuevas/qbo-mcp/tokens/bmr.json"),
        "realm_id": "9341453243233117",
        "book": "Bauhaus Maintenance & Repairs",
    },
}


def read_gcp_secret(secret_name: str) -> dict | None:
    """Read latest version of a secret from GCP Secret Manager."""
    result = subprocess.run(
        [
            "gcloud", "secrets", "versions", "access", "latest",
            f"--secret={secret_name}", f"--project={PROJECT_ID}",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"    GCP read error: {result.stderr.strip()}")
        return None
    return json.loads(result.stdout)


def write_gcp_secret(secret_name: str, tokens: dict) -> bool:
    """Write a new version of tokens to GCP Secret Manager."""
    result = subprocess.run(
        [
            "gcloud", "secrets", "versions", "add", secret_name,
            f"--project={PROJECT_ID}", "--data-file=-",
        ],
        input=json.dumps(tokens), capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"    GCP write error: {result.stderr.strip()}")
        return False
    return True


def refresh_token(refresh_tok: str) -> dict | None:
    """Call Intuit token endpoint to refresh the access token."""
    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_tok,
    }).encode()

    req = urllib.request.Request(TOKEN_URL, data=data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Authorization", f"Basic {AUTH_STRING}")
    req.add_header("Accept", "application/json")

    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        print(f"    HTTP ERROR {e.code}: {error_body}")
        return None
    except Exception as e:
        print(f"    ERROR: {e}")
        return None


def try_refresh_from_source(source_name: str, tokens: dict, realm_id: str) -> dict | None:
    """Try to refresh using tokens from a given source."""
    rt = tokens.get("refresh_token")
    if not rt:
        print(f"    No refresh token in {source_name}")
        return None

    print(f"    Trying {source_name} refresh token: {rt[:25]}...")
    response = refresh_token(rt)

    if response and response.get("access_token") and response.get("refresh_token"):
        return {
            "access_token": response["access_token"],
            "refresh_token": response["refresh_token"],
            "environment": "production",
            "realm_id": realm_id,
        }
    return None


def main():
    print("=" * 70)
    print("QBO OAuth Token Refresher — All 3 Instances")
    print("=" * 70)

    results = {}

    for name, info in INSTANCES.items():
        print(f"\n{'─' * 70}")
        print(f"  {name.upper()} — {info['book']} (Realm: {info['realm_id']})")
        print(f"{'─' * 70}")

        new_tokens = None

        # Strategy 1: Try GCP Secret Manager tokens first
        print("\n  [1] Reading from GCP Secret Manager...")
        gcp_tokens = read_gcp_secret(info["secret"])
        if gcp_tokens:
            new_tokens = try_refresh_from_source("GCP", gcp_tokens, info["realm_id"])

        # Strategy 2: Try local file tokens
        if not new_tokens:
            print("\n  [2] Trying local token file...")
            try:
                with open(info["local"]) as f:
                    local_tokens = json.load(f)
                new_tokens = try_refresh_from_source("local", local_tokens, info["realm_id"])
            except Exception as e:
                print(f"    Local file error: {e}")

        # Save results
        if new_tokens:
            # Save to local
            with open(info["local"], "w") as f:
                json.dump(new_tokens, f, indent=2)
            print(f"\n  ✅ Saved to local: {info['local']}")

            # Save to GCP
            if write_gcp_secret(info["secret"], new_tokens):
                print(f"  ✅ Saved to GCP: {info['secret']}")
            else:
                print(f"  ⚠️  Local saved but GCP write failed")

            print(f"  New refresh token: {new_tokens['refresh_token'][:30]}...")
            results[name] = "SUCCESS"
        else:
            print(f"\n  ❌ FAILED — Both GCP and local refresh tokens are expired.")
            print(f"     Run: uv run python scripts/get_tokens.py --token-file tokens/{name}.json --push-to-gcp")
            results[name] = "FAILED"

    # Summary
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    all_success = True
    for name, result in results.items():
        status = "✅" if result == "SUCCESS" else "❌"
        print(f"  {status} {name.upper()}: {result}")
        if result != "SUCCESS":
            all_success = False

    if not all_success:
        print(f"\n{'=' * 70}")
        print("MANUAL RE-AUTH REQUIRED FOR FAILED INSTANCES")
        print(f"{'=' * 70}")
        print("Run the following for each failed instance:")
        print("  cd ~/qbo-mcp")
        for name, result in results.items():
            if result != "SUCCESS":
                print(f"  uv run python scripts/get_tokens.py --token-file tokens/{name}.json --push-to-gcp")
        print("\nThis will open a browser for Intuit OAuth. Log in, authorize,")
        print("copy the redirect URL, and paste it back into the terminal.")

    sys.exit(0 if all_success else 1)


if __name__ == "__main__":
    main()
