#!/usr/bin/env python3
"""
QBO re-auth via Playwright — fully autonomous.

Uses the Intuit Playground redirect URI (registered). Playwright captures
the redirect URL with code+realmId automatically. Eric just clicks Connect.

Usage:
    cd ~/qbo-mcp && uv run python scripts/reauth_playwright.py
    cd ~/qbo-mcp && uv run python scripts/reauth_playwright.py --only ecre
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dotenv import load_dotenv
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

CLIENT_ID = os.getenv("QBO_CLIENT_ID")
CLIENT_SECRET = os.getenv("QBO_CLIENT_SECRET")
ENVIRONMENT = os.getenv("QBO_ENVIRONMENT", "production")
PROJECT_ID = os.getenv("GCP_PROJECT_ID", "gen-lang-client-0253282755")

# Use the registered Intuit Playground redirect URI
REDIRECT_URI = "https://developer.intuit.com/v2/OAuth2Playground/RedirectUrl"

INSTANCES = [
    {
        "key": "ecre",
        # Renamed by Kem: ECRE → "Bauhaus Property Management" (2026-05-17) →
        # "Bauhaus Group" (current, confirmed live via CompanyInfo 2026-07-19).
        # Legal name is still EC REAL ESTATE ENTERPRISE, INC.; realm_id and book
        # are unchanged — only the display name on Intuit's company-picker page
        # changed. Keep this in sync with the live CompanyName so Playwright can
        # find the right company to click Connect on (a stale name failed twice).
        "name": "Bauhaus Group",
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
    result = subprocess.run(
        ["gcloud", "secrets", "versions", "add", secret_name,
         f"--project={PROJECT_ID}", "--data-file=-"],
        input=json.dumps(tokens), capture_output=True, text=True,
    )
    return result.returncode == 0


def authorize_instance(info: dict, page) -> dict | None:
    """Run OAuth for one instance using Playwright to capture the redirect."""
    print(f"\n{'='*60}")
    print(f"  [{info['key'].upper()}] {info['name']}")
    print(f"  Divisions: {info['divisions']}")
    print(f"  >>> SELECT: {info['name']} <<<")
    print(f"{'='*60}")

    auth_client = AuthClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        environment=ENVIRONMENT,
    )

    auth_url = auth_client.get_authorization_url(scopes=[Scopes.ACCOUNTING])
    print(f"  Navigating to Intuit auth...")

    # Navigate — use domcontentloaded (networkidle hangs on Intuit's tracking scripts)
    page.goto(auth_url, wait_until="domcontentloaded", timeout=60000)

    # Wait for the redirect — the URL will contain code= and realmId=
    # User needs to log in, select company, and click Connect
    print(f"  Waiting for authorization (select: {info['name']})...")
    print(f"  You have 5 minutes — log in, select the company, click Connect")

    try:
        # Wait for URL to contain 'code=' (max 5 minutes for login + company selection)
        page.wait_for_url("**/RedirectUrl**code=*", timeout=300000)
    except Exception:
        # Try checking current URL anyway
        pass

    current_url = page.url
    print(f"  Captured redirect URL")

    # Parse code and realmId from the URL
    parsed = urlparse(current_url)
    params = parse_qs(parsed.query)
    if not params:
        params = parse_qs(parsed.fragment)

    code = params.get("code", [None])[0]
    realm_id = params.get("realmId", [None])[0]

    if not code:
        print(f"  ERROR: No 'code' in URL: {current_url[:100]}...")
        return None

    if not realm_id:
        print(f"  ERROR: No 'realmId' in URL")
        return None

    if realm_id != info["realm_id"]:
        print(f"  WARNING: Expected realm {info['realm_id']} but got {realm_id}")
        print(f"  Wrong company selected — skipping")
        return None

    print(f"  Code captured for realm {realm_id}. Exchanging for tokens...")

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

    print(f"  SUCCESS — tokens obtained!")
    return tokens


def main():
    parser = argparse.ArgumentParser(description="QBO OAuth re-auth via Playwright")
    parser.add_argument("--only", choices=["ecre", "bcd", "bmr"])
    args = parser.parse_args()

    if not CLIENT_ID or not CLIENT_SECRET:
        print("ERROR: QBO_CLIENT_ID and QBO_CLIENT_SECRET must be set in .env")
        sys.exit(1)

    targets = [i for i in INSTANCES if not args.only or i["key"] == args.only]

    print("="*60)
    print("  QBO OAUTH RE-AUTH (Playwright)")
    print("="*60)
    print(f"  Instances: {', '.join(i['key'].upper() for i in targets)}")
    print(f"  Browser will open — just click 'Connect' for each company")

    results = {}

    with sync_playwright() as p:
        # Launch visible browser (not headless) so Eric can interact
        browser = p.chromium.launch(
            headless=False,
            args=["--disable-blink-features=AutomationControlled"],
        )
        context = browser.new_context(
            viewport={"width": 1200, "height": 800},
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        page = context.new_page()

        for info in targets:
            tokens = authorize_instance(info, page)

            if tokens:
                with open(info["token_file"], "w") as f:
                    json.dump(tokens, f, indent=2)
                print(f"  Saved to: {info['token_file']}")

                if save_to_gcp(info["gcp_secret"], tokens):
                    print(f"  Saved to GCP: {info['gcp_secret']}")
                else:
                    print(f"  GCP save failed (local is fine)")

                results[info["key"]] = "SUCCESS"
            else:
                results[info["key"]] = "FAILED"

            time.sleep(1)

        browser.close()

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
        print(f"\n  All QBO tokens refreshed! MCP servers will use new tokens on next request.")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
