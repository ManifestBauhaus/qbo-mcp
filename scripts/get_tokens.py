#!/usr/bin/env python3
"""
One-time OAuth token fetcher for QBO MCP.

Uses Intuit's OAuth2 Playground redirect URI (already registered for Production)
to capture the auth code, then exchanges it for tokens programmatically.

Usage:
    uv run python scripts/get_tokens.py --token-file tokens/ecre.json
    uv run python scripts/get_tokens.py --token-file tokens/bcd.json
    uv run python scripts/get_tokens.py --token-file tokens/bmr.json
"""

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv
from intuitlib.client import AuthClient
from intuitlib.enums import Scopes

# Intuit's OAuth2 Playground redirect URI — already registered for Production
PLAYGROUND_REDIRECT = "https://developer.intuit.com/v2/OAuth2Playground/RedirectUrl"


def main():
    parser = argparse.ArgumentParser(description="Fetch QBO OAuth tokens")
    parser.add_argument("--token-file", required=True, help="Path to save tokens (e.g. tokens/ecre.json)")
    args = parser.parse_args()

    # Load .env
    env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(env_path)

    client_id = os.getenv("QBO_CLIENT_ID")
    client_secret = os.getenv("QBO_CLIENT_SECRET")
    environment = os.getenv("QBO_ENVIRONMENT", "production")

    if not client_id or not client_secret:
        print("ERROR: QBO_CLIENT_ID and QBO_CLIENT_SECRET must be set in .env")
        sys.exit(1)

    token_file = Path(args.token_file).resolve()
    token_file.parent.mkdir(parents=True, exist_ok=True)

    # Create auth client with the Playground redirect URI
    auth_client = AuthClient(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=PLAYGROUND_REDIRECT,
        environment=environment,
    )

    # Generate auth URL
    auth_url = auth_client.get_authorization_url(scopes=[Scopes.ACCOUNTING])

    print(f"\n{'='*60}")
    print("QBO OAuth Token Fetcher")
    print(f"{'='*60}")
    print(f"\nEnvironment: {environment}")
    print(f"Token file:  {token_file}")
    print(f"\nOpening browser for authorization...")
    print(f"\nAuth URL:\n{auth_url}\n")

    webbrowser.open(auth_url)

    print("After authorizing, you'll be redirected to the Intuit OAuth2 Playground.")
    print("Copy the FULL URL from the browser address bar and paste it below.\n")

    callback_url = input("Paste the callback URL here: ").strip()

    if not callback_url:
        print("ERROR: No URL provided.")
        sys.exit(1)

    # Parse the callback URL for code and realmId
    parsed = urlparse(callback_url)
    params = parse_qs(parsed.query)

    # Handle fragment-based params (some redirects use # instead of ?)
    if not params and parsed.fragment:
        params = parse_qs(parsed.fragment)

    code = params.get("code", [None])[0]
    realm_id = params.get("realmId", [None])[0]

    if not code:
        print(f"ERROR: No 'code' found in URL. Params: {params}")
        sys.exit(1)
    if not realm_id:
        print(f"ERROR: No 'realmId' found in URL. Params: {params}")
        sys.exit(1)

    print(f"\nCode:     {code[:20]}...")
    print(f"Realm ID: {realm_id}")
    print(f"\nExchanging code for tokens...")

    try:
        auth_client.get_bearer_token(code, realm_id=realm_id)
    except Exception as e:
        print(f"ERROR: Token exchange failed: {e}")
        sys.exit(1)

    tokens = {
        "access_token": auth_client.access_token,
        "refresh_token": auth_client.refresh_token,
        "environment": environment,
        "realm_id": realm_id,
    }

    with open(token_file, "w") as f:
        json.dump(tokens, f, indent=2)

    print(f"\nSUCCESS! Tokens saved to {token_file}")
    print(f"  Realm ID:          {realm_id}")
    print(f"  Has access token:  {bool(tokens['access_token'])}")
    print(f"  Has refresh token: {bool(tokens['refresh_token'])}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
