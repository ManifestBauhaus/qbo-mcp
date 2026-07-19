#!/usr/bin/env python3
"""
Automated QBO token refresh — runs every 6 hours via launchd.

Refreshes all 3 QBO tokens using the Intuit token endpoint with:
- File locking to prevent race conditions with MCP servers
- Dual save: local file + GCP Secret Manager
- Token age monitoring with staleness alerts
- Gmail draft + Google Chat alerts on failure
- Retry with exponential backoff

Intuit OAuth facts:
- Access tokens expire in 1 hour
- Refresh tokens expire in 100 days
- Each refresh returns a NEW refresh token (rolling) — old one is invalidated
- Race condition: if two processes use the same refresh token, only one succeeds

This script is the SINGLE SOURCE OF TRUTH for token refresh.
The launchd schedule (every 6h) ensures tokens never go stale.

Usage:
    python3 scripts/auto_refresh_tokens.py          # Normal run
    python3 scripts/auto_refresh_tokens.py --dry-run # Check without saving
    python3 scripts/auto_refresh_tokens.py --status  # Check token freshness
    python3 scripts/auto_refresh_tokens.py --only ecre  # Single book
"""

import argparse
import base64
import fcntl
import json
import logging
import os
import subprocess
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# --- Sentry instrumentation (GOLEM #4) ---
try:
    import sys as _sys, os as _os
    _bos = _os.path.expanduser('~/bauhaus-os')
    if _bos not in _sys.path:
        _sys.path.insert(0, _bos)
    from src.shared.sentry_init import instrumented
except Exception:  # noqa: BLE001 — degrade to no-op
    def instrumented(_label):  # type: ignore[misc]
        def _decorator(fn):
            return fn
        return _decorator
# --- end Sentry instrumentation ---


LOG_DIR = Path("/Users/ericcuevas/qbo-mcp/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(LOG_DIR / "auto-refresh.log"),
    ],
)
log = logging.getLogger("qbo_auto_refresh")

CLIENT_ID = "ABIGnvF0yJf5Kfamzng9ONwhnzw9yonrCTNt2Z7a14BHj38TXg"
CLIENT_SECRET = "lPMDHrLH3ZGLUOWQB7nJWRwPDsqDiVPMqAsneo8G"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
PROJECT_ID = "gen-lang-client-0253282755"
AUTH_STRING = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

LOCK_FILE = LOG_DIR / ".token-refresh.lock"
STALENESS_THRESHOLD_HOURS = 24  # Alert if tokens older than this

INSTANCES = [
    {"key": "ecre", "name": "EC Real Estate", "local": Path("/Users/ericcuevas/qbo-mcp/tokens/ecre.json"), "secret": "qbo-tokens-ecre"},
    {"key": "bcd", "name": "Bauhaus Construction", "local": Path("/Users/ericcuevas/qbo-mcp/tokens/bcd.json"), "secret": "qbo-tokens-bcd"},
    {"key": "bmr", "name": "Bauhaus Maintenance", "local": Path("/Users/ericcuevas/qbo-mcp/tokens/bmr.json"), "secret": "qbo-tokens-bmr"},
]


def acquire_lock() -> int:
    """Acquire exclusive file lock to prevent concurrent refreshes."""
    fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, f"{os.getpid()}\n".encode())
        return fd
    except BlockingIOError:
        os.close(fd)
        log.warning("Another refresh process is running — exiting")
        sys.exit(0)


def release_lock(fd: int):
    """Release file lock."""
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        LOCK_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def refresh_token(refresh_tok: str, retries: int = 3) -> dict | None:
    """Refresh token with exponential backoff retry."""
    for attempt in range(retries):
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
                result = json.loads(resp.read().decode())
                if result.get("access_token") and result.get("refresh_token"):
                    return result
                log.error(f"  Incomplete response: {list(result.keys())}")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            log.error(f"  Attempt {attempt + 1}/{retries} — HTTP {e.code}: {body}")
            # invalid_grant means refresh token is dead — no retry will help
            if "invalid_grant" in body:
                return None
        except Exception as e:
            log.error(f"  Attempt {attempt + 1}/{retries} — Error: {e}")

        if attempt < retries - 1:
            wait = 2 ** attempt
            log.info(f"  Retrying in {wait}s...")
            time.sleep(wait)

    return None


GCLOUD_PATH = "/Users/ericcuevas/google-cloud-sdk/bin/gcloud"
# Explicit credentials — never depend on gcloud's ambient active account.
# Sibling sessions flip `gcloud config set account` (2026-07-06..14 outage:
# firebase SA became active, lacked secretmanager.versions.add, GCP copies
# went stale, Cloud Run dashboard read dead tokens → "all books offline").
GCP_SA_KEY = "/Users/ericcuevas/bauhaus-os/config/service-account.json"
GCLOUD_ACCOUNT = "eric@bauhaus.la"


def _save_to_gcp_client(secret_name: str, payload: str) -> tuple[bool, str]:
    """Primary path: Secret Manager Python client with explicit SA key creds.

    Immune to gcloud account flips and user-token reauth expiry. Requires the
    SA to hold roles/secretmanager.secretVersionAdder on the qbo-tokens-*
    secrets.
    """
    try:
        from google.cloud import secretmanager
        from google.oauth2 import service_account
    except ImportError as e:
        return False, f"client library unavailable: {e}"
    try:
        creds = service_account.Credentials.from_service_account_file(GCP_SA_KEY)
        client = secretmanager.SecretManagerServiceClient(credentials=creds)
        client.add_secret_version(request={
            "parent": f"projects/{PROJECT_ID}/secrets/{secret_name}",
            "payload": {"data": payload.encode("utf-8")},
        })
        return True, ""
    except Exception as e:
        return False, str(e).split("\n")[0][:200]


def _save_to_gcp_gcloud(secret_name: str, payload: str) -> tuple[bool, str]:
    """Fallback path: gcloud CLI pinned to the named user account."""
    try:
        result = subprocess.run(
            [GCLOUD_PATH, "secrets", "versions", "add", secret_name,
             f"--project={PROJECT_ID}", f"--account={GCLOUD_ACCOUNT}",
             "--data-file=-"],
            input=payload, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, ""
        return False, (result.stderr or "").strip().split("\n")[0][:200]
    except FileNotFoundError:
        return False, f"gcloud not found at {GCLOUD_PATH}"
    except Exception as e:
        return False, str(e)[:200]


def save_to_gcp(secret_name: str, tokens: dict) -> bool:
    """Save tokens to GCP Secret Manager. Non-fatal — local save is primary,
    but Cloud Run (sovereign dashboard) reads ONLY the GCP copy, so a silent
    stale secret takes the dashboard's books offline. Always log WHY a save
    failed."""
    payload = json.dumps(tokens)
    ok, err_client = _save_to_gcp_client(secret_name, payload)
    if ok:
        return True
    ok, err_gcloud = _save_to_gcp_gcloud(secret_name, payload)
    if ok:
        return True
    log.warning(f"  GCP save failed — client: {err_client} | gcloud: {err_gcloud}")
    return False


def send_chat_alert(message: str):
    """Send alert to Google Chat NCN Alerts space."""
    webhook_url = os.getenv("GOOGLE_CHAT_WEBHOOK_URL")
    if not webhook_url:
        # Try reading from Make.com data store config
        return
    try:
        data = json.dumps({"text": message}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json; charset=UTF-8"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log.warning(f"Chat alert failed: {e}")


def send_gmail_alert(failed_instances: list[str]):
    """Create Gmail draft alerting Eric about failed token refresh."""
    names = ", ".join(f.upper() for f in failed_instances)
    body = (
        f"<p><b>QBO token refresh failed for: {names}</b></p>"
        f"<p>Refresh tokens may be expired (invalid_grant). Interactive re-auth required:</p>"
        f"<pre>cd ~/qbo-mcp && uv run python scripts/reauth_playwright.py</pre>"
        f"<p>Or for a single book:</p>"
        f"<pre>cd ~/qbo-mcp && uv run python scripts/reauth_playwright.py --only ecre</pre>"
        f"<p style='color:#888;font-size:11px'>— QBO Auto-Refresh (launchd, every 6h)</p>"
    )
    try:
        subprocess.run(
            ["python3", str(Path.home() / ".claude" / "gmail_draft.py"),
             "--to", "eric@bauhaus.la",
             "--subject", f"P1: QBO Token Refresh Failed — {names}",
             "--html", body],
            capture_output=True, text=True, timeout=30,
        )
        log.info(f"Gmail draft alert created for: {names}")
    except Exception as e:
        log.error(f"Failed to create alert draft: {e}")


def get_token_age_hours(token_file: Path) -> float:
    """Get age of token file in hours."""
    try:
        mtime = token_file.stat().st_mtime
        age_sec = time.time() - mtime
        return age_sec / 3600
    except Exception:
        return float("inf")


def check_status():
    """Print token freshness status for all instances."""
    print(f"{'Book':<8} {'Age (hrs)':<12} {'Status':<15} {'File Modified'}")
    print("-" * 60)
    for inst in INSTANCES:
        age = get_token_age_hours(inst["local"])
        if age == float("inf"):
            status = "MISSING"
            modified = "N/A"
        elif age > STALENESS_THRESHOLD_HOURS:
            status = "STALE"
            modified = datetime.fromtimestamp(inst["local"].stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        else:
            status = "FRESH"
            modified = datetime.fromtimestamp(inst["local"].stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        print(f"{inst['key'].upper():<8} {age:<12.1f} {status:<15} {modified}")

        # Check if tokens are valid JSON with required fields
        try:
            with open(inst["local"]) as f:
                tokens = json.load(f)
            has_access = bool(tokens.get("access_token"))
            has_refresh = bool(tokens.get("refresh_token"))
            has_realm = bool(tokens.get("realm_id"))
            if not (has_access and has_refresh and has_realm):
                print(f"  WARNING: Missing fields — access={has_access} refresh={has_refresh} realm={has_realm}")
        except Exception as e:
            print(f"  ERROR: Cannot read file — {e}")


@instrumented("com.bauhaus.qbo-token-refresh")
def main():
    parser = argparse.ArgumentParser(description="QBO token auto-refresh (every 6h)")
    parser.add_argument("--dry-run", action="store_true", help="Check without saving")
    parser.add_argument("--status", action="store_true", help="Show token freshness")
    parser.add_argument("--only", choices=["ecre", "bcd", "bmr"], help="Refresh single book")
    args = parser.parse_args()

    if args.status:
        check_status()
        return

    # Acquire exclusive lock
    lock_fd = acquire_lock()

    try:
        targets = [i for i in INSTANCES if not args.only or i["key"] == args.only]
        log.info(f"QBO auto-refresh starting for: {', '.join(i['key'].upper() for i in targets)}")

        failed = []
        succeeded = []

        for inst in targets:
            log.info(f"Refreshing {inst['key'].upper()} ({inst['name']})...")

            # Check token age first
            age = get_token_age_hours(inst["local"])
            log.info(f"  Token age: {age:.1f} hours")

            # Read local tokens
            try:
                with open(inst["local"]) as f:
                    tokens = json.load(f)
            except Exception as e:
                log.error(f"  Cannot read {inst['local']}: {e}")
                failed.append(inst["key"])
                continue

            rt = tokens.get("refresh_token")
            realm_id = tokens.get("realm_id")
            if not rt:
                log.error(f"  No refresh token in file")
                failed.append(inst["key"])
                continue

            if args.dry_run:
                log.info(f"  [DRY RUN] Would refresh (skipping API call to avoid token rotation)")
                succeeded.append(inst["key"])
                continue

            # Refresh with retry
            result = refresh_token(rt)
            if not result:
                log.error(f"  Token refresh failed for {inst['key'].upper()}")
                failed.append(inst["key"])
                continue

            new_tokens = {
                "access_token": result["access_token"],
                "refresh_token": result["refresh_token"],
                "environment": "production",
                "realm_id": realm_id,
            }

            # Save local (atomic write via temp file). fsync before rename:
            # Intuit invalidates the old refresh token the moment the new one
            # is issued, so losing this write to a crash/power cut = full
            # browser re-auth for the book. Shrink that window to ~zero.
            tmp_file = inst["local"].with_suffix(".tmp")
            with open(tmp_file, "w") as f:
                json.dump(new_tokens, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            tmp_file.replace(inst["local"])
            log.info(f"  Saved to {inst['local']}")

            # Save GCP
            if save_to_gcp(inst["secret"], new_tokens):
                log.info(f"  Saved to GCP: {inst['secret']}")
            else:
                log.warning(f"  GCP save failed (local OK)")

            succeeded.append(inst["key"])

            # Brief pause between books to avoid rate limiting
            time.sleep(1)

        # Summary
        log.info(f"Results: {len(succeeded)} succeeded, {len(failed)} failed")
        if succeeded:
            log.info(f"  OK: {', '.join(s.upper() for s in succeeded)}")
        if failed:
            log.error(f"  FAILED: {', '.join(f.upper() for f in failed)}")
            if not args.dry_run:
                # Email channel disabled per Eric 2026-05-19 — Chat-only.
                # send_gmail_alert(failed)
                send_chat_alert(
                    f"*QBO Token Refresh Failed*\n"
                    f"Books: {', '.join(f.upper() for f in failed)}\n"
                    f"Run: `cd ~/qbo-mcp && uv run python scripts/reauth_playwright.py`"
                )

        sys.exit(0 if not failed else 1)

    finally:
        release_lock(lock_fd)


if __name__ == "__main__":
    main()
