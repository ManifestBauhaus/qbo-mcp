# QBO MCP Hardening Design

**Date:** 2026-02-26
**Status:** Approved
**Scope:** ~/qbo-mcp

## Goal

Close three vulnerabilities in the QBO MCP server: silent token expiry, unencrypted local token storage, and unrestricted API scope.

## Context

The QBO MCP server exposes 12 read-only financial reporting tools across 3 QuickBooks books (ECRE, BCD, BMR). Production OAuth tokens were obtained on 2026-02-26. The server currently has no auth event logging, stores tokens as local JSON files, and relies on convention (not enforcement) for read-only access.

---

## 1. Token Refresh Logging + Google Chat Alert

### Problem

The `intuitlib` library handles automatic token refreshing. If the refresh token expires (100 days of inactivity), API calls silently fail. There is no logging or alerting for auth events.

### Solution

Add a dedicated auth logger writing to `logs/qbo-auth.log` with a `RotatingFileHandler`. On every token refresh attempt, log success or failure. On failure, POST to a Google Chat webhook.

### Components

**New file: `src/qbo_mcp/auth_logger.py`**
- Python `logging.handlers.RotatingFileHandler` → `logs/qbo-auth.log`
- Max 5MB per file, 3 backups
- Functions: `log_refresh_success(realm_id, book_name)`, `log_refresh_failure(realm_id, book_name, error)`, `send_chat_alert(message)`

**Modified: `src/qbo_mcp/auth.py`**
- After every `auth_client.refresh()` call, invoke the auth logger
- On failure, fire Google Chat webhook with actionable message: book name, realm ID, exact command to re-authenticate

**New env var: `GOOGLE_CHAT_WEBHOOK_URL`**
- Optional. If not set, log only — no crash, no error.

### Log Format

```
2026-02-26 18:30:00 | REFRESH_SUCCESS | ecre | 1321803265
2026-02-26 18:30:01 | REFRESH_FAILURE | bmr | 9341453243233117 | Token expired
```

### Chat Alert Format

```
QBO Token Expired for BMR (Realm 9341453243233117).
Run: uv run python scripts/get_tokens.py --token-file tokens/bmr.json
```

---

## 2. Token Migration to GCP Secret Manager

### Problem

Tokens for 3 QuickBooks books live in unencrypted JSON files on the local Mac (`tokens/{ecre,bcd,bmr}.json`). Disk failure means repeating the entire manual OAuth process.

### Solution

Store tokens in GCP Secret Manager with local file fallback. The MCP server pulls tokens from GCP at runtime and writes updated tokens back after refresh.

### Components

**3 new GCP secrets** in project `gen-lang-client-0253282755`:
- `qbo-tokens-ecre`
- `qbo-tokens-bcd`
- `qbo-tokens-bmr`

Each stores the same JSON: `{access_token, refresh_token, environment, realm_id}`.

**Modified: `src/qbo_mcp/auth.py`**
- Abstract `_load_tokens()` and `_save_tokens()` behind a backend interface
- `QBO_TOKEN_BACKEND=gcp`: read/write via `google-cloud-secret-manager`
- `QBO_TOKEN_BACKEND=local` (default): current file-based behavior, backward compatible
- Fallback: if GCP unreachable, warn and try local files

**New env var: `QBO_TOKEN_BACKEND`**
- Values: `gcp` or `local`
- Default: `local`

**New env var: `GCP_PROJECT_ID`**
- Required when `QBO_TOKEN_BACKEND=gcp`
- Default: `gen-lang-client-0253282755`

**Modified: `scripts/get_tokens.py`**
- New flag: `--push-to-gcp` — uploads local token file to Secret Manager

**New dependency:** `google-cloud-secret-manager` in `pyproject.toml`

---

## 3. Read-Only Enforcement (Write Protection)

### Problem

The OAuth scope `com.intuit.quickbooks.accounting` allows reads AND writes. All 12 current tools are read-only, but nothing prevents a future tool or direct library call from writing to the general ledger.

### Solution

Monkey-patch the `python-quickbooks` `QuickBooks` client to block all write HTTP methods at the lowest level. Always on — no toggle.

### Components

**New file: `src/qbo_mcp/readonly_guard.py`**
- Function: `apply_readonly_guard(client: QuickBooks)` → patches `post()`, `put()`, `delete()`, `batch_operation()` on the client instance
- Each patched method raises `PermissionError("QBO MCP is read-only. Write operations are blocked.")`
- Logs every blocked attempt to `logs/qbo-auth.log` at WARNING level

**Modified: `src/qbo_mcp/auth.py`**
- In `get_authenticated_client()`, call `apply_readonly_guard(self.qbo)` after client creation

### What's allowed

- `QuickBooks.get()` — used by entity lookups
- `QuickBooks.get_report()` — used by all 12 report tools

### Why monkey-patch

The `python-quickbooks` library calls its own HTTP methods internally (e.g., `Invoice.save(qb=client)` calls `client.post()`). A wrapper around our MCP tools wouldn't catch direct library usage. The monkey-patch intercepts at the HTTP call level — the last line of defense.

### No toggle

The guard is always on. Enabling writes requires a deliberate code change, not a config flip. This prevents accidental activation.

---

## Dependencies Added

- `google-cloud-secret-manager` — GCP Secret Manager client

## Files Changed

| File | Action |
|------|--------|
| `src/qbo_mcp/auth_logger.py` | Create — auth event logging + Chat webhook |
| `src/qbo_mcp/readonly_guard.py` | Create — write operation blocker |
| `src/qbo_mcp/auth.py` | Modify — integrate logger, GCP backend, readonly guard |
| `scripts/get_tokens.py` | Modify — add `--push-to-gcp` flag |
| `pyproject.toml` | Modify — add `google-cloud-secret-manager` |
| `.env` | Modify — add `GOOGLE_CHAT_WEBHOOK_URL`, `QBO_TOKEN_BACKEND`, `GCP_PROJECT_ID` |
| `env.example` | Modify — document new env vars |

## Testing

- Unit tests for readonly guard (mock QuickBooks client, verify PermissionError on write calls)
- Unit tests for auth logger (verify log file creation, log format, webhook POST)
- Integration test: attempt `Invoice.save()` through guarded client → expect PermissionError
- Manual test: corrupt a token file, trigger refresh failure, verify Chat alert fires
