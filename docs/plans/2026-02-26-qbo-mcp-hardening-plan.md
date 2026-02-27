# QBO MCP Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close three vulnerabilities: silent token expiry, unencrypted local tokens, and unrestricted API write access.

**Architecture:** Three independent hardening layers added to the existing QBO MCP server. Auth logger wraps token refresh events and fires Google Chat webhooks on failure. GCP Secret Manager provides an alternative token backend behind `_load_tokens()`/`_save_tokens()`. A readonly guard monkey-patches the QuickBooks client's `post()` method to block all write operations at the HTTP level.

**Tech Stack:** Python 3.12, intuitlib, python-quickbooks, google-cloud-secret-manager, FastMCP, pytest

**Design doc:** `docs/plans/2026-02-26-qbo-mcp-hardening-design.md`

---

### Task 1: Read-Only Guard

The simplest and highest-impact task. Zero dependencies on other tasks.

**Files:**
- Create: `src/qbo_mcp/readonly_guard.py`
- Create: `tests/test_readonly_guard.py`
- Modify: `src/qbo_mcp/auth.py:136-161`

**Step 1: Write the failing tests**

Create `tests/test_readonly_guard.py`:

```python
import pytest
from unittest.mock import MagicMock
from qbo_mcp.readonly_guard import apply_readonly_guard


class TestReadonlyGuard:
    def _make_mock_client(self):
        """Create a mock QuickBooks client with real-ish methods."""
        client = MagicMock()
        client.post = MagicMock(return_value={"response": "ok"})
        client.get = MagicMock(return_value={"response": "ok"})
        client.get_report = MagicMock(return_value={"Header": {}, "Rows": []})
        client.make_request = MagicMock(return_value={"response": "ok"})
        client.create_object = MagicMock(return_value={"response": "ok"})
        client.update_object = MagicMock(return_value={"response": "ok"})
        client.delete_object = MagicMock(return_value={"response": "ok"})
        client.batch_operation = MagicMock(return_value={"response": "ok"})
        client.misc_operation = MagicMock(return_value={"response": "ok"})
        return client

    def test_guard_blocks_post(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.post("/some/url", {})

    def test_guard_blocks_create_object(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.create_object("Invoice", {})

    def test_guard_blocks_update_object(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.update_object("Invoice", {})

    def test_guard_blocks_delete_object(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.delete_object("Invoice", {})

    def test_guard_blocks_batch_operation(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.batch_operation({})

    def test_guard_blocks_misc_operation(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.misc_operation("endpoint", {})

    def test_guard_allows_get(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        result = client.get("/some/url")
        assert result == {"response": "ok"}

    def test_guard_allows_get_report(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        result = client.get_report("ProfitAndLoss", {})
        assert result == {"Header": {}, "Rows": []}

    def test_guard_is_idempotent(self):
        client = self._make_mock_client()
        apply_readonly_guard(client)
        apply_readonly_guard(client)  # second call should not error
        with pytest.raises(PermissionError):
            client.post("/url", {})
        result = client.get("/url")
        assert result == {"response": "ok"}
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/test_readonly_guard.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'qbo_mcp.readonly_guard'`

**Step 3: Implement the readonly guard**

Create `src/qbo_mcp/readonly_guard.py`:

```python
"""Read-only guard for QuickBooks client.

Monkey-patches write methods on a QuickBooks client instance to raise
PermissionError. Always on — no toggle. Disabling requires a code change.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

BLOCKED_METHODS = [
    "post",
    "create_object",
    "update_object",
    "delete_object",
    "batch_operation",
    "misc_operation",
]

_GUARD_ATTR = "_readonly_guard_applied"


def _make_blocked_method(method_name: str):
    """Create a replacement method that raises PermissionError."""
    def blocked(*args: Any, **kwargs: Any) -> None:
        logger.warning(f"BLOCKED write operation: {method_name}()")
        raise PermissionError(
            f"QBO MCP is read-only. Write operation '{method_name}' is blocked. "
            "This server only supports read operations (get, get_report, query)."
        )
    return blocked


def apply_readonly_guard(client) -> None:
    """Patch a QuickBooks client instance to block all write operations.

    Replaces post(), create_object(), update_object(), delete_object(),
    batch_operation(), and misc_operation() with methods that raise
    PermissionError.

    Safe to call multiple times (idempotent).

    Args:
        client: A QuickBooks client instance.
    """
    if getattr(client, _GUARD_ATTR, False):
        return

    for method_name in BLOCKED_METHODS:
        if hasattr(client, method_name):
            setattr(client, method_name, _make_blocked_method(method_name))

    setattr(client, _GUARD_ATTR, True)
    logger.info("Read-only guard applied to QuickBooks client")
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/test_readonly_guard.py -v`
Expected: 10 PASSED

**Step 5: Integrate into auth.py**

In `src/qbo_mcp/auth.py`, add import at the top (after line 11):

```python
from qbo_mcp.readonly_guard import apply_readonly_guard
```

In `get_authenticated_client()` method (after line 157, after `self.qbo = QuickBooks(...)`), add:

```python
            apply_readonly_guard(self.qbo)
```

So the method becomes:

```python
    def get_authenticated_client(self) -> QuickBooks:
        if not (self.auth_client.access_token and self.auth_client.refresh_token and self.auth_client.realm_id):
            raise ValueError("Missing required tokens or realm_id for QuickBooks client.")
        if not self.ensure_authenticated():
            raise ValueError("Could not refresh tokens for QuickBooks client.")
        try:
            self.qbo = QuickBooks(
                auth_client=self.auth_client,
                refresh_token=self.auth_client.refresh_token,
                realm_id=self.auth_client.realm_id,
            )
            apply_readonly_guard(self.qbo)
        except Exception as e:
            logger.error(f"QBO Service error: {str(e)}")
            raise ValueError(f"QBO Service error: {str(e)}")
        return self.qbo
```

**Step 6: Run all tests**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/ -v`
Expected: All pass

**Step 7: Commit**

```bash
git add src/qbo_mcp/readonly_guard.py tests/test_readonly_guard.py src/qbo_mcp/auth.py
git commit -m "feat: add read-only guard blocking all QBO write operations"
```

---

### Task 2: Auth Event Logger + Google Chat Alerts

**Files:**
- Create: `src/qbo_mcp/auth_logger.py`
- Create: `tests/test_auth_logger.py`
- Modify: `src/qbo_mcp/auth.py:113-134`
- Modify: `src/qbo_mcp/config/config.py:30-39`
- Modify: `env.example`

**Step 1: Write the failing tests**

Create `tests/test_auth_logger.py`:

```python
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from qbo_mcp.auth_logger import AuthEventLogger


class TestAuthEventLogger:
    def test_log_refresh_success(self, tmp_path):
        log_file = tmp_path / "qbo-auth.log"
        logger = AuthEventLogger(log_dir=tmp_path)
        logger.log_refresh_success(realm_id="1321803265", book_name="ecre")
        content = log_file.read_text()
        assert "REFRESH_SUCCESS" in content
        assert "ecre" in content
        assert "1321803265" in content

    def test_log_refresh_failure(self, tmp_path):
        log_file = tmp_path / "qbo-auth.log"
        logger = AuthEventLogger(log_dir=tmp_path)
        logger.log_refresh_failure(
            realm_id="9341453243233117",
            book_name="bmr",
            error="Token expired"
        )
        content = log_file.read_text()
        assert "REFRESH_FAILURE" in content
        assert "bmr" in content
        assert "Token expired" in content

    def test_log_creates_directory(self, tmp_path):
        log_dir = tmp_path / "nested" / "logs"
        logger = AuthEventLogger(log_dir=log_dir)
        logger.log_refresh_success(realm_id="123", book_name="test")
        assert log_dir.exists()
        assert (log_dir / "qbo-auth.log").exists()

    @patch("qbo_mcp.auth_logger.urllib.request.urlopen")
    def test_chat_alert_on_failure(self, mock_urlopen, tmp_path):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        logger = AuthEventLogger(
            log_dir=tmp_path,
            chat_webhook_url="https://chat.googleapis.com/v1/spaces/test/messages?key=test"
        )
        logger.log_refresh_failure(
            realm_id="9341453243233117",
            book_name="bmr",
            error="Token expired"
        )
        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        body = json.loads(request.data)
        assert "bmr" in body["text"]
        assert "Token expired" in body["text"] or "9341453243233117" in body["text"]

    def test_no_crash_without_webhook_url(self, tmp_path):
        logger = AuthEventLogger(log_dir=tmp_path, chat_webhook_url=None)
        # Should not raise even on failure
        logger.log_refresh_failure(
            realm_id="123",
            book_name="test",
            error="some error"
        )

    def test_log_write_blocked(self, tmp_path):
        log_file = tmp_path / "qbo-auth.log"
        logger = AuthEventLogger(log_dir=tmp_path)
        logger.log_write_blocked(method_name="post", details="Invoice.save()")
        content = log_file.read_text()
        assert "WRITE_BLOCKED" in content
        assert "post" in content
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/test_auth_logger.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'qbo_mcp.auth_logger'`

**Step 3: Implement the auth logger**

Create `src/qbo_mcp/auth_logger.py`:

```python
"""Auth event logger with Google Chat webhook alerts.

Writes auth events to logs/qbo-auth.log and optionally sends
Google Chat alerts on token refresh failures.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_FILENAME = "qbo-auth.log"
_MAX_BYTES = 5 * 1024 * 1024  # 5MB
_BACKUP_COUNT = 3


class AuthEventLogger:
    """Logs QBO auth events to a rotating file and optionally alerts via Google Chat."""

    def __init__(self, log_dir: Path | None = None, chat_webhook_url: str | None = None):
        self.chat_webhook_url = chat_webhook_url

        if log_dir is None:
            log_dir = Path(__file__).resolve().parent.parent.parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("qbo_auth_events")
        self._logger.setLevel(logging.INFO)
        # Avoid duplicate handlers on repeated init
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                log_dir / _LOG_FILENAME,
                maxBytes=_MAX_BYTES,
                backupCount=_BACKUP_COUNT,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def log_refresh_success(self, realm_id: str, book_name: str) -> None:
        self._logger.info(
            f"{self._timestamp()} | REFRESH_SUCCESS | {book_name} | {realm_id}"
        )

    def log_refresh_failure(self, realm_id: str, book_name: str, error: str) -> None:
        self._logger.error(
            f"{self._timestamp()} | REFRESH_FAILURE | {book_name} | {realm_id} | {error}"
        )
        self._send_chat_alert(
            f"*QBO Token Refresh Failed* for *{book_name.upper()}* "
            f"(Realm {realm_id}).\n"
            f"Error: {error}\n"
            f"Run: `uv run python scripts/get_tokens.py --token-file tokens/{book_name}.json`"
        )

    def log_write_blocked(self, method_name: str, details: str = "") -> None:
        msg = f"{self._timestamp()} | WRITE_BLOCKED | {method_name}"
        if details:
            msg += f" | {details}"
        self._logger.warning(msg)

    def _send_chat_alert(self, message: str) -> None:
        if not self.chat_webhook_url:
            return
        try:
            payload = json.dumps({"text": message}).encode("utf-8")
            req = urllib.request.Request(
                self.chat_webhook_url,
                data=payload,
                headers={"Content-Type": "application/json; charset=UTF-8"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status != 200:
                    logging.getLogger(__name__).warning(
                        f"Chat webhook returned status {resp.status}"
                    )
        except (urllib.error.URLError, OSError) as e:
            logging.getLogger(__name__).warning(f"Chat webhook failed: {e}")
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/test_auth_logger.py -v`
Expected: 6 PASSED

**Step 5: Add config support**

In `src/qbo_mcp/config/config.py`, add to `__init__` (after line 39, after `self.token_file`):

```python
        # Auth logging
        self.chat_webhook_url: str | None = os.getenv("GOOGLE_CHAT_WEBHOOK_URL")

        # Book name — derived from token file name (e.g., "ecre" from "tokens/ecre.json")
        self.book_name: str = self.token_file.stem
```

**Step 6: Integrate into auth.py**

In `src/qbo_mcp/auth.py`, add import at top (after the `readonly_guard` import from Task 1):

```python
from qbo_mcp.auth_logger import AuthEventLogger
```

In `QBOService.__init__()`, after `self._load_tokens()` (after line 42), add:

```python
        self.auth_event_logger = AuthEventLogger(
            chat_webhook_url=self.config.chat_webhook_url,
        )
```

Modify `ensure_authenticated()` (lines 113-134) to:

```python
    def ensure_authenticated(self) -> bool:
        if not self.auth_client:
            raise ValueError("Auth client not initialized!")
        if not self.auth_client.access_token or not self.auth_client.refresh_token:
            raise ValueError("No valid access or refresh token found!")
        try:
            self.auth_client.refresh()
            self._save_tokens()
            self.auth_event_logger.log_refresh_success(
                realm_id=self.auth_client.realm_id or "unknown",
                book_name=self.config.book_name,
            )
            logger.info("Tokens refreshed successfully!")
            return True
        except Exception as e:
            self.auth_event_logger.log_refresh_failure(
                realm_id=self.auth_client.realm_id or "unknown",
                book_name=self.config.book_name,
                error=str(e),
            )
            logger.error(f"Token refresh error: {str(e)}")
            return False
```

**Step 7: Update env.example**

Append to `env.example`:

```
# Google Chat webhook URL for auth failure alerts (optional)
GOOGLE_CHAT_WEBHOOK_URL=
```

**Step 8: Update readonly_guard to use auth_logger**

In `src/qbo_mcp/readonly_guard.py`, update `_make_blocked_method` to accept an optional logger:

Update `apply_readonly_guard` signature to accept an optional `auth_event_logger`:

```python
def apply_readonly_guard(client, auth_event_logger=None) -> None:
    if getattr(client, _GUARD_ATTR, False):
        return

    for method_name in BLOCKED_METHODS:
        if hasattr(client, method_name):
            setattr(client, method_name, _make_blocked_method(method_name, auth_event_logger))

    setattr(client, _GUARD_ATTR, True)
    logger.info("Read-only guard applied to QuickBooks client")


def _make_blocked_method(method_name: str, auth_event_logger=None):
    def blocked(*args, **kwargs):
        logger.warning(f"BLOCKED write operation: {method_name}()")
        if auth_event_logger:
            auth_event_logger.log_write_blocked(method_name)
        raise PermissionError(
            f"QBO MCP is read-only. Write operation '{method_name}' is blocked. "
            "This server only supports read operations (get, get_report, query)."
        )
    return blocked
```

Update the call in `auth.py` `get_authenticated_client()`:

```python
            apply_readonly_guard(self.qbo, self.auth_event_logger)
```

**Step 9: Run all tests**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/ -v`
Expected: All pass

**Step 10: Commit**

```bash
git add src/qbo_mcp/auth_logger.py tests/test_auth_logger.py src/qbo_mcp/auth.py src/qbo_mcp/config/config.py src/qbo_mcp/readonly_guard.py env.example
git commit -m "feat: auth event logging with Google Chat alerts on token failure"
```

---

### Task 3: GCP Secret Manager Token Backend

**Files:**
- Create: `src/qbo_mcp/token_backends.py`
- Create: `tests/test_token_backends.py`
- Modify: `src/qbo_mcp/auth.py:46-111`
- Modify: `src/qbo_mcp/config/config.py`
- Modify: `scripts/get_tokens.py`
- Modify: `pyproject.toml`
- Modify: `env.example`

**Step 1: Add dependency**

In `pyproject.toml`, add to `dependencies` list (after line 16):

```
    "google-cloud-secret-manager>=2.20.0",
```

Run: `cd /Users/ericcuevas/qbo-mcp && uv sync`

**Step 2: Write the failing tests**

Create `tests/test_token_backends.py`:

```python
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from qbo_mcp.token_backends import LocalTokenBackend, GCPTokenBackend, get_token_backend


SAMPLE_TOKENS = {
    "access_token": "test_access",
    "refresh_token": "test_refresh",
    "environment": "production",
    "realm_id": "123456",
}


class TestLocalTokenBackend:
    def test_load_tokens(self, tmp_path):
        token_file = tmp_path / "tokens.json"
        token_file.write_text(json.dumps(SAMPLE_TOKENS))
        backend = LocalTokenBackend(token_file)
        tokens = backend.load()
        assert tokens["access_token"] == "test_access"
        assert tokens["realm_id"] == "123456"

    def test_save_tokens(self, tmp_path):
        token_file = tmp_path / "tokens.json"
        backend = LocalTokenBackend(token_file)
        backend.save(SAMPLE_TOKENS)
        loaded = json.loads(token_file.read_text())
        assert loaded == SAMPLE_TOKENS

    def test_load_missing_file(self, tmp_path):
        token_file = tmp_path / "nonexistent.json"
        backend = LocalTokenBackend(token_file)
        tokens = backend.load()
        assert tokens == {}

    def test_load_empty_file(self, tmp_path):
        token_file = tmp_path / "empty.json"
        token_file.write_text("{}")
        backend = LocalTokenBackend(token_file)
        tokens = backend.load()
        assert tokens == {}


class TestGCPTokenBackend:
    @patch("qbo_mcp.token_backends.secretmanager.SecretManagerServiceClient")
    def test_load_tokens(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.payload.data = json.dumps(SAMPLE_TOKENS).encode("utf-8")
        mock_client.access_secret_version.return_value = mock_response

        backend = GCPTokenBackend(project_id="test-project", secret_id="qbo-tokens-ecre")
        tokens = backend.load()
        assert tokens["access_token"] == "test_access"
        mock_client.access_secret_version.assert_called_once()

    @patch("qbo_mcp.token_backends.secretmanager.SecretManagerServiceClient")
    def test_save_tokens(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        backend = GCPTokenBackend(project_id="test-project", secret_id="qbo-tokens-ecre")
        backend.save(SAMPLE_TOKENS)
        mock_client.add_secret_version.assert_called_once()
        call_kwargs = mock_client.add_secret_version.call_args
        parent = call_kwargs[1]["request"]["parent"]
        assert "qbo-tokens-ecre" in parent

    @patch("qbo_mcp.token_backends.secretmanager.SecretManagerServiceClient")
    def test_load_not_found_returns_empty(self, mock_client_cls):
        from google.api_core.exceptions import NotFound
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.access_secret_version.side_effect = NotFound("not found")

        backend = GCPTokenBackend(project_id="test-project", secret_id="qbo-tokens-ecre")
        tokens = backend.load()
        assert tokens == {}


class TestGetTokenBackend:
    def test_local_backend(self, tmp_path):
        token_file = tmp_path / "tokens.json"
        backend = get_token_backend("local", token_file=token_file)
        assert isinstance(backend, LocalTokenBackend)

    @patch("qbo_mcp.token_backends.secretmanager.SecretManagerServiceClient")
    def test_gcp_backend(self, mock_client_cls):
        backend = get_token_backend(
            "gcp", project_id="test-project", secret_id="qbo-tokens-ecre"
        )
        assert isinstance(backend, GCPTokenBackend)

    def test_invalid_backend(self):
        with pytest.raises(ValueError, match="Unknown token backend"):
            get_token_backend("redis")
```

**Step 3: Run tests to verify they fail**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/test_token_backends.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'qbo_mcp.token_backends'`

**Step 4: Implement the token backends**

Create `src/qbo_mcp/token_backends.py`:

```python
"""Token storage backends for QBO MCP.

Supports local file storage and GCP Secret Manager.
"""

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TokenBackend(ABC):
    """Abstract base class for token storage backends."""

    @abstractmethod
    def load(self) -> dict[str, Any]:
        """Load tokens. Returns empty dict if not found."""
        ...

    @abstractmethod
    def save(self, tokens: dict[str, Any]) -> None:
        """Persist tokens."""
        ...


class LocalTokenBackend(TokenBackend):
    """Store tokens as a local JSON file."""

    def __init__(self, token_file: Path):
        self.token_file = token_file

    def load(self) -> dict[str, Any]:
        try:
            with open(self.token_file, "r") as f:
                tokens = json.load(f)
            if tokens.get("access_token"):
                logger.info(f"Loaded tokens from {self.token_file}")
                return tokens
            return {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        except Exception as e:
            logger.warning(f"Error reading token file: {e}")
            return {}

    def save(self, tokens: dict[str, Any]) -> None:
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.token_file, "w") as f:
            json.dump(tokens, f, indent=2)
        logger.info(f"Saved tokens to {self.token_file}")


class GCPTokenBackend(TokenBackend):
    """Store tokens in GCP Secret Manager."""

    def __init__(self, project_id: str, secret_id: str):
        from google.cloud import secretmanager
        self._client = secretmanager.SecretManagerServiceClient()
        self._project_id = project_id
        self._secret_id = secret_id
        self._secret_path = f"projects/{project_id}/secrets/{secret_id}"

    def load(self) -> dict[str, Any]:
        from google.api_core.exceptions import NotFound
        try:
            response = self._client.access_secret_version(
                request={"name": f"{self._secret_path}/versions/latest"}
            )
            tokens = json.loads(response.payload.data.decode("utf-8"))
            if tokens.get("access_token"):
                logger.info(f"Loaded tokens from GCP secret {self._secret_id}")
                return tokens
            return {}
        except NotFound:
            logger.warning(f"GCP secret {self._secret_id} not found")
            return {}
        except Exception as e:
            logger.warning(f"Error loading from GCP: {e}")
            return {}

    def save(self, tokens: dict[str, Any]) -> None:
        payload = json.dumps(tokens, indent=2).encode("utf-8")
        try:
            self._client.add_secret_version(
                request={
                    "parent": self._secret_path,
                    "payload": {"data": payload},
                }
            )
            logger.info(f"Saved tokens to GCP secret {self._secret_id}")
        except Exception as e:
            # If secret doesn't exist yet, create it then add version
            from google.api_core.exceptions import NotFound
            if isinstance(e, NotFound):
                self._client.create_secret(
                    request={
                        "parent": f"projects/{self._project_id}",
                        "secret_id": self._secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
                self._client.add_secret_version(
                    request={
                        "parent": self._secret_path,
                        "payload": {"data": payload},
                    }
                )
                logger.info(f"Created and saved GCP secret {self._secret_id}")
            else:
                logger.error(f"Error saving to GCP: {e}")
                raise


def get_token_backend(
    backend_type: str,
    token_file: Path | None = None,
    project_id: str | None = None,
    secret_id: str | None = None,
) -> TokenBackend:
    """Factory function to create the appropriate token backend."""
    if backend_type == "local":
        if token_file is None:
            raise ValueError("token_file required for local backend")
        return LocalTokenBackend(token_file)
    elif backend_type == "gcp":
        if not project_id or not secret_id:
            raise ValueError("project_id and secret_id required for gcp backend")
        return GCPTokenBackend(project_id=project_id, secret_id=secret_id)
    else:
        raise ValueError(f"Unknown token backend: {backend_type}")
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/test_token_backends.py -v`
Expected: 9 PASSED

**Step 6: Add config support**

In `src/qbo_mcp/config/config.py`, add to `__init__` (after the `book_name` line from Task 2):

```python
        # Token backend
        self.token_backend: str = os.getenv("QBO_TOKEN_BACKEND", "local")
        self.gcp_project_id: str = os.getenv("GCP_PROJECT_ID", "gen-lang-client-0253282755")
        self.gcp_secret_id: str = f"qbo-tokens-{self.book_name}"
```

**Step 7: Integrate into auth.py**

In `src/qbo_mcp/auth.py`, add import:

```python
from qbo_mcp.token_backends import get_token_backend
```

Replace `_load_tokens()` (lines 46-90) with:

```python
    def _load_tokens(self) -> None:
        tokens = {}

        # 1. Try configured backend (gcp or local)
        try:
            self._token_backend = get_token_backend(
                self.config.token_backend,
                token_file=self.token_file,
                project_id=self.config.gcp_project_id,
                secret_id=self.config.gcp_secret_id,
            )
            tokens = self._token_backend.load()
        except Exception as e:
            logger.warning(f"Token backend ({self.config.token_backend}) error: {e}")

        # 2. Fallback: if GCP failed, try local file
        if not tokens.get("access_token") and self.config.token_backend == "gcp":
            logger.warning("GCP backend failed, falling back to local file")
            from qbo_mcp.token_backends import LocalTokenBackend
            fallback = LocalTokenBackend(self.token_file)
            tokens = fallback.load()

        # 3. Fallback: try environment variables
        if not tokens.get("access_token"):
            env_tokens = {
                "access_token": os.getenv("QBO_ACCESS_TOKEN"),
                "refresh_token": os.getenv("QBO_REFRESH_TOKEN"),
                "environment": os.getenv("QBO_ENVIRONMENT", "sandbox"),
                "realm_id": os.getenv("QBO_REALM_ID"),
            }
            env_tokens = {k: v for k, v in env_tokens.items() if v is not None}
            if env_tokens.get("access_token"):
                tokens = env_tokens
                logger.info("Loaded tokens from environment variables.")

        # 4. Last resort: interactive OAuth
        if not tokens.get("access_token"):
            logger.warning("No tokens found. Starting new authentication session.")
            tokens = run_interactive_oauth(self.auth_client, self.config.scopes)
            self._save_tokens(tokens)

        # Set tokens on auth_client
        self.auth_client.access_token = tokens.get("access_token")
        self.auth_client.refresh_token = tokens.get("refresh_token")
        self.auth_client.environment = tokens.get("environment", "sandbox")
        self.auth_client.realm_id = tokens.get("realm_id")
```

Replace `_save_tokens()` (lines 92-111) with:

```python
    def _save_tokens(self, tokens=None) -> None:
        try:
            if tokens is None:
                tokens = {
                    "access_token": self.auth_client.access_token,
                    "refresh_token": self.auth_client.refresh_token,
                    "environment": self.auth_client.environment,
                    "realm_id": self.auth_client.realm_id,
                }
            self._token_backend.save(tokens)
        except Exception as e:
            logger.error(f"Error saving tokens: {e}")
```

**Step 8: Add --push-to-gcp to get_tokens.py**

In `scripts/get_tokens.py`, add argument (after the `--token-file` argument):

```python
    parser.add_argument(
        "--push-to-gcp",
        action="store_true",
        help="Upload local token file to GCP Secret Manager",
    )
```

Add this block after the existing `main()` logic, before the final `print`:

```python
    if args.push_to_gcp:
        from qbo_mcp.token_backends import GCPTokenBackend
        project_id = os.getenv("GCP_PROJECT_ID", "gen-lang-client-0253282755")
        book_name = token_file.stem
        secret_id = f"qbo-tokens-{book_name}"
        print(f"\nPushing to GCP Secret Manager: {secret_id}")
        backend = GCPTokenBackend(project_id=project_id, secret_id=secret_id)
        backend.save(tokens)
        print(f"Uploaded to GCP secret: {secret_id}")
```

**Step 9: Update env.example**

Append to `env.example`:

```
# Token storage backend: 'local' (default) or 'gcp'
QBO_TOKEN_BACKEND=local

# GCP project ID (required when QBO_TOKEN_BACKEND=gcp)
GCP_PROJECT_ID=gen-lang-client-0253282755
```

**Step 10: Run all tests**

Run: `cd /Users/ericcuevas/qbo-mcp && uv run pytest tests/ -v`
Expected: All pass

**Step 11: Commit**

```bash
git add src/qbo_mcp/token_backends.py tests/test_token_backends.py src/qbo_mcp/auth.py src/qbo_mcp/config/config.py scripts/get_tokens.py pyproject.toml env.example
git commit -m "feat: GCP Secret Manager token backend with local fallback"
```

---

### Task 4: Push Existing Tokens to GCP + Smoke Test

**Files:**
- No new files

**Step 1: Push all 3 token files to GCP**

```bash
cd /Users/ericcuevas/qbo-mcp
uv run python scripts/get_tokens.py --token-file tokens/ecre.json --push-to-gcp
uv run python scripts/get_tokens.py --token-file tokens/bcd.json --push-to-gcp
uv run python scripts/get_tokens.py --token-file tokens/bmr.json --push-to-gcp
```

Expected: Each prints "Uploaded to GCP secret: qbo-tokens-{book}"

**Step 2: Smoke test — verify GCP backend works end-to-end**

```bash
cd /Users/ericcuevas/qbo-mcp
QBO_TOKEN_BACKEND=gcp QBO_TOKEN_FILE=/Users/ericcuevas/qbo-mcp/tokens/ecre.json \
  uv run python -c "
from qbo_mcp.token_backends import GCPTokenBackend
backend = GCPTokenBackend('gen-lang-client-0253282755', 'qbo-tokens-ecre')
tokens = backend.load()
print(f'Realm ID: {tokens.get(\"realm_id\")}')
print(f'Has access token: {bool(tokens.get(\"access_token\"))}')
print(f'Has refresh token: {bool(tokens.get(\"refresh_token\"))}')
"
```

Expected: Prints realm ID 1321803265, both tokens present.

**Step 3: Smoke test — readonly guard blocks writes**

```bash
cd /Users/ericcuevas/qbo-mcp
uv run python -c "
from unittest.mock import MagicMock
from qbo_mcp.readonly_guard import apply_readonly_guard
client = MagicMock()
apply_readonly_guard(client)
try:
    client.post('/url', {})
    print('FAIL: post was not blocked')
except PermissionError as e:
    print(f'PASS: {e}')
result = client.get('/url')
print(f'PASS: get() returned {result}')
"
```

Expected: `PASS: QBO MCP is read-only...` then `PASS: get() returned ...`

**Step 4: Verify auth log file**

```bash
ls -la /Users/ericcuevas/qbo-mcp/logs/qbo-auth.log
```

Expected: File exists with recent entries.

**Step 5: Add logs/ to .gitignore**

In `.gitignore`, append: `logs/`

**Step 6: Final commit**

```bash
git add .gitignore
git commit -m "chore: add logs/ to gitignore after smoke tests"
git push origin develop
```

---

### Summary

| Task | Component | New Files | Tests |
|------|-----------|-----------|-------|
| 1 | Read-only guard | `readonly_guard.py` | 10 |
| 2 | Auth logger + Chat alerts | `auth_logger.py` | 6 |
| 3 | GCP token backend | `token_backends.py` | 9 |
| 4 | Push tokens + smoke test | — | manual |
| **Total** | | **3 new modules** | **25 automated** |
