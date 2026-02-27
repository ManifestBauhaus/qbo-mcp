"""Auth event logger with optional Google Chat webhook alerts.

Logs token refresh successes/failures and write-blocked events to a rotating
log file. On refresh failure, optionally sends a Google Chat alert so the
team can re-authenticate before the token expires.
"""

import json
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_FILENAME = "qbo-auth.log"
_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
_BACKUP_COUNT = 3


class AuthEventLogger:
    """Structured logger for QBO authentication events."""

    def __init__(
        self,
        log_dir: Path | None = None,
        chat_webhook_url: str | None = None,
    ):
        if log_dir is None:
            log_dir = Path(__file__).resolve().parent.parent.parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        self._chat_webhook_url = chat_webhook_url

        log_file = log_dir / _LOG_FILENAME
        # Use a logger name keyed on the resolved log path so each distinct
        # log directory gets its own handler (important for tests with tmp_path).
        logger_name = f"qbo_auth_events.{log_file}"
        self._logger = logging.getLogger(logger_name)
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        # Only add a handler once per logger name (idempotent).
        if not self._logger.handlers:
            handler = RotatingFileHandler(
                log_file,
                maxBytes=_MAX_BYTES,
                backupCount=_BACKUP_COUNT,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_refresh_success(self, realm_id: str, book_name: str) -> None:
        """Record a successful token refresh."""
        ts = self._timestamp()
        self._logger.info("%s | REFRESH_SUCCESS | %s | %s", ts, book_name, realm_id)

    def log_refresh_failure(
        self, realm_id: str, book_name: str, error: str
    ) -> None:
        """Record a failed token refresh and fire a Chat alert."""
        ts = self._timestamp()
        self._logger.error(
            "%s | REFRESH_FAILURE | %s | %s | %s", ts, book_name, realm_id, error
        )
        self._send_chat_alert(
            f"*QBO Token Refresh Failed* for *{book_name.upper()}* "
            f"(Realm {realm_id}).\n"
            f"Error: {error}\n"
            f"Run: `uv run python scripts/get_tokens.py --token-file tokens/{book_name}.json`"
        )

    def log_write_blocked(self, method_name: str, details: str = "") -> None:
        """Record a blocked write attempt."""
        ts = self._timestamp()
        self._logger.warning(
            "%s | WRITE_BLOCKED | %s | %s", ts, method_name, details
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _send_chat_alert(self, message: str) -> None:
        """POST a text card to a Google Chat webhook (best-effort)."""
        if not self._chat_webhook_url:
            return
        try:
            data = json.dumps({"text": message}).encode("utf-8")
            req = urllib.request.Request(
                self._chat_webhook_url,
                data=data,
                headers={"Content-Type": "application/json; charset=UTF-8"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:  # noqa: BLE001
            self._logger.warning("Chat alert failed: %s", exc)
