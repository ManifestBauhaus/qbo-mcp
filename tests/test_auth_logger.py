"""Tests for the auth event logger and Google Chat alert integration."""

from unittest.mock import patch

from qbo_mcp.auth_logger import AuthEventLogger


class TestAuthEventLogger:
    def test_log_refresh_success(self, tmp_path):
        logger = AuthEventLogger(log_dir=tmp_path)
        logger.log_refresh_success(realm_id="123456", book_name="bmr")
        log_content = (tmp_path / "qbo-auth.log").read_text()
        assert "REFRESH_SUCCESS" in log_content
        assert "bmr" in log_content
        assert "123456" in log_content

    def test_log_refresh_failure(self, tmp_path):
        logger = AuthEventLogger(log_dir=tmp_path)
        logger.log_refresh_failure(
            realm_id="123456", book_name="bmr", error="token expired"
        )
        log_content = (tmp_path / "qbo-auth.log").read_text()
        assert "REFRESH_FAILURE" in log_content
        assert "bmr" in log_content
        assert "token expired" in log_content

    def test_log_creates_directory(self, tmp_path):
        nested = tmp_path / "deep" / "nested" / "logs"
        logger = AuthEventLogger(log_dir=nested)
        logger.log_refresh_success(realm_id="999", book_name="ecre")
        assert nested.exists()
        assert (nested / "qbo-auth.log").exists()

    @patch("qbo_mcp.auth_logger.urllib.request.urlopen")
    def test_chat_alert_on_failure(self, mock_urlopen, tmp_path):
        logger = AuthEventLogger(
            log_dir=tmp_path,
            chat_webhook_url="https://chat.googleapis.com/v1/spaces/test/messages?key=abc",
        )
        logger.log_refresh_failure(
            realm_id="123456", book_name="bmr", error="token expired"
        )
        mock_urlopen.assert_called_once()
        # Verify the request body contains expected fields
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        import json

        body = json.loads(request.data.decode("utf-8"))
        assert "bmr" in body["text"]
        assert "123456" in body["text"]

    def test_no_crash_without_webhook_url(self, tmp_path):
        logger = AuthEventLogger(log_dir=tmp_path)
        # Should not raise even without a webhook URL
        logger.log_refresh_failure(
            realm_id="123456", book_name="bmr", error="token expired"
        )

    def test_log_write_blocked(self, tmp_path):
        logger = AuthEventLogger(log_dir=tmp_path)
        logger.log_write_blocked(method_name="post", details="attempted POST")
        log_content = (tmp_path / "qbo-auth.log").read_text()
        assert "WRITE_BLOCKED" in log_content
        assert "post" in log_content
