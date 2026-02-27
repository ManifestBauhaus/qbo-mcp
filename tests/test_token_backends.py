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
    @patch("google.cloud.secretmanager.SecretManagerServiceClient")
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

    @patch("google.cloud.secretmanager.SecretManagerServiceClient")
    def test_save_tokens(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        backend = GCPTokenBackend(project_id="test-project", secret_id="qbo-tokens-ecre")
        backend.save(SAMPLE_TOKENS)
        mock_client.add_secret_version.assert_called_once()
        call_kwargs = mock_client.add_secret_version.call_args
        parent = call_kwargs[1]["request"]["parent"]
        assert "qbo-tokens-ecre" in parent

    @patch("google.cloud.secretmanager.SecretManagerServiceClient")
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

    @patch("google.cloud.secretmanager.SecretManagerServiceClient")
    def test_gcp_backend(self, mock_client_cls):
        backend = get_token_backend(
            "gcp", project_id="test-project", secret_id="qbo-tokens-ecre"
        )
        assert isinstance(backend, GCPTokenBackend)

    def test_invalid_backend(self):
        with pytest.raises(ValueError, match="Unknown token backend"):
            get_token_backend("redis")
