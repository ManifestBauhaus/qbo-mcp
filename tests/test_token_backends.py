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


# ===== Old-version prune (2026-10-01: ~4,400 live versions billed monthly, $266 in Sep 2026) =====
from qbo_mcp.token_backends import prune_old_versions  # noqa: E402


class _V:
    def __init__(self, n):
        self.name = f"projects/p/secrets/s/versions/{n}"


class _FakeSM:
    def __init__(self, nums, fail_list=False, fail_destroy_at=None):
        self.nums, self.fail_list, self.fail_destroy_at = nums, fail_list, fail_destroy_at
        self.destroyed = []

    def list_secret_versions(self, request):
        assert request["filter"] == "state:(ENABLED OR DISABLED)"
        if self.fail_list:
            raise RuntimeError("403 Permission 'secretmanager.versions.list' denied")
        return [_V(n) for n in self.nums]

    def destroy_secret_version(self, request):
        n = int(request["name"].rsplit("/", 1)[1])
        if n == self.fail_destroy_at:
            raise RuntimeError("403 Permission 'secretmanager.versions.destroy' denied")
        self.destroyed.append(n)


def test_prune_keeps_the_two_highest_version_numbers_whatever_the_list_order():
    sm = _FakeSM([3, 10, 1, 7, 9, 2])
    assert prune_old_versions(sm, "projects/p/secrets/s") == (4, "")
    assert sorted(sm.destroyed) == [1, 2, 3, 7]          # 10 and 9 survive


def test_prune_is_capped_per_call_and_newest_never_destroyed():
    sm = _FakeSM(list(range(1, 501)))
    assert prune_old_versions(sm, "x", max_destroy=200) == (200, "")
    assert 500 not in sm.destroyed and 499 not in sm.destroyed
    assert sm.destroyed == list(range(1, 201))           # oldest first; recent extras wait for later runs
    with pytest.raises(ValueError):
        prune_old_versions(_FakeSM([1, 2]), "x", keep=0)


def test_prune_never_raises_and_reports_why():
    destroyed, err = prune_old_versions(_FakeSM([1, 2, 3], fail_list=True), "x")
    assert destroyed == 0 and "list failed" in err
    sm = _FakeSM([1, 2, 3, 4, 5], fail_destroy_at=2)
    destroyed, err = prune_old_versions(sm, "x")
    assert destroyed == 1 and "destroy failed at 2" in err and sm.destroyed == [1]
    assert prune_old_versions(_FakeSM([1, 2]), "x") == (0, "")


@patch("google.cloud.secretmanager.SecretManagerServiceClient")
def test_save_prunes_after_writing(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.list_secret_versions.return_value = [_V(n) for n in (1, 2, 3)]
    GCPTokenBackend(project_id="p", secret_id="s").save(SAMPLE_TOKENS)
    mock_client.add_secret_version.assert_called_once()
    mock_client.destroy_secret_version.assert_called_once_with(request={"name": "projects/p/secrets/s/versions/1"})


def test_interactive_save_cap_is_small():
    from qbo_mcp import token_backends as tb
    assert tb.PRUNE_MAX_INTERACTIVE <= 10 < tb.PRUNE_MAX_PER_CALL
