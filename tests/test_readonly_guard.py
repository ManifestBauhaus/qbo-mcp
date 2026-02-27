"""Tests for the read-only guard that blocks all QBO write operations."""

import pytest
from unittest.mock import MagicMock

from qbo_mcp.readonly_guard import apply_readonly_guard


class TestReadonlyGuardBlocks:
    """Tests that the guard blocks all write methods."""

    def test_guard_blocks_post(self):
        client = MagicMock()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.post()

    def test_guard_blocks_create_object(self):
        client = MagicMock()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.create_object()

    def test_guard_blocks_update_object(self):
        client = MagicMock()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.update_object()

    def test_guard_blocks_delete_object(self):
        client = MagicMock()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.delete_object()

    def test_guard_blocks_batch_operation(self):
        client = MagicMock()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.batch_operation()

    def test_guard_blocks_misc_operation(self):
        client = MagicMock()
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="read-only"):
            client.misc_operation()


class TestReadonlyGuardMakeRequest:
    """Tests that make_request is wrapped to only allow GET."""

    def test_guard_blocks_post_via_make_request(self):
        client = MagicMock()
        client.make_request.return_value = {"ok": True}
        apply_readonly_guard(client)
        with pytest.raises(PermissionError, match="HTTP POST is blocked"):
            client.make_request("POST", "/url", {})

    def test_guard_allows_get_via_make_request(self):
        original_return = {"Id": "42", "Name": "Acme"}
        client = MagicMock()
        client.make_request.return_value = original_return
        apply_readonly_guard(client)
        result = client.make_request("GET", "/url")
        assert result == original_return


class TestReadonlyGuardAllows:
    """Tests that the guard allows read methods to work normally."""

    def test_guard_allows_get(self):
        client = MagicMock()
        client.get.return_value = {"Id": "1", "Name": "Test"}
        apply_readonly_guard(client)
        result = client.get()
        assert result == {"Id": "1", "Name": "Test"}

    def test_guard_allows_get_report(self):
        client = MagicMock()
        client.get_report.return_value = {"Header": {}, "Rows": []}
        apply_readonly_guard(client)
        result = client.get_report()
        assert result == {"Header": {}, "Rows": []}


class TestReadonlyGuardIdempotent:
    """Tests that applying the guard multiple times is safe."""

    def test_guard_is_idempotent(self):
        client = MagicMock()
        client.get.return_value = {"Id": "1"}

        # Apply twice
        apply_readonly_guard(client)
        apply_readonly_guard(client)

        # Blocks still work
        with pytest.raises(PermissionError, match="read-only"):
            client.post()
        with pytest.raises(PermissionError, match="read-only"):
            client.create_object()

        # Allows still work
        result = client.get()
        assert result == {"Id": "1"}
