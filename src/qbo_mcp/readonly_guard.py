"""Read-only guard for the QuickBooks client.

Monkey-patches the python-quickbooks QuickBooks client to block all write
HTTP methods. Always on, no toggle. This ensures the MCP server can never
accidentally create, update, or delete QuickBooks objects.
"""

import logging

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
    """Return a function that raises PermissionError when called."""

    def blocked(*args, **kwargs):
        logger.warning(
            "Blocked write operation '%s' on read-only QBO client.", method_name
        )
        raise PermissionError(
            f"QBO MCP is read-only. Write operation '{method_name}' is blocked. "
            "This server only supports read operations (get, get_report, query)."
        )

    return blocked


def _make_readonly_make_request(original):
    """Return a wrapper around make_request that only allows GET requests.

    The QuickBooks client's get() and get_report() internally call
    make_request("GET", ...), so we cannot block make_request outright.
    Instead we intercept it and reject any non-GET HTTP method.
    """

    def wrapper(request_type, *args, **kwargs):
        if request_type.upper() != "GET":
            logger.warning(
                "Blocked non-GET make_request('%s') on read-only QBO client.",
                request_type,
            )
            raise PermissionError(
                f"QBO MCP is read-only. HTTP {request_type} is blocked."
            )
        return original(request_type, *args, **kwargs)

    return wrapper


def apply_readonly_guard(client) -> None:
    """Patch all write methods on the QuickBooks client to raise PermissionError.

    This is idempotent -- calling it multiple times on the same client is safe.

    Args:
        client: A python-quickbooks QuickBooks client instance.
    """
    if getattr(client, _GUARD_ATTR, None) is True:
        logger.info("Read-only guard already applied, skipping.")
        return

    for method_name in BLOCKED_METHODS:
        setattr(client, method_name, _make_blocked_method(method_name))

    if hasattr(client, "make_request"):
        original_make_request = client.make_request
        client.make_request = _make_readonly_make_request(original_make_request)

    setattr(client, _GUARD_ATTR, True)
    logger.info(
        "Read-only guard applied. Blocked methods: %s",
        ", ".join(BLOCKED_METHODS),
    )
