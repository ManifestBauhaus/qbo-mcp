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

    @abstractmethod
    def delete(self) -> None:
        """Remove stored tokens."""
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

    def delete(self) -> None:
        if self.token_file.exists():
            self.token_file.unlink()
            logger.info(f"Deleted token file {self.token_file}")


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
        from google.api_core.exceptions import NotFound
        payload = json.dumps(tokens, indent=2).encode("utf-8")
        try:
            self._client.add_secret_version(
                request={
                    "parent": self._secret_path,
                    "payload": {"data": payload},
                }
            )
            logger.info(f"Saved tokens to GCP secret {self._secret_id}")
        except NotFound:
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

    def delete(self) -> None:
        from google.api_core.exceptions import NotFound
        try:
            # Disable the latest version rather than destroying the secret
            name = f"{self._secret_path}/versions/latest"
            self._client.disable_secret_version(request={"name": name})
            logger.info(f"Disabled GCP secret version {self._secret_id}")
        except NotFound:
            logger.info(f"GCP secret {self._secret_id} not found, nothing to delete")
        except Exception as e:
            logger.warning(f"Error disabling GCP secret: {e}")


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
