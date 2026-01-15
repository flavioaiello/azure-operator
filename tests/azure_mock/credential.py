"""Mock Azure credential for secretless testing.

Provides a mock ManagedIdentityCredential that returns fake tokens
without requiring Azure connectivity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

# Token validity duration
TOKEN_VALIDITY_HOURS = 1


class MockCredentialError(Exception):
    """Mock credential authentication error.

    Simulates Azure SDK's ClientAuthenticationError for test scenarios.
    """

    pass


@dataclass
class MockAccessToken:
    """Mock Azure access token.

    Mimics azure.core.credentials.AccessToken structure.
    """

    token: str
    expires_on: int

    def __post_init__(self) -> None:
        """Validate token format."""
        if not self.token:
            raise ValueError("Token cannot be empty")


class MockManagedIdentityCredential:
    """Mock implementation of ManagedIdentityCredential.

    Returns fake tokens that allow testing without Azure connectivity.
    Tracks authentication calls for test assertions.

    Thread-safe: Each instance maintains its own state.
    """

    def __init__(self, client_id: str | None = None) -> None:
        """Initialize mock credential.

        Args:
            client_id: Optional user-assigned identity client ID.
        """
        self._client_id = client_id
        self._get_token_calls: list[dict[str, Any]] = []
        self._token_counter = 0
        self._should_fail = False
        self._failure_message = "Authentication failed"

    @property
    def client_id(self) -> str | None:
        """Get the configured client ID."""
        return self._client_id

    @property
    def get_token_call_count(self) -> int:
        """Get the number of times get_token was called."""
        return len(self._get_token_calls)

    @property
    def get_token_calls(self) -> list[dict[str, Any]]:
        """Get all recorded get_token calls."""
        return self._get_token_calls.copy()

    def set_failure(self, should_fail: bool, message: str = "Authentication failed") -> None:
        """Configure the credential to fail on next get_token call.

        Args:
            should_fail: Whether to fail.
            message: Error message to raise.
        """
        self._should_fail = should_fail
        self._failure_message = message

    def get_token(
        self,
        *scopes: str,
        claims: str | None = None,
        tenant_id: str | None = None,
        **kwargs: Any,
    ) -> MockAccessToken:
        """Get a mock access token.

        Args:
            scopes: Token scopes (e.g., "https://management.azure.com/.default").
            claims: Optional claims challenge.
            tenant_id: Optional tenant ID.
            **kwargs: Additional arguments.

        Returns:
            Mock access token.

        Raises:
            Exception: If configured to fail.
        """
        # Record the call
        self._get_token_calls.append({
            "scopes": scopes,
            "claims": claims,
            "tenant_id": tenant_id,
            "kwargs": kwargs,
            "timestamp": datetime.now(UTC).isoformat(),
        })

        # Check if we should fail
        if self._should_fail:
            raise MockCredentialError(self._failure_message)

        # Generate a fake token
        self._token_counter += 1
        expires_on = datetime.now(UTC) + timedelta(hours=TOKEN_VALIDITY_HOURS)

        # Token format: mock-token-{counter}-{client_id or system}
        identity_part = self._client_id or "system-assigned"
        token = f"mock-token-{self._token_counter}-{identity_part}"

        return MockAccessToken(
            token=token,
            expires_on=int(expires_on.timestamp()),
        )

    def close(self) -> None:
        """Close the credential (no-op for mock)."""
        pass

    def __enter__(self) -> MockManagedIdentityCredential:
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit."""
        self.close()


def create_mock_credential(client_id: str | None = None) -> MockManagedIdentityCredential:
    """Factory function to create a mock credential.

    Args:
        client_id: Optional user-assigned identity client ID.

    Returns:
        MockManagedIdentityCredential instance.
    """
    return MockManagedIdentityCredential(client_id=client_id)
