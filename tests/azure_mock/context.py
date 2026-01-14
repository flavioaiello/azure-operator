"""Azure Mock Context for integration testing.

Provides context manager that patches Azure SDK components with mock implementations.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any
from unittest import mock

from .credential import MockManagedIdentityCredential, create_mock_credential
from .resources import MockResourceClient, MockResourceState

if TYPE_CHECKING:
    pass


class MockAzureContext:
    """Context manager for Azure API mocking in integration tests.

    Patches:
    - azure.identity.ManagedIdentityCredential → MockManagedIdentityCredential
    - azure.mgmt.resource.ResourceManagementClient → MockResourceClient

    Provides access to mock state for test assertions.

    Usage:
        with MockAzureContext() as ctx:
            # Operator code will use mocked Azure APIs
            reconciler = Reconciler(config)
            await reconciler._reconcile_once()

            # Assert on mock state
            assert ctx.state.deployment_count == 1
            assert ctx.credential.get_token_call_count == 1
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        fail_auth: bool = False,
        fail_deployments: bool = False,
        initial_resources: list[dict[str, Any]] | None = None,
    ) -> None:
        """Initialize mock context.

        Args:
            client_id: User-assigned identity client ID to simulate.
            fail_auth: Whether authentication should fail.
            fail_deployments: Whether deployments should fail.
            initial_resources: Resources to pre-populate in state.
        """
        self._client_id = client_id
        self._fail_auth = fail_auth
        self._fail_deployments = fail_deployments
        self._initial_resources = initial_resources or []

        # These are set when context is entered
        self._state: MockResourceState | None = None
        self._credential: MockManagedIdentityCredential | None = None
        self._patches: list[Any] = []

    @property
    def state(self) -> MockResourceState:
        """Get the mock resource state.

        Raises:
            RuntimeError: If accessed outside of context.
        """
        if self._state is None:
            raise RuntimeError("MockAzureContext must be used as a context manager")
        return self._state

    @property
    def credential(self) -> MockManagedIdentityCredential:
        """Get the mock credential.

        Raises:
            RuntimeError: If accessed outside of context.
        """
        if self._credential is None:
            raise RuntimeError("MockAzureContext must be used as a context manager")
        return self._credential

    def get_deployment_count(self) -> int:
        """Get number of deployments executed."""
        return self.state.deployment_count

    def get_resource_count(self) -> int:
        """Get number of resources in state."""
        return self.state.resource_count

    def get_deployments(self) -> list[Any]:
        """Get all deployments in execution order."""
        return self.state.get_deployment_history()

    def __enter__(self) -> MockAzureContext:
        """Enter the mock context, applying patches."""
        # Initialize state
        self._state = MockResourceState()
        self._credential = create_mock_credential(client_id=self._client_id)

        if self._fail_auth:
            self._credential.set_failure(True, "Simulated authentication failure")

        # Pre-populate resources if provided
        from .resources import MockResource

        for resource_data in self._initial_resources:
            resource = MockResource(
                resource_id=resource_data["resource_id"],
                resource_type=resource_data["resource_type"],
                name=resource_data["name"],
                location=resource_data.get("location", "westeurope"),
                properties=resource_data.get("properties", {}),
                tags=resource_data.get("tags", {}),
            )
            self._state.put_resource(resource)

        # Patch ManagedIdentityCredential
        credential_patch = mock.patch(
            "controller.security.ManagedIdentityCredential",
            return_value=self._credential,
        )
        self._patches.append(credential_patch)

        # Create factory for ResourceManagementClient that uses our state
        def create_mock_client(credential: Any, subscription_id: str) -> MockResourceClient:
            return MockResourceClient(
                state=self._state,
                subscription_id=subscription_id,
                fail_deployments=self._fail_deployments,
            )

        client_patch = mock.patch(
            "controller.reconciler.ResourceManagementClient",
            side_effect=create_mock_client,
        )
        self._patches.append(client_patch)

        # Start all patches
        for patch in self._patches:
            patch.start()

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the mock context, removing patches."""
        # Stop all patches in reverse order
        for patch in reversed(self._patches):
            patch.stop()
        self._patches.clear()


@contextmanager
def mock_azure_context(
    *,
    client_id: str | None = None,
    fail_auth: bool = False,
    fail_deployments: bool = False,
    initial_resources: list[dict[str, Any]] | None = None,
) -> Generator[MockAzureContext, None, None]:
    """Convenience function for creating a mock Azure context.

    Args:
        client_id: User-assigned identity client ID to simulate.
        fail_auth: Whether authentication should fail.
        fail_deployments: Whether deployments should fail.
        initial_resources: Resources to pre-populate in state.

    Yields:
        MockAzureContext for test assertions.
    """
    ctx = MockAzureContext(
        client_id=client_id,
        fail_auth=fail_auth,
        fail_deployments=fail_deployments,
        initial_resources=initial_resources,
    )
    with ctx:
        yield ctx
