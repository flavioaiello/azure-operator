"""Mock Azure Resource Manager state and operations.

Provides in-memory state management for Azure resources with
realistic WhatIf and deployment simulation.
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class DeploymentProvisioningState(str, Enum):
    """Azure deployment provisioning states."""

    ACCEPTED = "Accepted"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"


class WhatIfChangeType(str, Enum):
    """Azure WhatIf change types."""

    CREATE = "Create"
    DELETE = "Delete"
    MODIFY = "Modify"
    NO_CHANGE = "NoChange"
    IGNORE = "Ignore"
    DEPLOY = "Deploy"


@dataclass
class MockResource:
    """Represents a mock Azure resource in state.

    Immutable after creation - use copy_with() to create modified versions.
    """

    resource_id: str
    resource_type: str
    name: str
    location: str
    properties: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    api_version: str = "2024-01-01"

    def __post_init__(self) -> None:
        """Validate resource after creation."""
        if not self.resource_id:
            raise ValueError("resource_id cannot be empty")
        if not self.resource_type:
            raise ValueError("resource_type cannot be empty")

    def copy_with(self, **updates: Any) -> MockResource:
        """Create a copy with updated fields.

        Args:
            **updates: Fields to update.

        Returns:
            New MockResource with updates applied.
        """
        current = {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "name": self.name,
            "location": self.location,
            "properties": copy.deepcopy(self.properties),
            "tags": copy.deepcopy(self.tags),
            "created_at": self.created_at,
            "updated_at": datetime.now(UTC),
            "api_version": self.api_version,
        }
        current.update(updates)
        return MockResource(**current)


@dataclass
class MockDeployment:
    """Represents a mock ARM deployment."""

    name: str
    subscription_id: str
    resource_group: str | None
    location: str
    template: dict[str, Any]
    parameters: dict[str, Any]
    mode: str = "Incremental"
    provisioning_state: DeploymentProvisioningState = DeploymentProvisioningState.ACCEPTED
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    error: dict[str, Any] | None = None
    management_group_id: str | None = None
    outputs: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Get deployment resource ID."""
        if self.resource_group:
            return (
                f"/subscriptions/{self.subscription_id}"
                f"/resourceGroups/{self.resource_group}"
                f"/providers/Microsoft.Resources/deployments/{self.name}"
            )
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.Resources/deployments/{self.name}"
        )


@dataclass
class MockWhatIfChange:
    """Represents a single change in WhatIf result."""

    resource_id: str
    change_type: WhatIfChangeType
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    delta: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class MockWhatIfProperties:
    """Properties of a WhatIf result (matches Azure SDK structure)."""

    status: str = "Succeeded"
    changes: list[MockWhatIfChange] = field(default_factory=list)
    error: dict[str, Any] | None = None


@dataclass
class MockWhatIfResult:
    """Represents the result of a WhatIf operation.

    Matches Azure SDK's WhatIfOperationResult structure with:
    - properties.changes (list of changes)
    - properties.status (Succeeded/Failed)
    """

    properties: MockWhatIfProperties = field(default_factory=MockWhatIfProperties)

    @property
    def has_changes(self) -> bool:
        """Check if there are any non-trivial changes."""
        if self.properties.changes is None:
            return False
        return any(
            c.change_type not in (WhatIfChangeType.NO_CHANGE, WhatIfChangeType.IGNORE)
            for c in self.properties.changes
        )


class MockResourceState:
    """In-memory Azure resource state manager.

    Thread-safe state management for mock Azure resources.
    Supports resource CRUD operations and deployment tracking.

    All operations are synchronous since this is test code.
    """

    # Maximum resources to prevent unbounded growth in tests
    MAX_RESOURCES = 10000
    MAX_DEPLOYMENTS = 1000

    def __init__(self) -> None:
        """Initialize empty state."""
        self._resources: dict[str, MockResource] = {}
        self._deployments: dict[str, MockDeployment] = {}
        self._deployment_history: list[MockDeployment] = []

    @property
    def resource_count(self) -> int:
        """Get current resource count."""
        return len(self._resources)

    @property
    def deployment_count(self) -> int:
        """Get current deployment count."""
        return len(self._deployments)

    def get_resource(self, resource_id: str) -> MockResource | None:
        """Get a resource by ID.

        Args:
            resource_id: Full ARM resource ID.

        Returns:
            MockResource if found, None otherwise.
        """
        return self._resources.get(resource_id)

    def list_resources(
        self,
        resource_type: str | None = None,
        resource_group: str | None = None,
    ) -> list[MockResource]:
        """List resources with optional filtering.

        Args:
            resource_type: Filter by resource type.
            resource_group: Filter by resource group name.

        Returns:
            List of matching resources.
        """
        results = list(self._resources.values())

        if resource_type:
            results = [r for r in results if r.resource_type == resource_type]

        if resource_group:
            results = [
                r for r in results
                if f"/resourceGroups/{resource_group}/" in r.resource_id
            ]

        return results

    def put_resource(self, resource: MockResource) -> MockResource:
        """Create or update a resource.

        Args:
            resource: Resource to store.

        Returns:
            Stored resource.

        Raises:
            ValueError: If resource limit exceeded.
        """
        if (
            resource.resource_id not in self._resources
            and len(self._resources) >= self.MAX_RESOURCES
        ):
            raise ValueError(
                f"Resource limit exceeded: {self.MAX_RESOURCES}. "
                "Clear state or increase MAX_RESOURCES."
            )

        self._resources[resource.resource_id] = resource
        return resource

    def delete_resource(self, resource_id: str) -> bool:
        """Delete a resource by ID.

        Args:
            resource_id: Full ARM resource ID.

        Returns:
            True if deleted, False if not found.
        """
        if resource_id in self._resources:
            del self._resources[resource_id]
            return True
        return False

    def get_deployment(self, name: str) -> MockDeployment | None:
        """Get a deployment by name.

        Args:
            name: Deployment name.

        Returns:
            MockDeployment if found, None otherwise.
        """
        return self._deployments.get(name)

    def create_deployment(self, deployment: MockDeployment) -> MockDeployment:
        """Create a new deployment.

        Args:
            deployment: Deployment to create.

        Returns:
            Created deployment.

        Raises:
            ValueError: If deployment limit exceeded.
        """
        if len(self._deployments) >= self.MAX_DEPLOYMENTS:
            raise ValueError(
                f"Deployment limit exceeded: {self.MAX_DEPLOYMENTS}. "
                "Clear state or increase MAX_DEPLOYMENTS."
            )

        self._deployments[deployment.name] = deployment
        self._deployment_history.append(deployment)
        return deployment

    def update_deployment_state(
        self,
        name: str,
        state: DeploymentProvisioningState,
        error: dict[str, Any] | None = None,
        outputs: dict[str, Any] | None = None,
    ) -> MockDeployment | None:
        """Update deployment provisioning state.

        Args:
            name: Deployment name.
            state: New provisioning state.
            error: Optional error details.
            outputs: Optional deployment outputs.

        Returns:
            Updated deployment, or None if not found.
        """
        deployment = self._deployments.get(name)
        if deployment:
            deployment.provisioning_state = state
            if error:
                deployment.error = error
            if outputs:
                deployment.outputs = outputs
        return deployment

    def compute_whatif(
        self,
        template: dict[str, Any],
        parameters: dict[str, Any],  # noqa: ARG002 - kept for API compatibility
        subscription_id: str,
        resource_group: str | None = None,
        management_group_id: str | None = None,
    ) -> MockWhatIfResult:
        """Compute WhatIf result for a template deployment.

        Compares template resources against current state to determine changes.

        Args:
            template: ARM template.
            parameters: Template parameters.
            subscription_id: Target subscription.
            resource_group: Target resource group (for RG-scoped deployments).
            management_group_id: Target management group (for MG-scoped deployments).

        Returns:
            WhatIfResult with detected changes.
        """
        changes: list[MockWhatIfChange] = []

        # Extract resources from template
        template_resources = template.get("resources", [])

        for resource_def in template_resources:
            resource_type = resource_def.get("type", "")
            resource_name = resource_def.get("name", "")
            location = resource_def.get("location", "")

            # Construct resource ID based on scope
            if management_group_id:
                # Management group scope (ALZ pattern)
                resource_id = (
                    f"/providers/Microsoft.Management/managementGroups/{management_group_id}"
                    f"/providers/{resource_type}/{resource_name}"
                )
            elif resource_group:
                resource_id = (
                    f"/subscriptions/{subscription_id}"
                    f"/resourceGroups/{resource_group}"
                    f"/providers/{resource_type}/{resource_name}"
                )
            else:
                resource_id = (
                    f"/subscriptions/{subscription_id}"
                    f"/providers/{resource_type}/{resource_name}"
                )

            # Check if resource exists
            existing = self.get_resource(resource_id)

            if existing is None:
                # New resource
                changes.append(MockWhatIfChange(
                    resource_id=resource_id,
                    change_type=WhatIfChangeType.CREATE,
                    before=None,
                    after={
                        "type": resource_type,
                        "name": resource_name,
                        "location": location,
                        "properties": resource_def.get("properties", {}),
                    },
                ))
            else:
                # Compare properties
                new_props = resource_def.get("properties", {})
                if new_props != existing.properties:
                    changes.append(MockWhatIfChange(
                        resource_id=resource_id,
                        change_type=WhatIfChangeType.MODIFY,
                        before={"properties": existing.properties},
                        after={"properties": new_props},
                    ))
                else:
                    changes.append(MockWhatIfChange(
                        resource_id=resource_id,
                        change_type=WhatIfChangeType.NO_CHANGE,
                    ))

        return MockWhatIfResult(
            properties=MockWhatIfProperties(status="Succeeded", changes=changes)
        )

    def apply_deployment(self, deployment: MockDeployment) -> None:
        """Apply a deployment to state (create/update resources).

        Args:
            deployment: Deployment to apply.
        """
        template = deployment.template
        template_resources = template.get("resources", [])

        for resource_def in template_resources:
            resource_type = resource_def.get("type", "")
            resource_name = resource_def.get("name", "")
            location = resource_def.get("location", deployment.location)

            if deployment.resource_group:
                resource_id = (
                    f"/subscriptions/{deployment.subscription_id}"
                    f"/resourceGroups/{deployment.resource_group}"
                    f"/providers/{resource_type}/{resource_name}"
                )
            else:
                resource_id = (
                    f"/subscriptions/{deployment.subscription_id}"
                    f"/providers/{resource_type}/{resource_name}"
                )

            resource = MockResource(
                resource_id=resource_id,
                resource_type=resource_type,
                name=resource_name,
                location=location,
                properties=resource_def.get("properties", {}),
                tags=resource_def.get("tags", {}),
            )
            self.put_resource(resource)

    def clear(self) -> None:
        """Clear all state."""
        self._resources.clear()
        self._deployments.clear()
        self._deployment_history.clear()

    def get_deployment_history(self) -> list[MockDeployment]:
        """Get all deployments in order of creation."""
        return self._deployment_history.copy()


class MockResourceClient:
    """Mock implementation of Azure ResourceManagementClient.

    Provides mock implementations of the key ARM operations:
    - deployments.begin_what_if_at_subscription_scope()
    - deployments.begin_create_or_update_at_subscription_scope()
    - deployments.get()
    """

    def __init__(
        self,
        state: MockResourceState,
        subscription_id: str,
        *,
        simulate_delay: bool = False,
        fail_deployments: bool = False,
        failure_rate: float = 0.0,
    ) -> None:
        """Initialize mock client.

        Args:
            state: Shared resource state.
            subscription_id: Target subscription.
            simulate_delay: Whether to simulate network delays.
            fail_deployments: Whether to fail all deployments.
            failure_rate: Probability of random deployment failures (0.0-1.0).
        """
        self._state = state
        self._subscription_id = subscription_id
        self._simulate_delay = simulate_delay
        self._fail_deployments = fail_deployments
        self._failure_rate = failure_rate
        self.deployments = _MockDeploymentsOperations(self)

    @property
    def subscription_id(self) -> str:
        """Get subscription ID."""
        return self._subscription_id


class _MockDeploymentsOperations:
    """Mock ARM deployments operations."""

    def __init__(self, client: MockResourceClient) -> None:
        """Initialize with parent client."""
        self._client = client
        self._state = client._state

    def begin_what_if_at_subscription_scope(
        self,
        _deployment_name: str,
        parameters: Any,
        **_kwargs: Any,
    ) -> _MockLROPoller:
        """Start a WhatIf operation at subscription scope.

        Args:
            _deployment_name: Name for the deployment (unused in mock).
            parameters: ScopedDeploymentWhatIf parameters.
            **_kwargs: Additional arguments (unused in mock).

        Returns:
            Mock LRO poller with WhatIf result.
        """
        # Extract template and parameters from the deployment object
        template = parameters.properties.template
        params = parameters.properties.parameters or {}
        _ = parameters.location  # Explicitly acknowledge unused

        whatif_result = self._state.compute_whatif(
            template=template,
            parameters=params,
            subscription_id=self._client.subscription_id,
        )

        return _MockLROPoller(whatif_result)

    def begin_create_or_update_at_subscription_scope(
        self,
        deployment_name: str,
        parameters: Any,
        **_kwargs: Any,
    ) -> _MockLROPoller:
        """Start a deployment at subscription scope.

        Args:
            deployment_name: Name for the deployment.
            parameters: ScopedDeployment parameters.
            **_kwargs: Additional arguments (unused in mock).

        Returns:
            Mock LRO poller with deployment result.

        Raises:
            Exception: If fail_deployments is enabled.
        """
        template = parameters.properties.template
        params = parameters.properties.parameters or {}
        location = parameters.location

        deployment = MockDeployment(
            name=deployment_name,
            subscription_id=self._client.subscription_id,
            resource_group=None,
            location=location,
            template=template,
            parameters=params,
            provisioning_state=DeploymentProvisioningState.RUNNING,
        )

        self._state.create_deployment(deployment)

        # Simulate deployment failure by raising an exception
        if self._client._fail_deployments:
            self._state.update_deployment_state(
                deployment_name,
                DeploymentProvisioningState.FAILED,
                error={"code": "DeploymentFailed", "message": "Simulated failure"},
            )
            # Return a poller that will raise on result()
            return _MockLROPoller(
                result=None,
                error="Simulated deployment failure",
            )
        else:
            # Apply the deployment
            self._state.apply_deployment(deployment)
            self._state.update_deployment_state(
                deployment_name,
                DeploymentProvisioningState.SUCCEEDED,
            )

        return _MockLROPoller(self._state.get_deployment(deployment_name))

    def begin_what_if_at_management_group_scope(
        self,
        management_group_id: str,
        _deployment_name: str,
        parameters: Any,
        **_kwargs: Any,
    ) -> _MockLROPoller:
        """Start a WhatIf operation at management group scope.

        Args:
            management_group_id: Target management group ID.
            _deployment_name: Name for the deployment (unused in mock).
            parameters: ScopedDeploymentWhatIf parameters.
            **_kwargs: Additional arguments (unused in mock).

        Returns:
            Mock LRO poller with WhatIf result.
        """
        template = parameters.properties.template
        params = parameters.properties.parameters or {}

        whatif_result = self._state.compute_whatif(
            template=template,
            parameters=params,
            subscription_id=self._client.subscription_id,
            management_group_id=management_group_id,
        )

        return _MockLROPoller(whatif_result)

    def begin_create_or_update_at_management_group_scope(
        self,
        management_group_id: str,
        deployment_name: str,
        parameters: Any,
        **_kwargs: Any,
    ) -> _MockLROPoller:
        """Start a deployment at management group scope.

        Args:
            management_group_id: Target management group ID.
            deployment_name: Name for the deployment.
            parameters: ScopedDeployment parameters.
            **_kwargs: Additional arguments (unused in mock).

        Returns:
            Mock LRO poller with deployment result.

        Raises:
            Exception: If fail_deployments is enabled.
        """
        template = parameters.properties.template
        params = parameters.properties.parameters or {}
        location = parameters.location

        deployment = MockDeployment(
            name=deployment_name,
            subscription_id=self._client.subscription_id,
            resource_group=None,
            location=location,
            template=template,
            parameters=params,
            provisioning_state=DeploymentProvisioningState.RUNNING,
            management_group_id=management_group_id,
        )

        self._state.create_deployment(deployment)

        if self._client._fail_deployments:
            self._state.update_deployment_state(
                deployment_name,
                DeploymentProvisioningState.FAILED,
                error={"code": "DeploymentFailed", "message": "Simulated failure"},
            )
            return _MockLROPoller(
                result=None,
                error="Simulated deployment failure",
            )
        else:
            self._state.apply_deployment(deployment)
            self._state.update_deployment_state(
                deployment_name,
                DeploymentProvisioningState.SUCCEEDED,
            )

        return _MockLROPoller(self._state.get_deployment(deployment_name))

    def get(self, _resource_group: str, deployment_name: str) -> MockDeployment | None:
        """Get a deployment by name.

        Args:
            _resource_group: Resource group name (unused, deployments stored by name).
            deployment_name: Deployment name.

        Returns:
            MockDeployment if found.
        """
        return self._state.get_deployment(deployment_name)


class _MockLROPoller:
    """Mock Long-Running Operation poller.

    Immediately returns results (no actual polling needed in tests).
    Can be configured to raise an exception on result().
    """

    def __init__(self, result: Any, error: str | None = None) -> None:
        """Initialize with result or error.

        Args:
            result: The operation result.
            error: Optional error message - if set, result() will raise.
        """
        self._result = result
        self._error = error

    def result(self, _timeout: int | None = None) -> Any:
        """Get the operation result.

        Args:
            _timeout: Ignored in mock.

        Returns:
            The operation result.

        Raises:
            Exception: If an error was configured.
        """
        if self._error:
            from azure.core.exceptions import HttpResponseError

            raise HttpResponseError(message=self._error)
        return self._result

    def wait(self, timeout: int | None = None) -> None:
        """Wait for operation completion (no-op in mock)."""
        pass

    def done(self) -> bool:
        """Check if operation is complete."""
        return True

    def status(self) -> str:
        """Get operation status."""
        return "Failed" if self._error else "Succeeded"
