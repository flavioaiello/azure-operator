"""Mock Resource Graph client for testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

from azure.mgmt.resourcegraph.models import QueryResponse


@dataclass
class MockGraphChange:
    """Mock change event for testing."""

    resource_id: str
    change_type: str = "Update"
    changed_by: str = "test@example.com"
    client_type: str = "Azure Portal"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    changes: dict[str, Any] | None = None


@dataclass
class MockGraphResource:
    """Mock resource for testing."""

    resource_id: str
    name: str
    type: str
    location: str = "westeurope"
    resource_group: str = "rg-test"
    subscription_id: str = "00000000-0000-0000-0000-000000000000"
    tags: dict[str, str] | None = None


class MockResourceGraphClient:
    """Mock Resource Graph client for testing.

    Simulates Resource Graph API responses for:
    - ResourceChanges queries (change detection)
    - Resources queries (inventory)
    """

    def __init__(self) -> None:
        """Initialize mock state."""
        self._changes: list[MockGraphChange] = []
        self._resources: list[MockGraphResource] = []
        self._query_count = 0
        self._should_fail = False
        self._fail_message = "Mock failure"

    def add_change(self, change: MockGraphChange) -> None:
        """Add a mock change event."""
        self._changes.append(change)

    def add_resource(self, resource: MockGraphResource) -> None:
        """Add a mock resource."""
        self._resources.append(resource)

    def set_should_fail(self, should_fail: bool, message: str = "Mock failure") -> None:
        """Configure the mock to fail on next query."""
        self._should_fail = should_fail
        self._fail_message = message

    def clear(self) -> None:
        """Clear all mock state."""
        self._changes.clear()
        self._resources.clear()
        self._query_count = 0
        self._should_fail = False

    @property
    def query_count(self) -> int:
        """Get the number of queries executed."""
        return self._query_count

    def resources(self, request: Any) -> QueryResponse:
        """Mock Resource Graph query execution.

        Args:
            request: Query request (contains query string).

        Returns:
            QueryResponse with mock data.

        Raises:
            Exception: If configured to fail.
        """
        self._query_count += 1

        if self._should_fail:
            from azure.core.exceptions import HttpResponseError

            raise HttpResponseError(message=self._fail_message)

        query = request.query.lower()

        # Determine if this is a changes query or resources query
        if "resourcechanges" in query:
            return self._build_changes_response()
        else:
            return self._build_resources_response()

    def _build_changes_response(self) -> QueryResponse:
        """Build mock response for ResourceChanges query."""
        data = []
        for change in self._changes:
            data.append(
                {
                    "resourceId": change.resource_id,
                    "changeType": change.change_type,
                    "timestamp": change.timestamp.isoformat(),
                    "changedBy": change.changed_by,
                    "clientType": change.client_type,
                    "changes": change.changes,
                }
            )

        response = MagicMock(spec=QueryResponse)
        response.data = data
        response.count = len(data)
        response.total_records = len(data)
        return response

    def _build_resources_response(self) -> QueryResponse:
        """Build mock response for Resources query."""
        data = []
        for resource in self._resources:
            data.append(
                {
                    "id": resource.resource_id,
                    "name": resource.name,
                    "type": resource.type,
                    "location": resource.location,
                    "resourceGroup": resource.resource_group,
                    "subscriptionId": resource.subscription_id,
                    "tags": resource.tags,
                }
            )

        response = MagicMock(spec=QueryResponse)
        response.data = data
        response.count = len(data)
        response.total_records = len(data)
        return response


def create_mock_graph_client() -> MockResourceGraphClient:
    """Create a mock Resource Graph client for testing."""
    return MockResourceGraphClient()
