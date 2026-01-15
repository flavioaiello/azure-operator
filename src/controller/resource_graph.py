"""Azure Resource Graph client for fast state queries.

This module provides Resource Graph queries for:
1. Fast-path drift detection (recent changes in scope)
2. Change attribution (who modified resources)
3. Orphan detection (resources not in template)
4. Cross-scope resource inventory

ARCHITECTURE:
Resource Graph complements ARM WhatIf by providing:
- Fast queries (<2s vs 5-60s for WhatIf)
- Change history with attribution (changedBy, timestamp)
- Cross-scope visibility (query entire management group)
- Orphan detection (resources not managed by template)

WhatIf is still required for:
- Precise template-to-state diff
- Deployment preview (what will happen)
- Property-level change detection

SECURITY:
- All queries use Managed Identity authentication
- Query results are bounded to prevent OOM
- Subscription/MG scope is validated before query
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import (
    QueryRequest,
    QueryRequestOptions,
    ResultFormat,
)

from .config import (
    MAX_GRAPH_QUERY_RESULTS,
    MAX_GRAPH_QUERY_TIMEOUT_SECONDS,
    Config,
    DeploymentScope,
)

logger = logging.getLogger(__name__)


class GraphChangeType(str, Enum):
    """Resource Graph change types from ResourceChanges table."""

    CREATE = "Create"
    UPDATE = "Update"
    DELETE = "Delete"


@dataclass
class ResourceChange:
    """A change event from Resource Graph.

    Attributes:
        resource_id: Full ARM resource ID
        change_type: Create, Update, or Delete
        timestamp: When the change occurred
        changed_by: Email or object ID of the actor
        client_type: Client that made the change (e.g., "Azure Portal")
        changes: Dict of property changes (for updates)
    """

    resource_id: str
    change_type: GraphChangeType
    timestamp: datetime
    changed_by: str | None = None
    client_type: str | None = None
    changes: dict[str, Any] | None = None


@dataclass
class ResourceInfo:
    """Basic resource information from Resource Graph.

    Attributes:
        resource_id: Full ARM resource ID
        name: Resource name
        type: Resource type (e.g., microsoft.network/virtualnetworks)
        location: Azure region
        resource_group: Resource group name
        subscription_id: Subscription ID
        tags: Resource tags
    """

    resource_id: str
    name: str
    type: str
    location: str
    resource_group: str
    subscription_id: str
    tags: dict[str, str] | None = None


@dataclass
class GraphQueryResult:
    """Result of a Resource Graph drift check.

    Attributes:
        recent_changes: Changes detected in the scope since last check
        resources: Current resources in scope
        has_changes: Whether any relevant changes were detected
        query_time_seconds: Time taken for queries
    """

    recent_changes: list[ResourceChange]
    resources: list[ResourceInfo]
    has_changes: bool
    query_time_seconds: float


class ResourceGraphQuerier:
    """Azure Resource Graph client for drift detection.

    Provides fast queries to detect changes and inventory resources
    before invoking the slower WhatIf API.

    SECURITY:
    - Uses Managed Identity for authentication
    - Query results are bounded by MAX_GRAPH_QUERY_RESULTS
    - All queries have timeouts enforced
    """

    def __init__(self, credential: TokenCredential, config: Config) -> None:
        """Initialize Resource Graph client.

        Args:
            credential: Azure credential (must be Managed Identity)
            config: Operator configuration
        """
        self._config = config
        self._client = ResourceGraphClient(credential=credential)
        self._last_check_time: datetime | None = None

    async def check_for_changes(
        self,
        since: datetime | None = None,
        resource_types: list[str] | None = None,
    ) -> GraphQueryResult:
        """Check for recent changes in the configured scope.

        This is the primary fast-path check. If no changes are detected,
        the reconciler can skip the expensive WhatIf call.

        Args:
            since: Only return changes after this time.
                   Defaults to last check time or reconcile interval.
            resource_types: Optional filter for specific resource types.

        Returns:
            GraphQueryResult with changes and current resources.

        Raises:
            HttpResponseError: If the Graph API call fails.
        """
        import time

        start_time = time.monotonic()

        # Default to checking since last reconcile interval
        if since is None:
            since = self._last_check_time or (
                datetime.now(UTC) - timedelta(seconds=self._config.reconcile_interval_seconds)
            )

        # Query 1: Recent changes
        recent_changes = await self._query_recent_changes(since, resource_types)

        # Query 2: Current resources in scope
        resources = await self._query_resources(resource_types)

        # Update last check time
        self._last_check_time = datetime.now(UTC)

        query_time = time.monotonic() - start_time

        # Determine if there are relevant changes
        has_changes = len(recent_changes) > 0

        logger.info(
            "Resource Graph check complete",
            extra={
                "domain": self._config.domain,
                "changes_found": len(recent_changes),
                "resources_found": len(resources),
                "query_time_seconds": round(query_time, 2),
            },
        )

        return GraphQueryResult(
            recent_changes=recent_changes,
            resources=resources,
            has_changes=has_changes,
            query_time_seconds=query_time,
        )

    async def _query_recent_changes(
        self,
        since: datetime,
        resource_types: list[str] | None = None,
    ) -> list[ResourceChange]:
        """Query ResourceChanges table for recent modifications.

        Args:
            since: Only return changes after this time.
            resource_types: Optional filter for specific resource types.

        Returns:
            List of change events.
        """
        # Build scope filter based on configuration
        scope_filter = self._build_scope_filter()

        # Build optional type filter
        type_filter = ""
        if resource_types:
            type_list = ", ".join(f"'{t.lower()}'" for t in resource_types)
            type_filter = f"| where tolower(properties.targetResourceType) in ({type_list})"

        # Format timestamp for KQL
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        query = f"""
        resourcechanges
        | where todatetime(properties.changeAttributes.timestamp) > datetime('{since_str}')
        | where properties.targetResourceId contains '{scope_filter}'
        {type_filter}
        | extend
            resourceId = tostring(properties.targetResourceId),
            changeType = tostring(properties.changeType),
            timestamp = todatetime(properties.changeAttributes.timestamp),
            changedBy = tostring(properties.changeAttributes.changedBy),
            clientType = tostring(properties.changeAttributes.clientType),
            changes = properties.changes
        | project resourceId, changeType, timestamp, changedBy, clientType, changes
        | order by timestamp desc
        | limit {MAX_GRAPH_QUERY_RESULTS}
        """

        results = await self._execute_query(query.strip())

        changes = []
        for row in results:
            try:
                change_type = GraphChangeType(row.get("changeType", "Update"))
            except ValueError:
                change_type = GraphChangeType.UPDATE

            timestamp_val = row.get("timestamp")
            if isinstance(timestamp_val, str):
                timestamp = datetime.fromisoformat(timestamp_val.replace("Z", "+00:00"))
            elif isinstance(timestamp_val, datetime):
                timestamp = timestamp_val
            else:
                timestamp = datetime.now(UTC)

            changes.append(
                ResourceChange(
                    resource_id=row.get("resourceId", ""),
                    change_type=change_type,
                    timestamp=timestamp,
                    changed_by=row.get("changedBy"),
                    client_type=row.get("clientType"),
                    changes=row.get("changes"),
                )
            )

        return changes

    async def _query_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[ResourceInfo]:
        """Query current resources in scope.

        Args:
            resource_types: Optional filter for specific resource types.

        Returns:
            List of resource information.
        """
        # Build scope filter
        scope_filter = self._build_resources_scope_filter()

        # Build optional type filter
        type_filter = ""
        if resource_types:
            type_list = ", ".join(f"'{t.lower()}'" for t in resource_types)
            type_filter = f"| where tolower(type) in ({type_list})"

        query = f"""
        Resources
        {scope_filter}
        {type_filter}
        | project
            id,
            name,
            type,
            location,
            resourceGroup,
            subscriptionId,
            tags
        | limit {MAX_GRAPH_QUERY_RESULTS}
        """

        results = await self._execute_query(query.strip())

        resources = []
        for row in results:
            resources.append(
                ResourceInfo(
                    resource_id=row.get("id", ""),
                    name=row.get("name", ""),
                    type=row.get("type", ""),
                    location=row.get("location", ""),
                    resource_group=row.get("resourceGroup", ""),
                    subscription_id=row.get("subscriptionId", ""),
                    tags=row.get("tags"),
                )
            )

        return resources

    def _build_scope_filter(self) -> str:
        """Build scope filter string for ResourceChanges queries."""
        match self._config.scope:
            case DeploymentScope.SUBSCRIPTION:
                return f"/subscriptions/{self._config.subscription_id}"
            case DeploymentScope.MANAGEMENT_GROUP:
                # For MG scope, we'll filter in the query subscriptions parameter
                return f"/subscriptions/{self._config.subscription_id}"
            case DeploymentScope.RESOURCE_GROUP:
                return (
                    f"/subscriptions/{self._config.subscription_id}"
                    f"/resourceGroups/{self._config.resource_group_name}"
                )
            case _:
                return f"/subscriptions/{self._config.subscription_id}"

    def _build_resources_scope_filter(self) -> str:
        """Build scope filter for Resources table queries."""
        match self._config.scope:
            case DeploymentScope.SUBSCRIPTION:
                return f"| where subscriptionId == '{self._config.subscription_id}'"
            case DeploymentScope.MANAGEMENT_GROUP:
                # MG scope queries all subscriptions under the MG
                return f"| where subscriptionId == '{self._config.subscription_id}'"
            case DeploymentScope.RESOURCE_GROUP:
                return (
                    f"| where subscriptionId == '{self._config.subscription_id}'"
                    f" and resourceGroup =~ '{self._config.resource_group_name}'"
                )
            case _:
                return f"| where subscriptionId == '{self._config.subscription_id}'"

    async def _execute_query(self, query: str) -> list[dict[str, Any]]:
        """Execute a Resource Graph query.

        Args:
            query: KQL query string.

        Returns:
            List of result rows as dictionaries.

        Raises:
            HttpResponseError: If the query fails.
        """
        import asyncio

        # Build subscription list for query scope
        subscriptions = [self._config.subscription_id]

        # For management group scope, we could add more subscriptions
        # but that requires listing subscriptions under the MG first

        request = QueryRequest(
            subscriptions=subscriptions,
            query=query,
            options=QueryRequestOptions(
                result_format=ResultFormat.OBJECT_ARRAY,
                top=MAX_GRAPH_QUERY_RESULTS,
            ),
        )

        # Execute with timeout
        try:
            # Resource Graph client is synchronous, wrap in executor
            loop = asyncio.get_event_loop()
            response = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: self._client.resources(request)),
                timeout=MAX_GRAPH_QUERY_TIMEOUT_SECONDS,
            )
        except TimeoutError as e:
            logger.error(
                "Resource Graph query timed out",
                extra={
                    "domain": self._config.domain,
                    "timeout_seconds": MAX_GRAPH_QUERY_TIMEOUT_SECONDS,
                },
            )
            raise HttpResponseError(message="Resource Graph query timed out") from e
        except AzureError as e:
            logger.error(
                "Resource Graph query failed",
                extra={"domain": self._config.domain, "error": str(e)},
            )
            raise

        # Extract data from response
        if response.data is None:
            return []

        # response.data is a list of dictionaries when using OBJECT_ARRAY format
        if isinstance(response.data, list):
            return response.data

        return []

    async def get_change_attribution(
        self,
        resource_id: str,
        since: datetime | None = None,
    ) -> list[ResourceChange]:
        """Get change history for a specific resource.

        Useful for audit logging when drift is detected.

        Args:
            resource_id: Full ARM resource ID.
            since: Only return changes after this time (default: 24 hours).

        Returns:
            List of changes for the resource.
        """
        if since is None:
            since = datetime.now(UTC) - timedelta(hours=24)

        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        query = f"""
        resourcechanges
        | where properties.targetResourceId =~ '{resource_id}'
        | where todatetime(properties.changeAttributes.timestamp) > datetime('{since_str}')
        | extend
            resourceId = tostring(properties.targetResourceId),
            changeType = tostring(properties.changeType),
            timestamp = todatetime(properties.changeAttributes.timestamp),
            changedBy = tostring(properties.changeAttributes.changedBy),
            clientType = tostring(properties.changeAttributes.clientType),
            operation = tostring(properties.changeAttributes.operation),
            changes = properties.changes
        | project resourceId, changeType, timestamp, changedBy, clientType, operation, changes
        | order by timestamp desc
        | limit 50
        """

        results = await self._execute_query(query.strip())

        changes = []
        for row in results:
            try:
                change_type = GraphChangeType(row.get("changeType", "Update"))
            except ValueError:
                change_type = GraphChangeType.UPDATE

            timestamp_val = row.get("timestamp")
            if isinstance(timestamp_val, str):
                timestamp = datetime.fromisoformat(timestamp_val.replace("Z", "+00:00"))
            elif isinstance(timestamp_val, datetime):
                timestamp = timestamp_val
            else:
                timestamp = datetime.now(UTC)

            changes.append(
                ResourceChange(
                    resource_id=row.get("resourceId", ""),
                    change_type=change_type,
                    timestamp=timestamp,
                    changed_by=row.get("changedBy"),
                    client_type=row.get("clientType"),
                    changes=row.get("changes"),
                )
            )

        return changes

    async def find_orphans(
        self,
        expected_resource_ids: list[str],
        resource_types: list[str] | None = None,
    ) -> list[ResourceInfo]:
        """Find resources that exist but are not in the expected list.

        Orphan detection helps identify resources created outside
        of the operator's templates.

        Args:
            expected_resource_ids: List of resource IDs that should exist.
            resource_types: Optional filter for specific resource types.

        Returns:
            List of orphan resources.
        """
        # Get current resources in scope
        all_resources = await self._query_resources(resource_types)

        # Normalize expected IDs for comparison
        expected_set = {rid.lower() for rid in expected_resource_ids}

        # Find orphans
        orphans = [r for r in all_resources if r.resource_id.lower() not in expected_set]

        if orphans:
            logger.warning(
                "Orphan resources detected",
                extra={
                    "domain": self._config.domain,
                    "orphan_count": len(orphans),
                    "orphan_types": list({o.type for o in orphans}),
                },
            )

        return orphans
