"""Operator dependency ordering and validation.

This module implements dependency management for multi-operator scenarios:
1. Dependency graph construction from spec declarations
2. Topological sorting for execution order
3. Cycle detection to prevent deadlocks
4. Ready state checking via Azure Resource Graph

DESIGN PHILOSOPHY:
- Operators declare dependencies via `depends_on` in their spec
- Dependencies are domain names (e.g., "log-analytics", "hub-network")
- The orchestrator (bootstrap or external) uses this to order deployments
- Individual operators can block if dependencies are not satisfied

EXAMPLE SPEC:
```yaml
# firewall.yaml
domain: firewall
depends_on:
  - hub-network    # Firewall needs VNet first
  - log-analytics  # Firewall needs LAW for diagnostics
```
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from azure.identity import ManagedIdentityCredential

logger = logging.getLogger(__name__)

# Maximum size of the satisfied cache to prevent unbounded growth
MAX_SATISFIED_CACHE_SIZE = 100


class DependencyStatus(str, Enum):
    """Status of a dependency check."""

    SATISFIED = "satisfied"  # Dependency exists and is healthy
    PENDING = "pending"  # Dependency not yet deployed
    FAILED = "failed"  # Dependency exists but in failed state
    UNKNOWN = "unknown"  # Cannot determine status


class DependencyError(Exception):
    """Raised when dependency validation fails."""

    pass


class CyclicDependencyError(DependencyError):
    """Raised when a dependency cycle is detected."""

    pass


class UnsatisfiedDependencyError(DependencyError):
    """Raised when a required dependency is not satisfied."""

    pass


# Known operator domains with their typical dependencies
# This serves as documentation and can be used for validation
KNOWN_DEPENDENCIES: dict[str, list[str]] = {
    # Management plane - foundational
    "management-group": [],  # Root - no dependencies
    "log-analytics": [],  # Often first - central logging
    # Identity - depends on management
    "role": ["management-group"],
    "bootstrap": [],  # Special - creates identities
    # Security - depends on logging
    "defender": ["log-analytics"],
    "sentinel": ["log-analytics"],
    "keyvault": ["log-analytics"],
    # Connectivity - depends on management
    "hub-network": ["log-analytics"],
    "hub-network-secondary": ["hub-network", "log-analytics"],
    # Security appliances - depend on network
    "firewall": ["hub-network", "log-analytics"],
    "firewall-secondary": ["hub-network-secondary", "firewall", "log-analytics"],
    # Connectivity services - depend on network
    "bastion": ["hub-network", "log-analytics"],
    "bastion-secondary": ["hub-network-secondary", "log-analytics"],
    "dns": ["hub-network"],
    "vpn-gateway": ["hub-network", "log-analytics"],
    "vpn-gateway-secondary": ["hub-network-secondary", "log-analytics"],
    "expressroute": ["hub-network", "log-analytics"],
    # VWAN variants
    "vwan-hub": ["log-analytics"],
    "vwan-hub-secondary": ["vwan-hub", "log-analytics"],
    # Policy - depends on management groups
    "policy": ["management-group"],
    # Monitoring - depends on logging
    "monitor": ["log-analytics"],
    "automation": ["log-analytics"],
}

# Domain to Resource Graph query patterns
# Maps domain names to (resource_type, optional_name_pattern) for verification
# SECURITY: These patterns are used to verify that dependency resources exist
DOMAIN_RESOURCE_PATTERNS: dict[str, tuple[str, str | None]] = {
    "log-analytics": ("microsoft.operationalinsights/workspaces", None),
    "hub-network": ("microsoft.network/virtualnetworks", "hub"),
    "hub-network-secondary": ("microsoft.network/virtualnetworks", "hub"),
    "firewall": ("microsoft.network/azurefirewalls", None),
    "firewall-secondary": ("microsoft.network/azurefirewalls", None),
    "bastion": ("microsoft.network/bastionhosts", None),
    "bastion-secondary": ("microsoft.network/bastionhosts", None),
    "vpn-gateway": ("microsoft.network/virtualnetworkgateways", "vpn"),
    "vpn-gateway-secondary": ("microsoft.network/virtualnetworkgateways", "vpn"),
    "expressroute": ("microsoft.network/expressroutecircuits", None),
    "dns": ("microsoft.network/privatednszones", None),
    "defender": ("microsoft.security/pricings", None),
    "sentinel": ("microsoft.securityinsights/alertrules", None),
    "keyvault": ("microsoft.keyvault/vaults", None),
    "vwan-hub": ("microsoft.network/virtualhubs", None),
    "vwan-hub-secondary": ("microsoft.network/virtualhubs", None),
    "automation": ("microsoft.automation/automationaccounts", None),
    "monitor": ("microsoft.insights/datacollectionrules", None),
    "management-group": ("microsoft.management/managementgroups", None),
    "policy": ("microsoft.authorization/policyassignments", None),
}

# Default timeout for dependency wait
DEFAULT_DEPENDENCY_TIMEOUT_SECONDS = 300
MAX_DEPENDENCY_TIMEOUT_SECONDS = 3600


@dataclass
class DependencyNode:
    """A node in the dependency graph."""

    domain: str
    depends_on: list[str] = field(default_factory=list)
    status: DependencyStatus = DependencyStatus.UNKNOWN
    last_checked: datetime | None = None

@dataclass
class DependencyGraph:
    """Directed acyclic graph of operator dependencies."""

    nodes: dict[str, DependencyNode] = field(default_factory=dict)

    def add_node(self, domain: str, depends_on: list[str] | None = None) -> None:
        """Add a node to the dependency graph.

        Args:
            domain: Operator domain name.
            depends_on: List of domain names this operator depends on.
        """
        if domain in self.nodes:
            # Update existing node
            if depends_on:
                self.nodes[domain].depends_on = depends_on
        else:
            self.nodes[domain] = DependencyNode(
                domain=domain,
                depends_on=depends_on or [],
            )

        # Ensure all dependencies have nodes (even if not yet defined)
        for dep in depends_on or []:
            if dep not in self.nodes:
                self.nodes[dep] = DependencyNode(domain=dep)

    def validate(self) -> None:
        """Validate the dependency graph for cycles.

        Raises:
            CyclicDependencyError: If a cycle is detected.
        """
        # Kahn's algorithm for topological sort / cycle detection
        in_degree: dict[str, int] = {node: 0 for node in self.nodes}
        for node in self.nodes.values():
            for dep in node.depends_on:
                if dep in in_degree:
                    in_degree[dep] += 1

        # Queue nodes with no incoming edges
        queue = [node for node, degree in in_degree.items() if degree == 0]
        processed = 0

        while queue:
            current = queue.pop(0)
            processed += 1

            for dep in self.nodes[current].depends_on:
                if dep in in_degree:
                    in_degree[dep] -= 1
                    if in_degree[dep] == 0:
                        queue.append(dep)

        if processed != len(self.nodes):
            # Cycle detected - find the nodes in the cycle
            cycle_nodes = [node for node, degree in in_degree.items() if degree > 0]
            raise CyclicDependencyError(
                f"Circular dependency detected involving: {cycle_nodes}"
            )

    def topological_sort(self) -> list[str]:
        """Return domains in dependency order (dependencies first).

        Returns:
            List of domain names in execution order.

        Raises:
            CyclicDependencyError: If a cycle is detected.
        """
        self.validate()

        # Build adjacency list (reversed - edges point to dependents)
        dependents: dict[str, list[str]] = {node: [] for node in self.nodes}
        in_degree: dict[str, int] = {node: 0 for node in self.nodes}

        for node in self.nodes.values():
            for dep in node.depends_on:
                if dep in dependents:
                    dependents[dep].append(node.domain)
                    in_degree[node.domain] += 1

        # Kahn's algorithm
        result: list[str] = []
        queue = [node for node, degree in in_degree.items() if degree == 0]

        while queue:
            # Sort for deterministic ordering among nodes with same in_degree
            queue.sort()
            current = queue.pop(0)
            result.append(current)

            for dependent in dependents[current]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        return result

    def get_ready_domains(self, satisfied: set[str]) -> list[str]:
        """Get domains that are ready to deploy (all deps satisfied).

        Args:
            satisfied: Set of domain names already deployed/satisfied.

        Returns:
            List of domain names that can be deployed now.
        """
        ready = []
        for node in self.nodes.values():
            if node.domain in satisfied:
                continue

            # Check if all dependencies are satisfied
            deps_met = all(dep in satisfied for dep in node.depends_on)
            if deps_met:
                ready.append(node.domain)

        return sorted(ready)


@dataclass(frozen=True)
class DependencyConfig:
    """Configuration for dependency checking."""

    # Enable dependency enforcement
    enforce_dependencies: bool = True

    # Wait for dependencies before proceeding (vs fail immediately)
    wait_for_dependencies: bool = True

    # Timeout for waiting on dependencies
    dependency_timeout_seconds: int = DEFAULT_DEPENDENCY_TIMEOUT_SECONDS

    # Use Azure Resource Graph to verify dependency resources exist
    verify_via_resource_graph: bool = True

    @classmethod
    def from_env(cls) -> DependencyConfig:
        """Load configuration from environment.

        Environment Variables:
            ENFORCE_DEPENDENCIES: Enable dependency enforcement (default: true)
            WAIT_FOR_DEPENDENCIES: Wait vs fail for unmet deps (default: true)
            DEPENDENCY_TIMEOUT_SECONDS: Wait timeout (default: 300)
            VERIFY_DEPENDENCIES_VIA_GRAPH: Use Resource Graph (default: true)
        """

        def get_bool(key: str, default: bool) -> bool:
            value = os.environ.get(key, "").lower()
            if not value:
                return default
            return value in ("true", "1", "yes")

        def get_int(key: str, default: int) -> int:
            value = os.environ.get(key)
            if value is None:
                return default
            try:
                return min(int(value), MAX_DEPENDENCY_TIMEOUT_SECONDS)
            except ValueError:
                return default

        return cls(
            enforce_dependencies=get_bool("ENFORCE_DEPENDENCIES", True),
            wait_for_dependencies=get_bool("WAIT_FOR_DEPENDENCIES", True),
            dependency_timeout_seconds=get_int(
                "DEPENDENCY_TIMEOUT_SECONDS", DEFAULT_DEPENDENCY_TIMEOUT_SECONDS
            ),
            verify_via_resource_graph=get_bool("VERIFY_DEPENDENCIES_VIA_GRAPH", True),
        )


class DependencyChecker:
    """Checks if operator dependencies are satisfied.

    Uses Azure Resource Graph to verify that dependent resources exist
    before allowing an operator to proceed with deployment.

    SECURITY:
    - Real verification via Resource Graph queries
    - Bounded cache with LRU eviction
    - Fail-closed when verification cannot be performed
    """

    def __init__(
        self,
        config: DependencyConfig | None = None,
        credential: "ManagedIdentityCredential | None" = None,
        subscription_id: str | None = None,
    ) -> None:
        """Initialize dependency checker.

        Args:
            config: Dependency configuration.
            credential: Azure credential for Resource Graph queries.
            subscription_id: Default subscription for queries.
        """
        self._config = config or DependencyConfig.from_env()
        self._credential = credential
        self._subscription_id = subscription_id

        # Cache of known-satisfied dependencies with bounded size
        # Format: {domain: (timestamp, status)}
        self._satisfied_cache: dict[str, datetime] = {}

        # Resource Graph client (lazy initialized)
        self._graph_client: Any | None = None

    def _get_graph_client(self) -> Any:
        """Get or create Resource Graph client.

        Returns:
            ResourceGraphClient instance.

        Raises:
            DependencyError: If no credential is available.
        """
        if self._graph_client is not None:
            return self._graph_client

        if self._credential is None:
            raise DependencyError(
                "No credential available for dependency verification. "
                "Either provide a credential or set VERIFY_DEPENDENCIES_VIA_GRAPH=false."
            )

        from azure.mgmt.resourcegraph import ResourceGraphClient

        self._graph_client = ResourceGraphClient(credential=self._credential)
        return self._graph_client

    def _evict_cache_if_needed(self) -> None:
        """Evict oldest entries if cache exceeds maximum size."""
        if len(self._satisfied_cache) >= MAX_SATISFIED_CACHE_SIZE:
            # Remove oldest 20% of entries
            sorted_entries = sorted(self._satisfied_cache.items(), key=lambda x: x[1])
            to_remove = len(sorted_entries) // 5 or 1
            for domain, _ in sorted_entries[:to_remove]:
                del self._satisfied_cache[domain]
            logger.debug(
                "Evicted dependency cache entries",
                extra={"evicted_count": to_remove, "remaining": len(self._satisfied_cache)},
            )

    def check_dependencies(
        self,
        domain: str,
        depends_on: list[str],
        subscription_id: str | None = None,
        management_group_id: str | None = None,
    ) -> tuple[bool, list[str]]:
        """Check if all dependencies for a domain are satisfied.

        Args:
            domain: The domain being checked.
            depends_on: List of domain names that must be satisfied.
            subscription_id: Optional subscription scope.
            management_group_id: Optional management group scope.

        Returns:
            Tuple of (all_satisfied, unsatisfied_list).
        """
        if not self._config.enforce_dependencies:
            logger.debug(
                "Dependency enforcement disabled",
                extra={"domain": domain},
            )
            return True, []

        if not depends_on:
            logger.debug(
                "No dependencies declared",
                extra={"domain": domain},
            )
            return True, []

        unsatisfied: list[str] = []

        for dep in depends_on:
            # Check cache first
            if dep in self._satisfied_cache:
                logger.debug(
                    "Dependency satisfied (cached)",
                    extra={"domain": domain, "dependency": dep},
                )
                continue

            # Check if dependency is satisfied
            status = self._check_single_dependency(
                dep, subscription_id, management_group_id
            )

            if status == DependencyStatus.SATISFIED:
                self._satisfied_cache[dep] = datetime.now(UTC)
                logger.info(
                    "Dependency satisfied",
                    extra={"domain": domain, "dependency": dep},
                )
            else:
                unsatisfied.append(dep)
                logger.warning(
                    "Dependency not satisfied",
                    extra={
                        "domain": domain,
                        "dependency": dep,
                        "status": status.value,
                    },
                )

        # Evict cache if needed before adding new entries
        self._evict_cache_if_needed()

        return len(unsatisfied) == 0, unsatisfied

    def _check_single_dependency(
        self,
        dependency_domain: str,
        subscription_id: str | None,
        management_group_id: str | None,
    ) -> DependencyStatus:
        """Check a single dependency using Resource Graph.

        Queries Azure Resource Graph to verify that resources of the expected
        type exist in the subscription scope.

        SECURITY: Fail-closed - returns PENDING (not SATISFIED) when
        verification cannot be performed, blocking deployment until
        dependencies are confirmed.

        Args:
            dependency_domain: Domain name of the dependency.
            subscription_id: Subscription scope.
            management_group_id: Management group scope.

        Returns:
            Status of the dependency.
        """
        # If Resource Graph verification is disabled, assume satisfied
        # This allows operators to run without full verification in dev/test
        if not self._config.verify_via_resource_graph:
            logger.debug(
                "Resource Graph verification disabled, assuming satisfied",
                extra={"dependency": dependency_domain},
            )
            return DependencyStatus.SATISFIED

        # Look up resource pattern for this domain
        pattern = DOMAIN_RESOURCE_PATTERNS.get(dependency_domain)
        if pattern is None:
            # Unknown domain - check if it's in the cache (marked by another operator)
            if dependency_domain in self._satisfied_cache:
                return DependencyStatus.SATISFIED
            logger.warning(
                "Unknown dependency domain with no resource pattern",
                extra={"dependency": dependency_domain},
            )
            # SECURITY: Fail-closed for unknown domains
            return DependencyStatus.PENDING

        resource_type, name_pattern = pattern

        # Build subscription list for query
        sub_id = subscription_id or self._subscription_id
        if sub_id is None:
            logger.error(
                "No subscription ID available for dependency verification",
                extra={"dependency": dependency_domain},
            )
            # SECURITY: Fail-closed when we can't verify
            return DependencyStatus.PENDING

        try:
            # Query Resource Graph for resources of this type
            count = self._query_resource_count(
                subscription_id=sub_id,
                resource_type=resource_type,
                name_pattern=name_pattern,
            )

            if count > 0:
                logger.info(
                    "Dependency verified via Resource Graph",
                    extra={
                        "dependency": dependency_domain,
                        "resource_type": resource_type,
                        "count": count,
                    },
                )
                return DependencyStatus.SATISFIED
            else:
                logger.info(
                    "Dependency not found via Resource Graph",
                    extra={
                        "dependency": dependency_domain,
                        "resource_type": resource_type,
                    },
                )
                return DependencyStatus.PENDING

        except Exception as e:
            logger.error(
                "Resource Graph query failed for dependency check",
                extra={
                    "dependency": dependency_domain,
                    "error": str(e),
                    "error_type": type(e).__name__,
                },
            )
            # SECURITY: Fail-closed on query errors
            return DependencyStatus.PENDING

    def _query_resource_count(
        self,
        subscription_id: str,
        resource_type: str,
        name_pattern: str | None = None,
    ) -> int:
        """Query Resource Graph for count of resources matching criteria.

        Args:
            subscription_id: Subscription to query.
            resource_type: Resource type to search for.
            name_pattern: Optional name pattern (contains match).

        Returns:
            Count of matching resources.
        """
        from azure.mgmt.resourcegraph.models import (
            QueryRequest,
            QueryRequestOptions,
            ResultFormat,
        )

        client = self._get_graph_client()

        # Build KQL query
        name_filter = ""
        if name_pattern:
            name_filter = f"| where name contains '{name_pattern}'"

        query = f"""
        Resources
        | where subscriptionId == '{subscription_id}'
        | where tolower(type) == '{resource_type.lower()}'
        {name_filter}
        | count
        """

        request = QueryRequest(
            subscriptions=[subscription_id],
            query=query.strip(),
            options=QueryRequestOptions(
                result_format=ResultFormat.OBJECT_ARRAY,
            ),
        )

        response = client.resources(request)

        # Extract count from response
        if response.data and len(response.data) > 0:
            count_row = response.data[0]
            # Response format: {"count_": N} or {"Count": N}
            return count_row.get("count_", count_row.get("Count", 0))

        return 0

    def mark_satisfied(self, domain: str) -> None:
        """Mark a domain as satisfied (deployed successfully).

        Args:
            domain: Domain that completed successfully.
        """
        self._evict_cache_if_needed()
        self._satisfied_cache[domain] = datetime.now(UTC)
        logger.info(
            "Domain marked as satisfied",
            extra={"domain": domain},
        )

    def clear_cache(self) -> None:
        """Clear the satisfied cache."""
        self._satisfied_cache.clear()


def get_suggested_dependencies(domain: str) -> list[str]:
    """Get suggested dependencies for a domain.

    This returns the recommended dependencies based on ALZ best practices.
    Users can override in their spec files.

    Args:
        domain: Operator domain name.

    Returns:
        List of suggested dependency domain names.
    """
    return KNOWN_DEPENDENCIES.get(domain, [])


def validate_dependency_declaration(
    domain: str, depends_on: list[str]
) -> list[str]:
    """Validate that declared dependencies make sense.

    Returns warnings for unusual dependency declarations.

    Args:
        domain: Operator domain.
        depends_on: Declared dependencies.

    Returns:
        List of warning messages.
    """
    warnings: list[str] = []

    # Check for self-dependency
    if domain in depends_on:
        warnings.append(f"Domain '{domain}' cannot depend on itself")

    # Check for unknown dependencies
    known_domains = set(KNOWN_DEPENDENCIES.keys())
    for dep in depends_on:
        if dep not in known_domains:
            warnings.append(
                f"Unknown dependency '{dep}' - ensure this domain exists"
            )

    # Suggest missing common dependencies
    suggested = set(get_suggested_dependencies(domain))
    missing_suggested = suggested - set(depends_on)
    if missing_suggested:
        warnings.append(
            f"Consider adding dependencies: {sorted(missing_suggested)}"
        )

    return warnings
