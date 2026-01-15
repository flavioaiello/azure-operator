"""Deployment Stacks protection layer.

This module provides post-deployment protection via Azure Deployment Stacks.
After a successful ARM deployment, the operator wraps resources in a Stack
with deny settings to block out-of-band portal/CLI changes.

KEY DESIGN DECISIONS:
1. Stack per Spec: Each spec creates its own Stack (independent lifecycle)
2. Default enabled for Sub/RG scope: Where deny settings work
3. Default disabled for MG scope: Deny not supported at Management Group
4. Operator identity excluded: So subsequent deployments succeed
5. WhatIf still runs first: Stack deny is AFTER deployment, not instead of

FLOW:
1. WhatIf preview (unchanged)
2. Approval gate if needed (unchanged)
3. ARM deployment applies changes (unchanged)
4. Stack wraps deployed resources with deny settings (NEW)

LIMITATIONS:
- Management Group scope: deny assignments NOT supported
- Key Vault secrets: cannot be deleted via Stack
- Microsoft Graph resources: not supported
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class DenySettingsMode(str, Enum):
    """Deployment Stack deny settings mode.

    Controls what operations are blocked on stack-managed resources.
    """

    NONE = "none"  # No deny (defeats purpose, but available for testing)
    DENY_DELETE = "denyDelete"  # Block deletions only
    DENY_WRITE_AND_DELETE = "denyWriteAndDelete"  # Block modifications and deletions


class ActionOnUnmanage(str, Enum):
    """Action when a resource is removed from the Stack.

    Controls what happens to resources that were in the Stack template
    but are removed in an update.
    """

    DELETE = "delete"  # Delete the resource (dangerous)
    DETACH = "detach"  # Remove from Stack but keep resource (safer)


class DeploymentScope(str, Enum):
    """Deployment scope for Stacks."""

    RESOURCE_GROUP = "resourceGroup"
    SUBSCRIPTION = "subscription"
    MANAGEMENT_GROUP = "managementGroup"


# Domains that deploy to MG scope - deny NOT supported
MG_SCOPE_DOMAINS: frozenset[str] = frozenset({
    "management-group",
    "bootstrap",
    # Role assignments CAN be at sub scope, handled separately
})

# Domains where Stack deny is high-value (connectivity/security)
HIGH_VALUE_DENY_DOMAINS: frozenset[str] = frozenset({
    "hub-network",
    "firewall",
    "vpn-gateway",
    "vwan",
    "bastion",
    "dns",
})

# Domains where Stack deny is optional (monitoring/management)
OPTIONAL_DENY_DOMAINS: frozenset[str] = frozenset({
    "log-analytics",
    "sentinel",
    "monitor",
    "automation",
    "defender",
    "role",  # depends on scope
})

# Maximum length for stack names
MAX_STACK_NAME_LENGTH = 64

# Default deny mode for production
DEFAULT_DENY_MODE = DenySettingsMode.DENY_WRITE_AND_DELETE

# Default action when resources are removed from template
DEFAULT_ACTION_ON_UNMANAGE = ActionOnUnmanage.DETACH


@dataclass(frozen=True)
class StackProtectionConfig:
    """Configuration for Deployment Stack protection.

    Immutable after creation for thread safety.
    """

    enabled: bool = True
    deny_mode: DenySettingsMode = DEFAULT_DENY_MODE
    action_on_unmanage_resources: ActionOnUnmanage = DEFAULT_ACTION_ON_UNMANAGE
    action_on_unmanage_resource_groups: ActionOnUnmanage = ActionOnUnmanage.DETACH
    excluded_actions: tuple[str, ...] = ()  # Actions allowed despite deny
    apply_to_child_scopes: bool = True  # Deny applies to child resources

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> StackProtectionConfig:
        """Create config from dictionary (spec file).

        Args:
            data: Dictionary from spec's stackProtection field.

        Returns:
            StackProtectionConfig instance.
        """
        if data is None:
            return cls()

        return cls(
            enabled=data.get("enabled", True),
            deny_mode=DenySettingsMode(data.get("denyMode", DEFAULT_DENY_MODE.value)),
            action_on_unmanage_resources=ActionOnUnmanage(
                data.get("actionOnUnmanageResources", DEFAULT_ACTION_ON_UNMANAGE.value)
            ),
            action_on_unmanage_resource_groups=ActionOnUnmanage(
                data.get("actionOnUnmanageResourceGroups", ActionOnUnmanage.DETACH.value)
            ),
            excluded_actions=tuple(data.get("excludedActions", [])),
            apply_to_child_scopes=data.get("applyToChildScopes", True),
        )

    @classmethod
    def from_env(cls) -> StackProtectionConfig:
        """Create config from environment variables.

        Environment variables:
            STACK_PROTECTION_ENABLED: Enable stack protection (default: true)
            STACK_DENY_MODE: none, denyDelete, denyWriteAndDelete
            STACK_ACTION_ON_UNMANAGE: delete, detach
        """
        enabled_str = os.environ.get("STACK_PROTECTION_ENABLED", "true").lower()
        enabled = enabled_str in ("true", "1", "yes")

        deny_mode_str = os.environ.get("STACK_DENY_MODE", DEFAULT_DENY_MODE.value)
        try:
            deny_mode = DenySettingsMode(deny_mode_str)
        except ValueError:
            logger.warning(
                "Invalid STACK_DENY_MODE '%s', using default '%s'",
                deny_mode_str,
                DEFAULT_DENY_MODE.value,
            )
            deny_mode = DEFAULT_DENY_MODE

        action_str = os.environ.get("STACK_ACTION_ON_UNMANAGE", DEFAULT_ACTION_ON_UNMANAGE.value)
        try:
            action = ActionOnUnmanage(action_str)
        except ValueError:
            logger.warning(
                "Invalid STACK_ACTION_ON_UNMANAGE '%s', using default '%s'",
                action_str,
                DEFAULT_ACTION_ON_UNMANAGE.value,
            )
            action = DEFAULT_ACTION_ON_UNMANAGE

        return cls(
            enabled=enabled,
            deny_mode=deny_mode,
            action_on_unmanage_resources=action,
        )

    def to_deny_settings(self, excluded_principals: list[str]) -> dict[str, Any]:
        """Convert to Azure Deployment Stack deny settings format.

        Args:
            excluded_principals: Principal IDs that can bypass deny
                                (should include operator's managed identity).

        Returns:
            Dictionary matching Azure API denySettings schema.
        """
        return {
            "mode": self.deny_mode.value,
            "excludedPrincipals": excluded_principals,
            "excludedActions": list(self.excluded_actions),
            "applyToChildScopes": self.apply_to_child_scopes,
        }


@dataclass
class StackMetadata:
    """Metadata stamped on Stack for auditability."""

    operator_name: str
    domain: str
    spec_name: str
    spec_version: str  # Hash of spec content
    commit_sha: str | None = None
    operator_version: str | None = None
    deployed_at: str | None = None  # ISO timestamp

    def to_tags(self) -> dict[str, str]:
        """Convert to Azure resource tags.

        Returns:
            Dictionary of tags for the Stack resource.
        """
        tags = {
            "azure-operator/managed": "true",
            "azure-operator/domain": self.domain,
            "azure-operator/spec-name": self.spec_name,
            "azure-operator/spec-version": self.spec_version[:8],  # Short hash
        }

        if self.commit_sha:
            tags["azure-operator/commit-sha"] = self.commit_sha[:8]
        if self.operator_version:
            tags["azure-operator/operator-version"] = self.operator_version
        if self.deployed_at:
            tags["azure-operator/deployed-at"] = self.deployed_at

        return tags


@dataclass
class DeploymentStackSpec:
    """Specification for creating/updating a Deployment Stack.

    This is the operator's internal representation, converted to Azure API format.
    """

    name: str
    scope: DeploymentScope
    subscription_id: str
    resource_group: str | None  # For RG-scoped stacks
    management_group_id: str | None  # For MG-scoped stacks (deny won't work)
    location: str
    template: dict[str, Any]
    parameters: dict[str, Any]
    protection_config: StackProtectionConfig
    metadata: StackMetadata
    operator_principal_id: str  # Excluded from deny

    @property
    def deny_supported(self) -> bool:
        """Check if deny settings are supported for this scope."""
        return self.scope != DeploymentScope.MANAGEMENT_GROUP

    def to_azure_payload(self) -> dict[str, Any]:
        """Convert to Azure Deployment Stack API payload.

        Returns:
            Dictionary matching Azure REST API schema for Stack create/update.
        """
        properties: dict[str, Any] = {
            "template": self.template,
            "parameters": self.parameters,
            "actionOnUnmanage": {
                "resources": self.protection_config.action_on_unmanage_resources.value,
                "resourceGroups": self.protection_config.action_on_unmanage_resource_groups.value,
            },
        }

        # Only add deny settings if supported and enabled
        if self.deny_supported and self.protection_config.deny_mode != DenySettingsMode.NONE:
            properties["denySettings"] = self.protection_config.to_deny_settings(
                excluded_principals=[self.operator_principal_id],
            )

        return {
            "location": self.location,
            "tags": self.metadata.to_tags(),
            "properties": properties,
        }


def generate_stack_name(
    operator_name: str,
    domain: str,
    subscription_id: str,
    spec_name: str,
) -> str:
    """Generate a deterministic, unique Stack name.

    Format: azure-operator-{domain}-{sub_short}-{hash}

    The name must be:
    - Deterministic (same inputs = same name)
    - Unique per spec instance
    - Valid Azure resource name (alphanumeric, hyphens)
    - Under 64 characters

    Args:
        operator_name: Name of the operator instance.
        domain: Domain/spec type (e.g., "hub-network").
        subscription_id: Target subscription ID.
        spec_name: Name from spec metadata.

    Returns:
        Stack name string.
    """
    # Create a hash of the unique identifiers
    unique_key = f"{operator_name}:{domain}:{subscription_id}:{spec_name}"
    hash_digest = hashlib.sha256(unique_key.encode()).hexdigest()[:8]

    # Short subscription ID (first segment of GUID)
    sub_short = subscription_id.split("-")[0] if "-" in subscription_id else subscription_id[:8]

    # Construct name
    name = f"azop-{domain}-{sub_short}-{hash_digest}"

    # Ensure valid characters and length
    name = "".join(c if c.isalnum() or c == "-" else "-" for c in name.lower())
    name = name[:MAX_STACK_NAME_LENGTH]

    return name


def should_enable_stack_protection(
    domain: str,
    scope: DeploymentScope,
    explicit_config: StackProtectionConfig | None = None,
) -> bool:
    """Determine if Stack protection should be enabled for a deployment.

    Logic:
    1. If explicit config provided, use its enabled flag
    2. If MG scope, disable (deny not supported)
    3. If high-value domain, enable by default
    4. Otherwise, check environment/default

    Args:
        domain: Spec domain (e.g., "hub-network", "management-group").
        scope: Deployment scope (RG, Subscription, MG).
        explicit_config: Config from spec file, if provided.

    Returns:
        True if Stack protection should be enabled.
    """
    # Explicit config takes precedence
    if explicit_config is not None:
        return explicit_config.enabled

    # MG scope: deny not supported, no point enabling
    if scope == DeploymentScope.MANAGEMENT_GROUP:
        logger.debug(
            "Stack protection disabled for domain '%s': MG scope does not support deny",
            domain,
        )
        return False

    # MG-scoped domains (even if somehow at sub scope)
    if domain in MG_SCOPE_DOMAINS:
        logger.debug(
            "Stack protection disabled for domain '%s': MG-scoped domain",
            domain,
        )
        return False

    # High-value domains: enable by default
    if domain in HIGH_VALUE_DENY_DOMAINS:
        logger.debug(
            "Stack protection enabled by default for high-value domain '%s'",
            domain,
        )
        return True

    # Optional domains: check environment
    env_enabled = os.environ.get("STACK_PROTECTION_OPTIONAL_DOMAINS", "false").lower()
    if env_enabled in ("true", "1", "yes"):
        return True

    # Default: disabled for optional domains
    return False


@dataclass
class StackOperationResult:
    """Result of a Stack create/update operation."""

    success: bool
    stack_name: str
    stack_id: str | None = None
    provisioning_state: str | None = None
    error_message: str | None = None
    error_code: str | None = None
    deny_settings_applied: bool = False
    resources_managed: int = 0


class DeploymentStackManager:
    """Manages Deployment Stacks for the operator.

    This class handles:
    1. Creating/updating Stacks after ARM deployments
    2. Tracking which specs have Stacks
    3. Handling Stack-specific errors

    NOTE: Actual Azure API calls are delegated to the reconciler's
    Azure client. This class provides the logic layer.
    """

    # Maximum stacks to track per operator instance
    MAX_TRACKED_STACKS = 1000

    def __init__(
        self,
        operator_name: str,
        operator_principal_id: str,
        default_config: StackProtectionConfig | None = None,
    ) -> None:
        """Initialize the Stack manager.

        Args:
            operator_name: Name of the operator instance.
            operator_principal_id: Principal ID of operator's managed identity.
            default_config: Default Stack protection config.
        """
        if not operator_name:
            raise ValueError("operator_name cannot be empty")
        if not operator_principal_id:
            raise ValueError("operator_principal_id cannot be empty")

        self._operator_name = operator_name
        self._operator_principal_id = operator_principal_id
        self._default_config = default_config or StackProtectionConfig.from_env()

        # Track known stacks: stack_name -> DeploymentStackSpec
        self._stacks: dict[str, DeploymentStackSpec] = {}

    @property
    def operator_name(self) -> str:
        """Get operator name."""
        return self._operator_name

    @property
    def operator_principal_id(self) -> str:
        """Get operator's principal ID."""
        return self._operator_principal_id

    @property
    def default_config(self) -> StackProtectionConfig:
        """Get default Stack protection config."""
        return self._default_config

    @property
    def tracked_stack_count(self) -> int:
        """Get number of tracked stacks."""
        return len(self._stacks)

    def create_stack_spec(
        self,
        domain: str,
        spec_name: str,
        spec_content_hash: str,
        scope: DeploymentScope,
        subscription_id: str,
        location: str,
        template: dict[str, Any],
        parameters: dict[str, Any],
        resource_group: str | None = None,
        management_group_id: str | None = None,
        explicit_config: StackProtectionConfig | None = None,
        commit_sha: str | None = None,
        operator_version: str | None = None,
    ) -> DeploymentStackSpec | None:
        """Create a Stack specification for a deployment.

        Returns None if Stack protection should not be enabled.

        Args:
            domain: Spec domain (e.g., "hub-network").
            spec_name: Name from spec metadata.
            spec_content_hash: Hash of spec content for versioning.
            scope: Deployment scope.
            subscription_id: Target subscription.
            location: Azure region.
            template: ARM template.
            parameters: Template parameters.
            resource_group: Target RG (for RG-scoped).
            management_group_id: Target MG (for MG-scoped).
            explicit_config: Config from spec file.
            commit_sha: Git commit SHA.
            operator_version: Operator version string.

        Returns:
            DeploymentStackSpec if protection enabled, None otherwise.
        """
        # Check if should enable
        if not should_enable_stack_protection(domain, scope, explicit_config):
            return None

        # Determine config
        config = explicit_config or self._default_config

        # Generate deterministic name
        stack_name = generate_stack_name(
            self._operator_name,
            domain,
            subscription_id,
            spec_name,
        )

        # Create metadata
        metadata = StackMetadata(
            operator_name=self._operator_name,
            domain=domain,
            spec_name=spec_name,
            spec_version=spec_content_hash,
            commit_sha=commit_sha,
            operator_version=operator_version,
        )

        # Build spec
        stack_spec = DeploymentStackSpec(
            name=stack_name,
            scope=scope,
            subscription_id=subscription_id,
            resource_group=resource_group,
            management_group_id=management_group_id,
            location=location,
            template=template,
            parameters=parameters,
            protection_config=config,
            metadata=metadata,
            operator_principal_id=self._operator_principal_id,
        )

        # Track if under limit
        if len(self._stacks) < self.MAX_TRACKED_STACKS:
            self._stacks[stack_name] = stack_spec
        else:
            logger.warning(
                "Stack tracking limit reached (%d), not tracking '%s'",
                self.MAX_TRACKED_STACKS,
                stack_name,
            )

        return stack_spec

    def get_tracked_stack(self, stack_name: str) -> DeploymentStackSpec | None:
        """Get a tracked Stack spec by name.

        Args:
            stack_name: Name of the Stack.

        Returns:
            DeploymentStackSpec if tracked, None otherwise.
        """
        return self._stacks.get(stack_name)

    def remove_tracked_stack(self, stack_name: str) -> bool:
        """Remove a Stack from tracking.

        Args:
            stack_name: Name of the Stack.

        Returns:
            True if removed, False if not found.
        """
        if stack_name in self._stacks:
            del self._stacks[stack_name]
            return True
        return False

    def list_tracked_stacks(self) -> list[str]:
        """List all tracked Stack names.

        Returns:
            List of Stack names.
        """
        return list(self._stacks.keys())


def create_stack_manager_from_env(
    operator_name: str,
    operator_principal_id: str,
) -> DeploymentStackManager:
    """Create a DeploymentStackManager from environment configuration.

    Args:
        operator_name: Name of the operator instance.
        operator_principal_id: Principal ID of operator's managed identity.

    Returns:
        Configured DeploymentStackManager.
    """
    config = StackProtectionConfig.from_env()
    return DeploymentStackManager(
        operator_name=operator_name,
        operator_principal_id=operator_principal_id,
        default_config=config,
    )
