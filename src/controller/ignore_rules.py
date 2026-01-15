"""Ignore rules framework for drift detection.

This module implements K8s-style ignoreDifferences for Azure resources,
allowing operators to specify which properties should be ignored during
drift detection.

DESIGN PHILOSOPHY:
- Explicit rules: Only ignore what is explicitly configured
- Path-based matching: Use JSONPath-like syntax for property paths
- Resource type scoping: Rules can target specific resource types
- Audit trail: Log when rules suppress drift for visibility

These rules normalize WhatIf output to reduce noise from:
- System-managed properties (provisioningState, resourceGuid)
- Default value differences (empty array vs null)
- Tags that are externally managed (createdBy, environment)
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class IgnoreRulesError(Exception):
    """Raised when ignore rules configuration is invalid."""

    pass


@dataclass(frozen=True)
class IgnoreRule:
    """A single ignore rule for drift detection.

    Attributes:
        resource_type: Azure resource type to match (e.g., "Microsoft.Network/virtualNetworks")
                       Supports wildcards: "*" matches all types.
        paths: List of property paths to ignore (e.g., "properties.provisioningState")
               Supports wildcards in path segments.
        reason: Human-readable explanation for audit logging.
    """

    resource_type: str
    paths: list[str]
    reason: str = ""

    def matches_resource(self, resource_type: str) -> bool:
        """Check if this rule applies to a resource type.

        Args:
            resource_type: The Azure resource type to check.

        Returns:
            True if this rule applies to the resource type.
        """
        if self.resource_type == "*":
            return True
        # Case-insensitive matching for Azure resource types
        return fnmatch.fnmatch(resource_type.lower(), self.resource_type.lower())

    def should_ignore_path(self, path: str) -> bool:
        """Check if a property path should be ignored.

        Args:
            path: The property path to check (e.g., "properties.tags.createdBy")

        Returns:
            True if this path should be ignored.
        """
        return any(self._path_matches(path, pattern) for pattern in self.paths)

    def _path_matches(self, path: str, pattern: str) -> bool:
        """Check if a path matches a pattern.

        Supports wildcards:
        - "*" matches any single segment
        - "**" matches any number of segments

        Args:
            path: The actual property path.
            pattern: The pattern to match against.

        Returns:
            True if path matches pattern.
        """
        path_parts = path.split(".")
        pattern_parts = pattern.split(".")

        return self._match_parts(path_parts, pattern_parts)

    def _match_parts(self, path_parts: list[str], pattern_parts: list[str]) -> bool:
        """Recursively match path parts against pattern parts."""
        if not pattern_parts:
            return not path_parts
        if not path_parts:
            return all(p == "**" for p in pattern_parts)

        if pattern_parts[0] == "**":
            # "**" can match zero or more segments
            if len(pattern_parts) == 1:
                return True  # "**" at end matches everything
            # Try matching rest of pattern at each position
            for i in range(len(path_parts) + 1):
                if self._match_parts(path_parts[i:], pattern_parts[1:]):
                    return True
            return False
        elif pattern_parts[0] == "*" or fnmatch.fnmatch(path_parts[0], pattern_parts[0]):
            return self._match_parts(path_parts[1:], pattern_parts[1:])
        else:
            return False


# Default ignore rules for common Azure noise
DEFAULT_IGNORE_RULES: list[IgnoreRule] = [
    IgnoreRule(
        resource_type="*",
        paths=[
            "properties.provisioningState",
            "properties.resourceGuid",
            "etag",
            "id",  # Resource ID is set by ARM
            "name",  # Name is set by ARM
            "type",  # Type is set by ARM
        ],
        reason="System-managed properties that change without user action",
    ),
    IgnoreRule(
        resource_type="Microsoft.Network/virtualNetworks",
        paths=[
            "properties.subnets.*.properties.provisioningState",
            "properties.subnets.*.properties.privateEndpointNetworkPolicies",
            "properties.subnets.*.properties.privateLinkServiceNetworkPolicies",
        ],
        reason="Subnet properties that Azure manages automatically",
    ),
    IgnoreRule(
        resource_type="Microsoft.Network/networkSecurityGroups",
        paths=[
            "properties.securityRules.*.properties.provisioningState",
            "properties.defaultSecurityRules",
        ],
        reason="NSG default rules and provisioning state",
    ),
    IgnoreRule(
        resource_type="Microsoft.ManagedIdentity/userAssignedIdentities",
        paths=[
            "properties.principalId",
            "properties.clientId",
            "properties.tenantId",
        ],
        reason="Identity properties populated after creation",
    ),
]


@dataclass
class IgnoreRulesConfig:
    """Configuration for ignore rules.

    Attributes:
        rules: List of ignore rules to apply.
        enable_default_rules: Whether to include default rules for common noise.
        log_ignored_changes: Whether to log when changes are ignored (for audit).
    """

    rules: list[IgnoreRule] = field(default_factory=list)
    enable_default_rules: bool = True
    log_ignored_changes: bool = True

    def get_effective_rules(self) -> list[IgnoreRule]:
        """Get all rules including defaults if enabled."""
        if self.enable_default_rules:
            return list(DEFAULT_IGNORE_RULES) + list(self.rules)
        return list(self.rules)

    @classmethod
    def from_yaml(cls, yaml_content: str) -> IgnoreRulesConfig:
        """Parse ignore rules from YAML content.

        Expected format:
        ```yaml
        enableDefaultRules: true
        logIgnoredChanges: true
        rules:
          - resourceType: "Microsoft.Network/virtualNetworks"
            paths:
              - "properties.provisioningState"
              - "tags.createdBy"
            reason: "Tolerate tags set by automation"
        ```

        Args:
            yaml_content: YAML string containing rules configuration.

        Returns:
            Configured IgnoreRulesConfig instance.

        Raises:
            IgnoreRulesError: If YAML is invalid or malformed.
        """
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise IgnoreRulesError(f"Invalid YAML in ignore rules: {e}") from e

        if data is None:
            return cls()

        if not isinstance(data, dict):
            raise IgnoreRulesError("Ignore rules must be a YAML object")

        rules: list[IgnoreRule] = []
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise IgnoreRulesError("'rules' must be a list")

        for i, rule_data in enumerate(raw_rules):
            if not isinstance(rule_data, dict):
                raise IgnoreRulesError(f"Rule {i} must be an object")

            resource_type = rule_data.get("resourceType", "*")
            paths = rule_data.get("paths", [])
            reason = rule_data.get("reason", "")

            if not isinstance(paths, list):
                raise IgnoreRulesError(f"Rule {i}: 'paths' must be a list")
            if not paths:
                raise IgnoreRulesError(f"Rule {i}: 'paths' cannot be empty")
            for path in paths:
                if not isinstance(path, str):
                    raise IgnoreRulesError(f"Rule {i}: paths must be strings")

            rules.append(IgnoreRule(
                resource_type=str(resource_type),
                paths=[str(p) for p in paths],
                reason=str(reason),
            ))

        return cls(
            rules=rules,
            enable_default_rules=data.get("enableDefaultRules", True),
            log_ignored_changes=data.get("logIgnoredChanges", True),
        )

    @classmethod
    def from_file(cls, path: str) -> IgnoreRulesConfig:
        """Load ignore rules from a file.

        Args:
            path: Path to YAML file containing rules.

        Returns:
            Configured IgnoreRulesConfig instance.

        Raises:
            IgnoreRulesError: If file cannot be read or parsed.
        """
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            raise IgnoreRulesError(f"Cannot read ignore rules file: {e}") from e

        return cls.from_yaml(content)

    @classmethod
    def from_env(cls) -> IgnoreRulesConfig:
        """Load ignore rules from environment.

        Environment Variables:
            IGNORE_RULES_FILE: Path to YAML file with rules (optional)
            ENABLE_DEFAULT_IGNORE_RULES: If "false", disable default rules
            LOG_IGNORED_CHANGES: If "false", don't log ignored changes

        Returns:
            Configured IgnoreRulesConfig instance.
        """
        config = cls(
            enable_default_rules=os.environ.get(
                "ENABLE_DEFAULT_IGNORE_RULES", "true"
            ).lower() in ("true", "1", "yes"),
            log_ignored_changes=os.environ.get(
                "LOG_IGNORED_CHANGES", "true"
            ).lower() in ("true", "1", "yes"),
        )

        rules_file = os.environ.get("IGNORE_RULES_FILE")
        if rules_file:
            try:
                file_config = cls.from_file(rules_file)
                # Merge rules from file with env settings
                config = IgnoreRulesConfig(
                    rules=file_config.rules,
                    enable_default_rules=config.enable_default_rules,
                    log_ignored_changes=config.log_ignored_changes,
                )
            except IgnoreRulesError:
                logger.warning(
                    "Failed to load ignore rules file, using defaults",
                    extra={"path": rules_file},
                )

        return config


class IgnoreRulesEvaluator:
    """Evaluates ignore rules against WhatIf changes.

    This class filters WhatIf results to remove noise from system-managed
    properties and user-configured ignore rules.
    """

    def __init__(self, config: IgnoreRulesConfig) -> None:
        """Initialize evaluator with configuration.

        Args:
            config: Ignore rules configuration.
        """
        self._config = config
        self._rules = config.get_effective_rules()

    def should_ignore_change(
        self,
        resource_type: str,
        change_path: str,
    ) -> tuple[bool, str | None]:
        """Check if a specific property change should be ignored.

        Args:
            resource_type: The Azure resource type being changed.
            change_path: The property path being changed.

        Returns:
            Tuple of (should_ignore, reason).
        """
        for rule in self._rules:
            if rule.matches_resource(resource_type) and rule.should_ignore_path(change_path):
                if self._config.log_ignored_changes:
                    logger.debug(
                        "Ignoring change per rule",
                        extra={
                            "resource_type": resource_type,
                            "change_path": change_path,
                            "reason": rule.reason,
                        },
                    )
                return True, rule.reason
        return False, None

    def filter_whatif_changes(
        self,
        changes: list[Any],
    ) -> tuple[list[Any], int]:
        """Filter WhatIf changes to remove ignored properties.

        This method processes WhatIf results and removes changes that
        match ignore rules. Changes with no significant properties
        left after filtering are dropped entirely.

        Args:
            changes: List of WhatIfChange objects from ARM WhatIf API.

        Returns:
            Tuple of (filtered_changes, ignored_count).
        """
        filtered: list[Any] = []
        ignored_count = 0

        for change in changes:
            resource_type = getattr(change, "resource_type", "") or ""
            change_type = getattr(change, "change_type", "")

            # Create, Delete, and NoChange are never filtered
            # Only Modify changes can have properties ignored
            if change_type not in ("Modify", "modify"):
                filtered.append(change)
                continue

            # Check if entire resource type should be ignored
            # (This would require a rule with an empty paths list, which we don't support)

            # For Modify changes, we'd need to inspect the delta
            # The WhatIf API returns property changes in delta.before/delta.after
            # For now, we'll apply resource-type-level rules only
            delta = getattr(change, "delta", None)
            if delta is None:
                filtered.append(change)
                continue

            # Check each property change in the delta
            has_significant_changes = False
            for prop_change in delta if isinstance(delta, list) else []:
                prop_path = getattr(prop_change, "path", "") or ""
                should_ignore, _ = self.should_ignore_change(resource_type, prop_path)
                if not should_ignore:
                    has_significant_changes = True
                    break
                else:
                    ignored_count += 1

            if has_significant_changes:
                filtered.append(change)
            else:
                logger.debug(
                    "Dropping change: all properties ignored",
                    extra={"resource_id": getattr(change, "resource_id", "")},
                )

        return filtered, ignored_count
