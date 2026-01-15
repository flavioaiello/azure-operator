"""Per-resource and per-scope mode overrides.

This module implements fine-grained reconciliation mode control at the
resource type level, allowing different policies for different resources.

DESIGN PHILOSOPHY:
- Global mode is the default (from Config.mode)
- Spec-level overrides apply to all resources in that spec
- Resource-type overrides allow fine-grained control
- More specific rules take precedence over general rules

USE CASES:
- OBSERVE globally, but ENFORCE for DNS records (low risk)
- ENFORCE globally, but PROTECT for roleAssignments (high risk)
- OBSERVE globally, but ENFORCE for specific resource group

SECURITY CONSIDERATIONS:
- Mode escalation (OBSERVE -> ENFORCE) requires explicit declaration
- Mode restrictions (ENFORCE -> PROTECT) can be applied globally
- Audit log captures all mode decisions with reasoning
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

from pydantic import BaseModel, Field, field_validator

from .config import ReconciliationMode

logger = logging.getLogger(__name__)


class ModeOverrideAction(str, Enum):
    """What action the mode override should take."""

    # Use this mode for matching resources
    SET = "set"
    # Restrict to at most this mode (ENFORCE -> OBSERVE)
    RESTRICT = "restrict"
    # Escalate to at least this mode (OBSERVE -> ENFORCE)
    ESCALATE = "escalate"


@dataclass(frozen=True)
class ModeOverrideResult:
    """Result of a mode override check.

    Attributes:
        effective_mode: The mode to use for this resource.
        rule_matched: Which rule was matched (None if using default).
        reason: Human-readable explanation of why this mode was chosen.
    """

    effective_mode: ReconciliationMode
    rule_matched: str | None
    reason: str


class ResourceModeOverride(BaseModel):
    """A single resource mode override rule.

    Specifies which resources this rule matches and what mode to apply.

    Examples:
        # Protect all role assignments
        - resource_types: ["Microsoft.Authorization/roleAssignments"]
          mode: protect

        # Observe all storage in specific RG
        - resource_group: "rg-archive-*"
          mode: observe

        # Enforce DNS changes
        - resource_types: ["Microsoft.Network/privateDnsZones/*"]
          mode: enforce
    """

    model_config = {"extra": "ignore"}

    # Match criteria (at least one must be specified)
    resource_types: list[str] = Field(default_factory=list, alias="resourceTypes")
    resource_groups: list[str] = Field(default_factory=list, alias="resourceGroups")
    subscriptions: list[str] = Field(default_factory=list)
    resource_names: list[str] = Field(default_factory=list, alias="resourceNames")

    # Action
    mode: ReconciliationMode
    action: ModeOverrideAction = ModeOverrideAction.SET

    # Documentation
    reason: str = ""

    @field_validator("resource_types", "resource_groups", "subscriptions", "resource_names")
    @classmethod
    def validate_patterns(cls, v: list[str]) -> list[str]:
        """Validate patterns are non-empty strings."""
        result = []
        for pattern in v:
            if not pattern or not pattern.strip():
                continue
            result.append(pattern.strip())
        return result

    def matches(
        self,
        resource_type: str,
        resource_group: str | None = None,
        subscription_id: str | None = None,
        resource_name: str | None = None,
    ) -> bool:
        """Check if this override matches the given resource.

        Args:
            resource_type: Azure resource type (e.g., "Microsoft.Network/virtualNetworks")
            resource_group: Resource group name (optional)
            subscription_id: Subscription ID (optional)
            resource_name: Resource name (optional)

        Returns:
            True if this rule matches the resource.
        """
        # Must have at least one match criterion
        if not any([
            self.resource_types,
            self.resource_groups,
            self.subscriptions,
            self.resource_names,
        ]):
            return False

        # Check resource type patterns
        if self.resource_types and not self._matches_any_pattern(
            resource_type, self.resource_types
        ):
            return False

        # Check resource group patterns
        if self.resource_groups:
            if not resource_group:
                return False
            if not self._matches_any_pattern(resource_group, self.resource_groups):
                return False

        # Check subscription patterns
        if self.subscriptions:
            if not subscription_id:
                return False
            if not self._matches_any_pattern(subscription_id, self.subscriptions):
                return False

        # Check resource name patterns
        if self.resource_names:
            if not resource_name:
                return False
            if not self._matches_any_pattern(resource_name, self.resource_names):
                return False

        return True

    def _matches_any_pattern(self, value: str, patterns: list[str]) -> bool:
        """Check if value matches any of the patterns.

        Supports glob-style wildcards:
        - * matches any characters
        - ? matches a single character
        """
        value_lower = value.lower()
        for pattern in patterns:
            pattern_lower = pattern.lower()

            # Convert glob to regex
            regex_pattern = self._glob_to_regex(pattern_lower)
            if re.match(regex_pattern, value_lower):
                return True

        return False

    def _glob_to_regex(self, pattern: str) -> str:
        """Convert glob pattern to regex.

        * -> .*
        ? -> .
        Other regex chars are escaped
        """
        # Escape regex special chars except * and ?
        escaped = ""
        for char in pattern:
            if char == "*":
                escaped += ".*"
            elif char == "?":
                escaped += "."
            elif char in r"\.[]{}()+^$|":
                escaped += "\\" + char
            else:
                escaped += char

        return f"^{escaped}$"


class SpecModeConfig(BaseModel):
    """Mode configuration within a spec file.

    This allows specs to declare their own mode preferences and
    resource-level overrides.

    Example YAML:
        modeConfig:
          defaultMode: observe
          overrides:
            - resourceTypes: ["Microsoft.Authorization/roleAssignments"]
              mode: protect
              reason: "RBAC changes require manual review"
    """

    model_config = {"extra": "ignore"}

    # Default mode for this spec (overrides global mode)
    default_mode: ReconciliationMode | None = Field(None, alias="defaultMode")

    # Resource-level overrides
    overrides: list[ResourceModeOverride] = Field(default_factory=list)

    # Whether to allow mode escalation (OBSERVE -> ENFORCE)
    # If False, overrides can only restrict modes
    allow_escalation: bool = Field(False, alias="allowEscalation")


# Well-known high-risk resource types that should default to PROTECT
HIGH_RISK_RESOURCE_TYPES: set[str] = {
    # RBAC
    "Microsoft.Authorization/roleAssignments",
    "Microsoft.Authorization/roleDefinitions",
    # Networking - security critical
    "Microsoft.Network/azureFirewalls",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/routeTables",
    # Key Vault
    "Microsoft.KeyVault/vaults",
    "Microsoft.KeyVault/vaults/accessPolicies",
    # Management Groups
    "Microsoft.Management/managementGroups",
    # Policy
    "Microsoft.Authorization/policyAssignments",
    "Microsoft.Authorization/policyDefinitions",
    "Microsoft.Authorization/policySetDefinitions",
}

# Resource types that are generally safe to auto-enforce
LOW_RISK_RESOURCE_TYPES: set[str] = {
    # Monitoring
    "Microsoft.Insights/diagnosticSettings",
    "Microsoft.Insights/activityLogAlerts",
    "Microsoft.Insights/metricAlerts",
    # DNS
    "Microsoft.Network/privateDnsZones",
    "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
    "Microsoft.Network/privateDnsZones/A",
    "Microsoft.Network/privateDnsZones/AAAA",
    "Microsoft.Network/privateDnsZones/CNAME",
    # Tags
    "Microsoft.Resources/tags",
}


@dataclass
class ModeResolver:
    """Resolves the effective reconciliation mode for a resource.

    This class evaluates the mode hierarchy:
    1. Global mode (from Config)
    2. Spec-level default mode (from spec file)
    3. Spec-level resource overrides
    4. Global resource type defaults (HIGH_RISK -> PROTECT)

    Thread Safety:
        This class is stateless and thread-safe.
    """

    # Global mode from Config
    global_mode: ReconciliationMode

    # Global overrides (from environment/config, not spec)
    global_overrides: list[ResourceModeOverride] = field(default_factory=list)

    # Whether to auto-protect high-risk resources
    auto_protect_high_risk: bool = True

    # Whether to allow specs to escalate mode
    allow_spec_escalation: bool = False

    def resolve(
        self,
        resource_type: str,
        spec_mode_config: SpecModeConfig | None = None,
        resource_group: str | None = None,
        subscription_id: str | None = None,
        resource_name: str | None = None,
    ) -> ModeOverrideResult:
        """Resolve the effective mode for a resource.

        Args:
            resource_type: Azure resource type.
            spec_mode_config: Mode configuration from the spec file.
            resource_group: Resource group name (optional).
            subscription_id: Subscription ID (optional).
            resource_name: Resource name (optional).

        Returns:
            ModeOverrideResult with the effective mode and reasoning.
        """
        # Start with global mode
        effective_mode = self.global_mode
        reason = f"Global mode: {self.global_mode.value}"
        rule_matched: str | None = None

        # Check spec-level default mode
        if spec_mode_config and spec_mode_config.default_mode:
            new_mode = self._apply_mode_change(
                current=effective_mode,
                requested=spec_mode_config.default_mode,
                action=ModeOverrideAction.SET,
                allow_escalation=self.allow_spec_escalation,
            )
            if new_mode != effective_mode:
                effective_mode = new_mode
                reason = f"Spec default mode: {spec_mode_config.default_mode.value}"
                rule_matched = "spec.modeConfig.defaultMode"

        # Check global overrides (from config/env)
        for override in self.global_overrides:
            if override.matches(
                resource_type=resource_type,
                resource_group=resource_group,
                subscription_id=subscription_id,
                resource_name=resource_name,
            ):
                new_mode = self._apply_mode_change(
                    current=effective_mode,
                    requested=override.mode,
                    action=override.action,
                    allow_escalation=True,  # Global overrides can always escalate
                )
                if new_mode != effective_mode:
                    effective_mode = new_mode
                    reason = override.reason or f"Global override: {override.mode.value}"
                    rule_matched = f"globalOverride:{override.resource_types}"
                break  # First match wins

        # Check spec-level overrides
        if spec_mode_config:
            for override in spec_mode_config.overrides:
                if override.matches(
                    resource_type=resource_type,
                    resource_group=resource_group,
                    subscription_id=subscription_id,
                    resource_name=resource_name,
                ):
                    new_mode = self._apply_mode_change(
                        current=effective_mode,
                        requested=override.mode,
                        action=override.action,
                        allow_escalation=spec_mode_config.allow_escalation,
                    )
                    if new_mode != effective_mode:
                        effective_mode = new_mode
                        reason = override.reason or f"Spec override: {override.mode.value}"
                        rule_matched = f"spec.override:{override.resource_types}"
                    break  # First match wins

        # Auto-protect high-risk resources (if enabled and not already PROTECT)
        if self.auto_protect_high_risk and effective_mode != ReconciliationMode.PROTECT:
            normalized_type = resource_type.lower()
            for high_risk in HIGH_RISK_RESOURCE_TYPES:
                if normalized_type == high_risk.lower():
                    effective_mode = ReconciliationMode.PROTECT
                    reason = f"Auto-protect high-risk resource type: {resource_type}"
                    rule_matched = "autoProtect:highRisk"
                    break

        return ModeOverrideResult(
            effective_mode=effective_mode,
            rule_matched=rule_matched,
            reason=reason,
        )

    def _apply_mode_change(
        self,
        current: ReconciliationMode,
        requested: ReconciliationMode,
        action: ModeOverrideAction,
        allow_escalation: bool,
    ) -> ReconciliationMode:
        """Apply a mode change based on action type.

        Mode hierarchy (from least to most restrictive):
        ENFORCE < OBSERVE < PROTECT

        Escalation = moving towards ENFORCE (less restrictive)
        Restriction = moving towards PROTECT (more restrictive)
        """
        mode_order = {
            ReconciliationMode.ENFORCE: 0,
            ReconciliationMode.OBSERVE: 1,
            ReconciliationMode.PROTECT: 2,
        }

        current_level = mode_order[current]
        requested_level = mode_order[requested]

        if action == ModeOverrideAction.SET:
            # Direct set - check escalation rules
            is_escalation = requested_level < current_level
            if is_escalation and not allow_escalation:
                logger.warning(
                    f"Mode escalation blocked: {current.value} -> {requested.value}",
                    extra={"current": current.value, "requested": requested.value},
                )
                return current
            return requested

        elif action == ModeOverrideAction.RESTRICT:
            # Only apply if more restrictive
            if requested_level > current_level:
                return requested
            return current

        elif action == ModeOverrideAction.ESCALATE:
            # Only apply if less restrictive (and allowed)
            if requested_level < current_level:
                if not allow_escalation:
                    logger.warning(
                        f"Mode escalation blocked: {current.value} -> {requested.value}",
                        extra={"current": current.value, "requested": requested.value},
                    )
                    return current
                return requested
            return current

        return current


def create_mode_resolver_from_env(global_mode: ReconciliationMode) -> ModeResolver:
    """Create a ModeResolver with configuration from environment.

    Environment Variables:
        AUTO_PROTECT_HIGH_RISK: If "true", auto-protect high-risk resources (default: true)
        ALLOW_SPEC_ESCALATION: If "true", allow specs to escalate mode (default: false)
        GLOBAL_MODE_OVERRIDES: JSON list of global overrides (optional)

    Args:
        global_mode: The global reconciliation mode.

    Returns:
        Configured ModeResolver.
    """
    import json
    import os

    auto_protect = os.environ.get(
        "AUTO_PROTECT_HIGH_RISK", "true"
    ).lower() in ("true", "1", "yes")
    allow_escalation = os.environ.get(
        "ALLOW_SPEC_ESCALATION", "false"
    ).lower() in ("true", "1", "yes")

    # Parse global overrides from JSON if provided
    global_overrides: list[ResourceModeOverride] = []
    overrides_json = os.environ.get("GLOBAL_MODE_OVERRIDES", "")
    if overrides_json:
        try:
            overrides_data = json.loads(overrides_json)
            if isinstance(overrides_data, list):
                for item in overrides_data:
                    global_overrides.append(ResourceModeOverride.model_validate(item))
        except ValueError as e:
            # ValueError covers json.JSONDecodeError (its subclass) and Pydantic validation errors
            logger.warning(f"Failed to parse GLOBAL_MODE_OVERRIDES: {e}")

    return ModeResolver(
        global_mode=global_mode,
        global_overrides=global_overrides,
        auto_protect_high_risk=auto_protect,
        allow_spec_escalation=allow_escalation,
    )
