"""Blast radius governance and safety guardrails.

This module implements hard safety limits to prevent unintended changes
at high-impact scopes (tenant root, management groups).

DESIGN PHILOSOPHY:
- Fail closed: When in doubt, block the operation
- Explicit allowlists: Only deploy to explicitly permitted scopes
- Kill switch: Central control to halt all apply operations
- Rate limits: Prevent runaway deployments

These guardrails make the operator VISIBLY SAFER than raw Terraform/Bicep
by enforcing organizational policy at the operator level.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class GuardrailViolation(Exception):
    """Raised when a guardrail check fails."""

    pass


class ScopeViolation(GuardrailViolation):
    """Raised when deployment targets a denied scope."""

    pass


class RateLimitViolation(GuardrailViolation):
    """Raised when change rate limit is exceeded."""

    pass


class KillSwitchActive(GuardrailViolation):
    """Raised when kill switch is enabled."""

    pass


# Well-known high-risk scope patterns
TENANT_ROOT_MG_NAMES = [
    "Tenant Root Group",
    "Root Management Group",
]

# Default denied management groups (can be overridden)
DEFAULT_DENIED_MANAGEMENT_GROUPS = [
    "Tenant Root Group",  # Never touch tenant root by default
]


class ChangeCategory(str, Enum):
    """Categories of changes for rate limiting."""

    RBAC = "rbac"
    POLICY = "policy"
    RESOURCE = "resource"


@dataclass
class RateLimitState:
    """Tracks change counts for rate limiting."""

    counts: dict[ChangeCategory, int] = field(default_factory=dict)
    window_start: datetime = field(default_factory=lambda: datetime.now(UTC))
    cooldown_until: datetime | None = None

    def reset(self) -> None:
        """Reset counters for new window."""
        self.counts = {}
        self.window_start = datetime.now(UTC)
        self.cooldown_until = None


@dataclass(frozen=True)
class GuardrailsConfig:
    """Configuration for blast radius guardrails.

    SECURITY: These settings enforce hard limits on what the operator can do.
    They cannot be bypassed by spec files - only by changing operator config.
    """

    # Scope allowlists - empty means "all allowed" (use with caution)
    allowed_management_groups: list[str] = field(default_factory=list)
    allowed_subscriptions: list[str] = field(default_factory=list)
    allowed_resource_groups: list[str] = field(default_factory=list)

    # Scope denylists - always checked, cannot be overridden by allowlists
    denied_management_groups: list[str] = field(
        default_factory=lambda: list(DEFAULT_DENIED_MANAGEMENT_GROUPS)
    )
    denied_subscriptions: list[str] = field(default_factory=list)

    # Rate limits per reconciliation interval
    max_rbac_changes_per_interval: int = 10
    max_policy_changes_per_interval: int = 5
    max_resource_changes_per_interval: int = 50

    # Cooldown after hitting rate limit
    rate_limit_cooldown_seconds: int = 3600  # 1 hour

    # Kill switch - blocks all apply operations when True
    # Can be set via KILL_SWITCH env var or Azure App Configuration
    kill_switch_enabled: bool = False

    # Fail closed on WhatIf degradation (too many Ignore results)
    fail_closed_on_whatif_degradation: bool = True
    max_whatif_ignore_count: int = 10

    @classmethod
    def from_env(cls) -> GuardrailsConfig:
        """Load guardrails configuration from environment.

        Environment Variables:
            KILL_SWITCH: If "true", blocks all apply operations
            ALLOWED_MANAGEMENT_GROUPS: Comma-separated list of allowed MGs
            DENIED_MANAGEMENT_GROUPS: Comma-separated list of denied MGs
            ALLOWED_SUBSCRIPTIONS: Comma-separated list of allowed subscription IDs
            MAX_RBAC_CHANGES: Max RBAC changes per interval (default: 10)
            MAX_POLICY_CHANGES: Max policy changes per interval (default: 5)
            MAX_RESOURCE_CHANGES: Max resource changes per interval (default: 50)
            RATE_LIMIT_COOLDOWN: Cooldown seconds after hitting limit (default: 3600)
            FAIL_CLOSED_ON_WHATIF_DEGRADATION: If "true", fail when WhatIf unreliable
            MAX_WHATIF_IGNORE_COUNT: Max Ignore results before failing (default: 10)
        """

        def get_list(key: str) -> list[str]:
            value = os.environ.get(key, "")
            if not value:
                return []
            return [item.strip() for item in value.split(",") if item.strip()]

        def get_int(key: str, default: int) -> int:
            value = os.environ.get(key)
            if value is None:
                return default
            try:
                return int(value)
            except ValueError:
                return default

        def get_bool(key: str, default: bool) -> bool:
            value = os.environ.get(key, "").lower()
            if not value:
                return default
            return value in ("true", "1", "yes")

        # Merge default denied MGs with any additional from env
        denied_mgs = list(DEFAULT_DENIED_MANAGEMENT_GROUPS)
        env_denied = get_list("DENIED_MANAGEMENT_GROUPS")
        for mg in env_denied:
            if mg not in denied_mgs:
                denied_mgs.append(mg)

        return cls(
            allowed_management_groups=get_list("ALLOWED_MANAGEMENT_GROUPS"),
            allowed_subscriptions=get_list("ALLOWED_SUBSCRIPTIONS"),
            allowed_resource_groups=get_list("ALLOWED_RESOURCE_GROUPS"),
            denied_management_groups=denied_mgs,
            denied_subscriptions=get_list("DENIED_SUBSCRIPTIONS"),
            max_rbac_changes_per_interval=get_int("MAX_RBAC_CHANGES", 10),
            max_policy_changes_per_interval=get_int("MAX_POLICY_CHANGES", 5),
            max_resource_changes_per_interval=get_int("MAX_RESOURCE_CHANGES", 50),
            rate_limit_cooldown_seconds=get_int("RATE_LIMIT_COOLDOWN", 3600),
            kill_switch_enabled=get_bool("KILL_SWITCH", False),
            fail_closed_on_whatif_degradation=get_bool("FAIL_CLOSED_ON_WHATIF_DEGRADATION", True),
            max_whatif_ignore_count=get_int("MAX_WHATIF_IGNORE_COUNT", 10),
        )


class GuardrailEnforcer:
    """Enforces blast radius guardrails before any deployment.

    SECURITY: This class is the gatekeeper for all deployments.
    Every deployment MUST pass through check_deployment() before apply.

    Usage:
        enforcer = GuardrailEnforcer(config)
        enforcer.check_kill_switch()  # Raises if kill switch active
        enforcer.check_scope(scope)   # Raises if scope not allowed
        enforcer.check_rate_limit(changes)  # Raises if rate limit exceeded
    """

    def __init__(self, config: GuardrailsConfig) -> None:
        """Initialize enforcer with configuration.

        Args:
            config: Guardrails configuration.
        """
        self._config = config
        self._rate_limit_state = RateLimitState()

    @property
    def config(self) -> GuardrailsConfig:
        """Get the guardrails configuration."""
        return self._config

    def check_kill_switch(self) -> None:
        """Check if kill switch is active.

        Raises:
            KillSwitchActive: If kill switch is enabled.
        """
        # Check environment variable (allows dynamic control)
        env_kill_switch = os.environ.get("KILL_SWITCH", "").lower() in ("true", "1", "yes")

        if self._config.kill_switch_enabled or env_kill_switch:
            logger.warning(
                "KILL_SWITCH: Apply operations blocked",
                extra={
                    "config_enabled": self._config.kill_switch_enabled,
                    "env_enabled": env_kill_switch,
                },
            )
            raise KillSwitchActive(
                "Kill switch is active. All apply operations are blocked. "
                "Set KILL_SWITCH=false to resume."
            )

    def check_scope(
        self,
        scope_type: str,
        scope_value: str,
    ) -> None:
        """Check if deployment scope is allowed.

        Args:
            scope_type: One of "management_group", "subscription", "resource_group"
            scope_value: The scope identifier (MG name, subscription ID, RG name)

        Raises:
            ScopeViolation: If scope is denied or not in allowlist.
        """
        # SECURITY: Denylist is ALWAYS checked first and cannot be overridden
        if scope_type == "management_group":
            self._check_management_group_scope(scope_value)
        elif scope_type == "subscription":
            self._check_subscription_scope(scope_value)
        elif scope_type == "resource_group":
            self._check_resource_group_scope(scope_value)

    def _check_management_group_scope(self, mg_name: str) -> None:
        """Check management group scope.

        Args:
            mg_name: Management group name or ID.

        Raises:
            ScopeViolation: If MG is denied or not allowed.
        """
        # Check denylist first (cannot be overridden)
        for denied in self._config.denied_management_groups:
            if self._scope_matches(mg_name, denied):
                logger.error(
                    "GUARDRAIL: Management group deployment blocked (denied)",
                    extra={"management_group": mg_name, "denied_pattern": denied},
                )
                raise ScopeViolation(
                    f"Management group '{mg_name}' is in the deny list. "
                    f"Deployment at this scope is not permitted."
                )

        # Check tenant root (always denied by default)
        for root_name in TENANT_ROOT_MG_NAMES:
            if mg_name.lower() == root_name.lower():
                logger.error(
                    "GUARDRAIL: Tenant root management group deployment blocked",
                    extra={"management_group": mg_name},
                )
                raise ScopeViolation(
                    f"Deployment to tenant root management group '{mg_name}' is not permitted. "
                    f"This is a safety guardrail to prevent tenant-wide impact."
                )

        # Check allowlist (if configured)
        if self._config.allowed_management_groups and not any(
            self._scope_matches(mg_name, allowed)
            for allowed in self._config.allowed_management_groups
        ):
            logger.error(
                "GUARDRAIL: Management group not in allowlist",
                extra={
                    "management_group": mg_name,
                    "allowed": self._config.allowed_management_groups,
                },
            )
            raise ScopeViolation(
                f"Management group '{mg_name}' is not in the allowed list. "
                f"Add it to ALLOWED_MANAGEMENT_GROUPS to permit deployment."
            )

    def _check_subscription_scope(self, subscription_id: str) -> None:
        """Check subscription scope.

        Args:
            subscription_id: Subscription ID (GUID).

        Raises:
            ScopeViolation: If subscription is denied or not allowed.
        """
        # Check denylist
        for denied in self._config.denied_subscriptions:
            if self._scope_matches(subscription_id, denied):
                logger.error(
                    "GUARDRAIL: Subscription deployment blocked (denied)",
                    extra={"subscription_id": subscription_id, "denied_pattern": denied},
                )
                raise ScopeViolation(
                    f"Subscription '{subscription_id}' is in the deny list."
                )

        # Check allowlist (if configured)
        if self._config.allowed_subscriptions and not any(
            self._scope_matches(subscription_id, allowed)
            for allowed in self._config.allowed_subscriptions
        ):
            logger.error(
                "GUARDRAIL: Subscription not in allowlist",
                extra={
                    "subscription_id": subscription_id,
                    "allowed": self._config.allowed_subscriptions,
                },
            )
            raise ScopeViolation(
                f"Subscription '{subscription_id}' is not in the allowed list."
            )

    def _check_resource_group_scope(self, rg_name: str) -> None:
        """Check resource group scope.

        Args:
            rg_name: Resource group name.

        Raises:
            ScopeViolation: If RG is not allowed.
        """
        # Check allowlist (if configured)
        if self._config.allowed_resource_groups and not any(
            self._scope_matches(rg_name, allowed)
            for allowed in self._config.allowed_resource_groups
        ):
            logger.error(
                "GUARDRAIL: Resource group not in allowlist",
                extra={
                    "resource_group": rg_name,
                    "allowed": self._config.allowed_resource_groups,
                },
            )
            raise ScopeViolation(
                f"Resource group '{rg_name}' is not in the allowed list."
            )

    def _scope_matches(self, value: str, pattern: str) -> bool:
        """Check if scope value matches pattern.

        Supports:
        - Exact match (case-insensitive)
        - Wildcard patterns (*, ?)
        - Regex patterns (if starts with ^)

        Args:
            value: The scope value to check.
            pattern: The pattern to match against.

        Returns:
            True if value matches pattern.
        """
        if pattern.startswith("^"):
            # Regex pattern
            return bool(re.match(pattern, value, re.IGNORECASE))
        elif "*" in pattern or "?" in pattern:
            # Wildcard pattern - convert to regex
            regex = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
            return bool(re.match(f"^{regex}$", value, re.IGNORECASE))
        else:
            # Exact match
            return value.lower() == pattern.lower()

    def check_rate_limit(
        self,
        rbac_changes: int = 0,
        policy_changes: int = 0,
        resource_changes: int = 0,
    ) -> None:
        """Check if change rate limit would be exceeded.

        Args:
            rbac_changes: Number of RBAC changes to apply.
            policy_changes: Number of policy changes to apply.
            resource_changes: Number of resource changes to apply.

        Raises:
            RateLimitViolation: If rate limit exceeded or in cooldown.
        """
        now = datetime.now(UTC)

        # Check if in cooldown
        if self._rate_limit_state.cooldown_until is not None:
            if now < self._rate_limit_state.cooldown_until:
                remaining = (self._rate_limit_state.cooldown_until - now).total_seconds()
                logger.warning(
                    "GUARDRAIL: Rate limit cooldown active",
                    extra={
                        "remaining_seconds": remaining,
                        "cooldown_until": self._rate_limit_state.cooldown_until.isoformat(),
                    },
                )
                raise RateLimitViolation(
                    f"Rate limit cooldown active. {remaining:.0f} seconds remaining."
                )
            else:
                # Cooldown expired, reset
                self._rate_limit_state.reset()

        # Check individual limits
        current_rbac = self._rate_limit_state.counts.get(ChangeCategory.RBAC, 0)
        current_policy = self._rate_limit_state.counts.get(ChangeCategory.POLICY, 0)
        current_resource = self._rate_limit_state.counts.get(ChangeCategory.RESOURCE, 0)

        violations = []

        if current_rbac + rbac_changes > self._config.max_rbac_changes_per_interval:
            violations.append(
                f"RBAC changes ({current_rbac + rbac_changes}) "
                f"would exceed limit ({self._config.max_rbac_changes_per_interval})"
            )

        if current_policy + policy_changes > self._config.max_policy_changes_per_interval:
            violations.append(
                f"Policy changes ({current_policy + policy_changes}) "
                f"would exceed limit ({self._config.max_policy_changes_per_interval})"
            )

        if current_resource + resource_changes > self._config.max_resource_changes_per_interval:
            violations.append(
                f"Resource changes ({current_resource + resource_changes}) "
                f"would exceed limit ({self._config.max_resource_changes_per_interval})"
            )

        if violations:
            # Enter cooldown
            self._rate_limit_state.cooldown_until = now + timedelta(
                seconds=self._config.rate_limit_cooldown_seconds
            )
            logger.error(
                "GUARDRAIL: Rate limit exceeded, entering cooldown",
                extra={
                    "violations": violations,
                    "cooldown_seconds": self._config.rate_limit_cooldown_seconds,
                },
            )
            raise RateLimitViolation(
                f"Rate limit exceeded: {'; '.join(violations)}. "
                f"Entering {self._config.rate_limit_cooldown_seconds}s cooldown."
            )

    def record_changes(
        self,
        rbac_changes: int = 0,
        policy_changes: int = 0,
        resource_changes: int = 0,
    ) -> None:
        """Record changes after successful apply.

        Args:
            rbac_changes: Number of RBAC changes applied.
            policy_changes: Number of policy changes applied.
            resource_changes: Number of resource changes applied.
        """
        if rbac_changes > 0:
            current = self._rate_limit_state.counts.get(ChangeCategory.RBAC, 0)
            self._rate_limit_state.counts[ChangeCategory.RBAC] = current + rbac_changes

        if policy_changes > 0:
            current = self._rate_limit_state.counts.get(ChangeCategory.POLICY, 0)
            self._rate_limit_state.counts[ChangeCategory.POLICY] = current + policy_changes

        if resource_changes > 0:
            current = self._rate_limit_state.counts.get(ChangeCategory.RESOURCE, 0)
            self._rate_limit_state.counts[ChangeCategory.RESOURCE] = current + resource_changes

        logger.info(
            "Rate limit state updated",
            extra={
                "rbac_total": self._rate_limit_state.counts.get(ChangeCategory.RBAC, 0),
                "policy_total": self._rate_limit_state.counts.get(ChangeCategory.POLICY, 0),
                "resource_total": self._rate_limit_state.counts.get(ChangeCategory.RESOURCE, 0),
            },
        )

    def check_whatif_reliability(self, ignore_count: int, total_count: int) -> None:
        """Check if WhatIf results are reliable.

        WhatIf returns Ignore for:
        - Nested template expansion limits
        - Template links not evaluated
        - Timeout conditions

        When too many Ignores are returned, the diff may be incomplete.

        Args:
            ignore_count: Number of Ignore results from WhatIf.
            total_count: Total number of changes from WhatIf.

        Raises:
            GuardrailViolation: If fail_closed is enabled and too many Ignores.
        """
        if ignore_count > self._config.max_whatif_ignore_count:
            logger.error(
                "GUARDRAIL: WhatIf reliability degraded",
                extra={
                    "ignore_count": ignore_count,
                    "total_count": total_count,
                    "threshold": self._config.max_whatif_ignore_count,
                    "fail_closed": self._config.fail_closed_on_whatif_degradation,
                },
            )

            if self._config.fail_closed_on_whatif_degradation:
                raise GuardrailViolation(
                    f"WhatIf returned {ignore_count} Ignore results (threshold: "
                    f"{self._config.max_whatif_ignore_count}). This may indicate "
                    f"template expansion limits or timeouts. Deployment blocked for safety. "
                    f"Set FAIL_CLOSED_ON_WHATIF_DEGRADATION=false to override."
                )
