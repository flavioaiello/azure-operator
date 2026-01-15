"""Tests for guardrails module.

Tests blast radius governance and safety guardrails including:
- Kill switch functionality
- Scope allowlists and denylists
- Rate limiting
- WhatIf reliability detection
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from controller.guardrails import (
    DEFAULT_DENIED_MANAGEMENT_GROUPS,
    TENANT_ROOT_MG_NAMES,
    ChangeCategory,
    GuardrailEnforcer,
    GuardrailsConfig,
    GuardrailViolation,
    KillSwitchActive,
    RateLimitState,
    RateLimitViolation,
    ScopeViolation,
)


class TestGuardrailsConfig:
    """Tests for GuardrailsConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = GuardrailsConfig()

        assert config.kill_switch_enabled is False
        assert config.max_rbac_changes_per_interval == 10
        assert config.max_policy_changes_per_interval == 5
        assert config.max_resource_changes_per_interval == 50
        assert config.rate_limit_cooldown_seconds == 3600
        assert config.fail_closed_on_whatif_degradation is True
        assert config.max_whatif_ignore_count == 10
        assert config.denied_management_groups == list(DEFAULT_DENIED_MANAGEMENT_GROUPS)

    def test_from_env_empty(self) -> None:
        """Test loading from environment with no variables set."""
        with patch.dict(os.environ, {}, clear=True):
            config = GuardrailsConfig.from_env()

        assert config.kill_switch_enabled is False
        assert config.allowed_management_groups == []
        assert config.allowed_subscriptions == []
        assert "Tenant Root Group" in config.denied_management_groups

    def test_from_env_kill_switch_true(self) -> None:
        """Test loading kill switch from environment."""
        with patch.dict(os.environ, {"KILL_SWITCH": "true"}, clear=True):
            config = GuardrailsConfig.from_env()

        assert config.kill_switch_enabled is True

    def test_from_env_kill_switch_1(self) -> None:
        """Test loading kill switch with '1' value."""
        with patch.dict(os.environ, {"KILL_SWITCH": "1"}, clear=True):
            config = GuardrailsConfig.from_env()

        assert config.kill_switch_enabled is True

    def test_from_env_kill_switch_yes(self) -> None:
        """Test loading kill switch with 'yes' value."""
        with patch.dict(os.environ, {"KILL_SWITCH": "yes"}, clear=True):
            config = GuardrailsConfig.from_env()

        assert config.kill_switch_enabled is True

    def test_from_env_allowlists(self) -> None:
        """Test loading allowlists from environment."""
        with patch.dict(
            os.environ,
            {
                "ALLOWED_MANAGEMENT_GROUPS": "mg1,mg2,mg3",
                "ALLOWED_SUBSCRIPTIONS": "sub-1,sub-2",
                "ALLOWED_RESOURCE_GROUPS": "rg-prod,rg-dev",
            },
            clear=True,
        ):
            config = GuardrailsConfig.from_env()

        assert config.allowed_management_groups == ["mg1", "mg2", "mg3"]
        assert config.allowed_subscriptions == ["sub-1", "sub-2"]
        assert config.allowed_resource_groups == ["rg-prod", "rg-dev"]

    def test_from_env_denylists_merged(self) -> None:
        """Test that env denylists are merged with defaults."""
        with patch.dict(
            os.environ,
            {"DENIED_MANAGEMENT_GROUPS": "custom-mg"},
            clear=True,
        ):
            config = GuardrailsConfig.from_env()

        # Should have both default and custom
        assert "Tenant Root Group" in config.denied_management_groups
        assert "custom-mg" in config.denied_management_groups

    def test_from_env_rate_limits(self) -> None:
        """Test loading rate limits from environment."""
        with patch.dict(
            os.environ,
            {
                "MAX_RBAC_CHANGES": "5",
                "MAX_POLICY_CHANGES": "3",
                "MAX_RESOURCE_CHANGES": "25",
                "RATE_LIMIT_COOLDOWN": "1800",
            },
            clear=True,
        ):
            config = GuardrailsConfig.from_env()

        assert config.max_rbac_changes_per_interval == 5
        assert config.max_policy_changes_per_interval == 3
        assert config.max_resource_changes_per_interval == 25
        assert config.rate_limit_cooldown_seconds == 1800

    def test_from_env_invalid_int_uses_default(self) -> None:
        """Test that invalid integers fall back to defaults."""
        with patch.dict(
            os.environ,
            {"MAX_RBAC_CHANGES": "not-a-number"},
            clear=True,
        ):
            config = GuardrailsConfig.from_env()

        assert config.max_rbac_changes_per_interval == 10  # default

    def test_from_env_whatif_settings(self) -> None:
        """Test loading WhatIf reliability settings."""
        with patch.dict(
            os.environ,
            {
                "FAIL_CLOSED_ON_WHATIF_DEGRADATION": "false",
                "MAX_WHATIF_IGNORE_COUNT": "20",
            },
            clear=True,
        ):
            config = GuardrailsConfig.from_env()

        assert config.fail_closed_on_whatif_degradation is False
        assert config.max_whatif_ignore_count == 20


class TestKillSwitch:
    """Tests for kill switch functionality."""

    def test_kill_switch_disabled(self) -> None:
        """Test that kill switch disabled allows operations."""
        config = GuardrailsConfig(kill_switch_enabled=False)
        enforcer = GuardrailEnforcer(config)

        # Should not raise
        enforcer.check_kill_switch()

    def test_kill_switch_enabled_config(self) -> None:
        """Test that kill switch enabled in config raises."""
        config = GuardrailsConfig(kill_switch_enabled=True)
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(KillSwitchActive) as exc_info:
            enforcer.check_kill_switch()

        assert "Kill switch is active" in str(exc_info.value)
        assert "KILL_SWITCH=false" in str(exc_info.value)

    def test_kill_switch_enabled_env(self) -> None:
        """Test that kill switch enabled via env raises."""
        config = GuardrailsConfig(kill_switch_enabled=False)
        enforcer = GuardrailEnforcer(config)

        with patch.dict(os.environ, {"KILL_SWITCH": "true"}):
            with pytest.raises(KillSwitchActive):
                enforcer.check_kill_switch()


class TestScopeValidation:
    """Tests for scope allowlist/denylist validation."""

    def test_management_group_denied_default(self) -> None:
        """Test that Tenant Root Group is denied by default."""
        config = GuardrailsConfig()
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(ScopeViolation) as exc_info:
            enforcer.check_scope("management_group", "Tenant Root Group")

        assert "deny list" in str(exc_info.value)

    def test_management_group_tenant_root_variations(self) -> None:
        """Test that various tenant root names are blocked."""
        config = GuardrailsConfig(denied_management_groups=[])  # Override defaults
        enforcer = GuardrailEnforcer(config)

        for root_name in TENANT_ROOT_MG_NAMES:
            with pytest.raises(ScopeViolation) as exc_info:
                enforcer.check_scope("management_group", root_name)
            assert "tenant root" in str(exc_info.value).lower()

    def test_management_group_allowed(self) -> None:
        """Test that allowed management groups pass."""
        config = GuardrailsConfig(
            allowed_management_groups=["prod-mg", "dev-mg"],
            denied_management_groups=[],
        )
        enforcer = GuardrailEnforcer(config)

        # Should not raise
        enforcer.check_scope("management_group", "prod-mg")
        enforcer.check_scope("management_group", "dev-mg")

    def test_management_group_not_in_allowlist(self) -> None:
        """Test that MGs not in allowlist are blocked."""
        config = GuardrailsConfig(
            allowed_management_groups=["prod-mg"],
            denied_management_groups=[],
        )
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(ScopeViolation) as exc_info:
            enforcer.check_scope("management_group", "staging-mg")

        assert "not in the allowed list" in str(exc_info.value)

    def test_management_group_no_allowlist_allows_all(self) -> None:
        """Test that empty allowlist allows all (except denied)."""
        config = GuardrailsConfig(
            allowed_management_groups=[],  # Empty means no restriction
            denied_management_groups=[],
        )
        enforcer = GuardrailEnforcer(config)

        # Should not raise (except for hardcoded tenant root)
        enforcer.check_scope("management_group", "any-mg")

    def test_denylist_takes_precedence(self) -> None:
        """Test that denylist blocks even if in allowlist."""
        config = GuardrailsConfig(
            allowed_management_groups=["bad-mg", "good-mg"],
            denied_management_groups=["bad-mg"],
        )
        enforcer = GuardrailEnforcer(config)

        # Denied takes precedence
        with pytest.raises(ScopeViolation):
            enforcer.check_scope("management_group", "bad-mg")

        # Allowed works
        enforcer.check_scope("management_group", "good-mg")

    def test_subscription_denied(self) -> None:
        """Test that denied subscriptions are blocked."""
        config = GuardrailsConfig(
            denied_subscriptions=["00000000-0000-0000-0000-000000000000"],
        )
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(ScopeViolation):
            enforcer.check_scope("subscription", "00000000-0000-0000-0000-000000000000")

    def test_subscription_allowed(self) -> None:
        """Test that allowed subscriptions pass."""
        config = GuardrailsConfig(
            allowed_subscriptions=["12345678-1234-1234-1234-123456789012"],
        )
        enforcer = GuardrailEnforcer(config)

        # Should not raise
        enforcer.check_scope("subscription", "12345678-1234-1234-1234-123456789012")

        # Not in allowlist
        with pytest.raises(ScopeViolation):
            enforcer.check_scope("subscription", "other-sub")

    def test_subscription_no_restrictions(self) -> None:
        """Test that empty lists allow all subscriptions."""
        config = GuardrailsConfig()
        enforcer = GuardrailEnforcer(config)

        # Should not raise
        enforcer.check_scope("subscription", "any-sub")

    def test_resource_group_allowed(self) -> None:
        """Test that allowed resource groups pass."""
        config = GuardrailsConfig(
            allowed_resource_groups=["rg-prod-*"],
        )
        enforcer = GuardrailEnforcer(config)

        # Should match wildcard
        enforcer.check_scope("resource_group", "rg-prod-eastus")
        enforcer.check_scope("resource_group", "rg-prod-westus")

        # Not matching
        with pytest.raises(ScopeViolation):
            enforcer.check_scope("resource_group", "rg-dev-eastus")

    def test_wildcard_patterns(self) -> None:
        """Test wildcard pattern matching."""
        config = GuardrailsConfig(
            allowed_management_groups=["contoso-*-mg"],
            denied_management_groups=[],
        )
        enforcer = GuardrailEnforcer(config)

        enforcer.check_scope("management_group", "contoso-prod-mg")
        enforcer.check_scope("management_group", "contoso-dev-mg")

        with pytest.raises(ScopeViolation):
            enforcer.check_scope("management_group", "fabrikam-prod-mg")

    def test_regex_patterns(self) -> None:
        """Test regex pattern matching."""
        config = GuardrailsConfig(
            allowed_subscriptions=[r"^[0-9a-f]{8}-prod-.*"],
            denied_subscriptions=[],
        )
        enforcer = GuardrailEnforcer(config)

        enforcer.check_scope("subscription", "12345678-prod-eastus")

        with pytest.raises(ScopeViolation):
            enforcer.check_scope("subscription", "12345678-dev-eastus")

    def test_case_insensitive_matching(self) -> None:
        """Test that scope matching is case-insensitive."""
        config = GuardrailsConfig(
            allowed_management_groups=["Prod-MG"],
            denied_management_groups=[],
        )
        enforcer = GuardrailEnforcer(config)

        enforcer.check_scope("management_group", "PROD-MG")
        enforcer.check_scope("management_group", "prod-mg")
        enforcer.check_scope("management_group", "Prod-MG")


class TestRateLimiting:
    """Tests for rate limiting functionality."""

    def test_under_limit_passes(self) -> None:
        """Test that changes under limit pass."""
        config = GuardrailsConfig(
            max_rbac_changes_per_interval=10,
            max_policy_changes_per_interval=5,
            max_resource_changes_per_interval=50,
        )
        enforcer = GuardrailEnforcer(config)

        # Should not raise
        enforcer.check_rate_limit(rbac_changes=5, policy_changes=2, resource_changes=25)

    def test_over_rbac_limit_fails(self) -> None:
        """Test that exceeding RBAC limit raises."""
        config = GuardrailsConfig(max_rbac_changes_per_interval=5)
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(RateLimitViolation) as exc_info:
            enforcer.check_rate_limit(rbac_changes=10)

        assert "RBAC changes" in str(exc_info.value)

    def test_over_policy_limit_fails(self) -> None:
        """Test that exceeding policy limit raises."""
        config = GuardrailsConfig(max_policy_changes_per_interval=5)
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(RateLimitViolation) as exc_info:
            enforcer.check_rate_limit(policy_changes=10)

        assert "Policy changes" in str(exc_info.value)

    def test_over_resource_limit_fails(self) -> None:
        """Test that exceeding resource limit raises."""
        config = GuardrailsConfig(max_resource_changes_per_interval=10)
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(RateLimitViolation) as exc_info:
            enforcer.check_rate_limit(resource_changes=20)

        assert "Resource changes" in str(exc_info.value)

    def test_cumulative_counting(self) -> None:
        """Test that changes accumulate across calls."""
        config = GuardrailsConfig(max_rbac_changes_per_interval=10)
        enforcer = GuardrailEnforcer(config)

        # First batch passes
        enforcer.check_rate_limit(rbac_changes=5)
        enforcer.record_changes(rbac_changes=5)

        # Second batch passes (at limit)
        enforcer.check_rate_limit(rbac_changes=5)
        enforcer.record_changes(rbac_changes=5)

        # Third batch fails (over limit)
        with pytest.raises(RateLimitViolation):
            enforcer.check_rate_limit(rbac_changes=1)

    def test_cooldown_blocks_all_changes(self) -> None:
        """Test that cooldown blocks all changes."""
        config = GuardrailsConfig(
            max_rbac_changes_per_interval=5,
            rate_limit_cooldown_seconds=3600,
        )
        enforcer = GuardrailEnforcer(config)

        # Exceed limit to enter cooldown
        with pytest.raises(RateLimitViolation):
            enforcer.check_rate_limit(rbac_changes=10)

        # Even small changes are blocked during cooldown
        with pytest.raises(RateLimitViolation) as exc_info:
            enforcer.check_rate_limit(rbac_changes=1)

        assert "cooldown" in str(exc_info.value).lower()

    def test_cooldown_expires(self) -> None:
        """Test that cooldown eventually expires."""
        config = GuardrailsConfig(
            max_rbac_changes_per_interval=5,
            rate_limit_cooldown_seconds=60,
        )
        enforcer = GuardrailEnforcer(config)

        # Exceed limit to enter cooldown
        with pytest.raises(RateLimitViolation):
            enforcer.check_rate_limit(rbac_changes=10)

        # Manually expire cooldown
        enforcer._rate_limit_state.cooldown_until = datetime.now(UTC) - timedelta(seconds=1)

        # Should now pass (state reset)
        enforcer.check_rate_limit(rbac_changes=1)

    def test_record_changes_updates_state(self) -> None:
        """Test that record_changes updates internal state."""
        config = GuardrailsConfig()
        enforcer = GuardrailEnforcer(config)

        enforcer.record_changes(rbac_changes=3, policy_changes=2, resource_changes=10)

        state = enforcer._rate_limit_state
        assert state.counts[ChangeCategory.RBAC] == 3
        assert state.counts[ChangeCategory.POLICY] == 2
        assert state.counts[ChangeCategory.RESOURCE] == 10

    def test_record_changes_accumulates(self) -> None:
        """Test that record_changes accumulates values."""
        config = GuardrailsConfig()
        enforcer = GuardrailEnforcer(config)

        enforcer.record_changes(rbac_changes=3)
        enforcer.record_changes(rbac_changes=5)

        assert enforcer._rate_limit_state.counts[ChangeCategory.RBAC] == 8


class TestWhatIfReliability:
    """Tests for WhatIf reliability detection."""

    def test_low_ignore_count_passes(self) -> None:
        """Test that low Ignore count passes."""
        config = GuardrailsConfig(
            max_whatif_ignore_count=10,
            fail_closed_on_whatif_degradation=True,
        )
        enforcer = GuardrailEnforcer(config)

        # Should not raise
        enforcer.check_whatif_reliability(ignore_count=5, total_count=100)

    def test_high_ignore_count_fails_closed(self) -> None:
        """Test that high Ignore count fails when fail_closed is True."""
        config = GuardrailsConfig(
            max_whatif_ignore_count=10,
            fail_closed_on_whatif_degradation=True,
        )
        enforcer = GuardrailEnforcer(config)

        with pytest.raises(GuardrailViolation) as exc_info:
            enforcer.check_whatif_reliability(ignore_count=15, total_count=100)

        assert "WhatIf returned 15 Ignore results" in str(exc_info.value)
        assert "FAIL_CLOSED_ON_WHATIF_DEGRADATION=false" in str(exc_info.value)

    def test_high_ignore_count_logs_when_fail_open(self) -> None:
        """Test that high Ignore count only logs when fail_closed is False."""
        config = GuardrailsConfig(
            max_whatif_ignore_count=10,
            fail_closed_on_whatif_degradation=False,
        )
        enforcer = GuardrailEnforcer(config)

        # Should not raise (just logs)
        enforcer.check_whatif_reliability(ignore_count=15, total_count=100)

    def test_at_threshold_passes(self) -> None:
        """Test that exactly at threshold passes."""
        config = GuardrailsConfig(max_whatif_ignore_count=10)
        enforcer = GuardrailEnforcer(config)

        # At threshold, should pass
        enforcer.check_whatif_reliability(ignore_count=10, total_count=100)


class TestRateLimitState:
    """Tests for RateLimitState dataclass."""

    def test_default_state(self) -> None:
        """Test default state values."""
        state = RateLimitState()

        assert state.counts == {}
        assert state.cooldown_until is None
        assert state.window_start is not None

    def test_reset_clears_state(self) -> None:
        """Test that reset clears all state."""
        state = RateLimitState()
        state.counts[ChangeCategory.RBAC] = 5
        state.cooldown_until = datetime.now(UTC)

        state.reset()

        assert state.counts == {}
        assert state.cooldown_until is None


class TestExceptionHierarchy:
    """Tests for exception class hierarchy."""

    def test_scope_violation_is_guardrail_violation(self) -> None:
        """Test that ScopeViolation inherits from GuardrailViolation."""
        exc = ScopeViolation("test")
        assert isinstance(exc, GuardrailViolation)

    def test_rate_limit_violation_is_guardrail_violation(self) -> None:
        """Test that RateLimitViolation inherits from GuardrailViolation."""
        exc = RateLimitViolation("test")
        assert isinstance(exc, GuardrailViolation)

    def test_kill_switch_active_is_guardrail_violation(self) -> None:
        """Test that KillSwitchActive inherits from GuardrailViolation."""
        exc = KillSwitchActive("test")
        assert isinstance(exc, GuardrailViolation)
