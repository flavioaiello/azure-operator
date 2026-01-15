"""Tests for per-resource mode overrides."""

from __future__ import annotations

import pytest

from controller.config import ReconciliationMode
from controller.resource_modes import (
    HIGH_RISK_RESOURCE_TYPES,
    LOW_RISK_RESOURCE_TYPES,
    ModeResolver,
    ResourceModeOverride,
    SpecModeConfig,
    create_mode_resolver_from_env,
)


class TestResourceModeOverride:
    """Tests for ResourceModeOverride matching."""

    def test_matches_resource_type_exact(self) -> None:
        """Test exact resource type matching."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": ["Microsoft.Network/virtualNetworks"],
            "mode": "protect",
        })

        assert override.matches("Microsoft.Network/virtualNetworks") is True
        assert override.matches("Microsoft.Network/networkSecurityGroups") is False

    def test_matches_resource_type_wildcard(self) -> None:
        """Test wildcard resource type matching."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": ["Microsoft.Network/*"],
            "mode": "observe",
        })

        assert override.matches("Microsoft.Network/virtualNetworks") is True
        assert override.matches("Microsoft.Network/networkSecurityGroups") is True
        assert override.matches("Microsoft.Compute/virtualMachines") is False

    def test_matches_resource_type_nested_wildcard(self) -> None:
        """Test nested wildcard matching."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": ["Microsoft.KeyVault/vaults/*"],
            "mode": "protect",
        })

        assert override.matches("Microsoft.KeyVault/vaults/secrets") is True
        assert override.matches("Microsoft.KeyVault/vaults/keys") is True
        assert override.matches("Microsoft.KeyVault/vaults") is False

    def test_matches_resource_group(self) -> None:
        """Test resource group matching."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": ["*"],
            "resourceGroups": ["rg-production-*"],
            "mode": "protect",
        })

        assert override.matches(
            "Microsoft.Network/virtualNetworks",
            resource_group="rg-production-hub",
        ) is True
        assert override.matches(
            "Microsoft.Network/virtualNetworks",
            resource_group="rg-dev-hub",
        ) is False

    def test_matches_subscription(self) -> None:
        """Test subscription matching."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": ["*"],
            "subscriptions": ["00000000-0000-0000-0000-000000000001"],
            "mode": "observe",
        })

        assert override.matches(
            "Microsoft.Network/virtualNetworks",
            subscription_id="00000000-0000-0000-0000-000000000001",
        ) is True
        assert override.matches(
            "Microsoft.Network/virtualNetworks",
            subscription_id="00000000-0000-0000-0000-000000000002",
        ) is False

    def test_matches_resource_name(self) -> None:
        """Test resource name matching."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": ["Microsoft.Network/virtualNetworks"],
            "resourceNames": ["vnet-hub-*"],
            "mode": "enforce",
        })

        assert override.matches(
            "Microsoft.Network/virtualNetworks",
            resource_name="vnet-hub-eastus",
        ) is True
        assert override.matches(
            "Microsoft.Network/virtualNetworks",
            resource_name="vnet-spoke-eastus",
        ) is False

    def test_matches_case_insensitive(self) -> None:
        """Test case-insensitive matching."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": ["microsoft.network/virtualnetworks"],
            "mode": "protect",
        })

        assert override.matches("Microsoft.Network/VirtualNetworks") is True

    def test_matches_no_criteria_returns_false(self) -> None:
        """Test that no criteria means no match."""
        override = ResourceModeOverride.model_validate({
            "resourceTypes": [],
            "mode": "protect",
        })

        assert override.matches("Microsoft.Network/virtualNetworks") is False


class TestSpecModeConfig:
    """Tests for SpecModeConfig."""

    def test_parse_from_dict(self) -> None:
        """Test parsing SpecModeConfig from dict."""
        config = SpecModeConfig.model_validate({
            "defaultMode": "observe",
            "overrides": [
                {
                    "resourceTypes": ["Microsoft.Authorization/roleAssignments"],
                    "mode": "protect",
                    "reason": "RBAC is critical",
                }
            ],
            "allowEscalation": False,
        })

        assert config.default_mode == ReconciliationMode.OBSERVE
        assert len(config.overrides) == 1
        assert config.overrides[0].mode == ReconciliationMode.PROTECT
        assert config.allow_escalation is False

    def test_defaults(self) -> None:
        """Test default values."""
        config = SpecModeConfig()

        assert config.default_mode is None
        assert config.overrides == []
        assert config.allow_escalation is False


class TestModeResolver:
    """Tests for ModeResolver."""

    @pytest.fixture
    def resolver_observe(self) -> ModeResolver:
        """Create resolver with global OBSERVE mode."""
        return ModeResolver(
            global_mode=ReconciliationMode.OBSERVE,
            auto_protect_high_risk=False,
        )

    @pytest.fixture
    def resolver_enforce(self) -> ModeResolver:
        """Create resolver with global ENFORCE mode."""
        return ModeResolver(
            global_mode=ReconciliationMode.ENFORCE,
            auto_protect_high_risk=False,
        )

    @pytest.fixture
    def resolver_with_auto_protect(self) -> ModeResolver:
        """Create resolver with auto-protect enabled."""
        return ModeResolver(
            global_mode=ReconciliationMode.OBSERVE,
            auto_protect_high_risk=True,
        )

    def test_uses_global_mode_by_default(self, resolver_observe: ModeResolver) -> None:
        """Test that global mode is used when no overrides."""
        result = resolver_observe.resolve("Microsoft.Network/virtualNetworks")

        assert result.effective_mode == ReconciliationMode.OBSERVE
        assert result.rule_matched is None
        assert "Global mode" in result.reason

    def test_spec_default_mode_overrides_global(self, resolver_observe: ModeResolver) -> None:
        """Test spec-level default mode overrides global."""
        spec_config = SpecModeConfig(default_mode=ReconciliationMode.ENFORCE)

        result = resolver_observe.resolve(
            "Microsoft.Network/virtualNetworks",
            spec_mode_config=spec_config,
        )

        # Escalation blocked by default
        assert result.effective_mode == ReconciliationMode.OBSERVE

    def test_spec_default_mode_with_escalation(self) -> None:
        """Test spec default mode with escalation allowed."""
        resolver = ModeResolver(
            global_mode=ReconciliationMode.OBSERVE,
            allow_spec_escalation=True,
            auto_protect_high_risk=False,
        )
        spec_config = SpecModeConfig.model_validate({"defaultMode": "enforce"})

        result = resolver.resolve(
            "Microsoft.Network/virtualNetworks",
            spec_mode_config=spec_config,
        )

        assert result.effective_mode == ReconciliationMode.ENFORCE

    def test_spec_override_matches_resource(self, resolver_enforce: ModeResolver) -> None:
        """Test spec-level override matching."""
        spec_config = SpecModeConfig.model_validate({
            "overrides": [
                {
                    "resourceTypes": ["Microsoft.Authorization/roleAssignments"],
                    "mode": "protect",
                    "reason": "RBAC changes need review",
                }
            ]
        })

        # Match
        result = resolver_enforce.resolve(
            "Microsoft.Authorization/roleAssignments",
            spec_mode_config=spec_config,
        )
        assert result.effective_mode == ReconciliationMode.PROTECT
        assert "RBAC changes need review" in result.reason

        # No match
        result = resolver_enforce.resolve(
            "Microsoft.Network/virtualNetworks",
            spec_mode_config=spec_config,
        )
        assert result.effective_mode == ReconciliationMode.ENFORCE

    def test_auto_protect_high_risk_resources(
        self, resolver_with_auto_protect: ModeResolver
    ) -> None:
        """Test auto-protect for high-risk resource types."""
        # High-risk resource should be protected
        result = resolver_with_auto_protect.resolve(
            "Microsoft.Authorization/roleAssignments"
        )
        assert result.effective_mode == ReconciliationMode.PROTECT
        assert "Auto-protect high-risk" in result.reason

        # Low-risk resource should use global mode
        result = resolver_with_auto_protect.resolve(
            "Microsoft.Network/virtualNetworks"
        )
        assert result.effective_mode == ReconciliationMode.OBSERVE

    def test_global_override_takes_precedence(self) -> None:
        """Test that global overrides take precedence over spec overrides."""
        resolver = ModeResolver(
            global_mode=ReconciliationMode.OBSERVE,
            global_overrides=[
                ResourceModeOverride.model_validate({
                    "resourceTypes": ["Microsoft.Authorization/*"],
                    "mode": "protect",
                    "reason": "Global policy: protect all authz",
                })
            ],
            auto_protect_high_risk=False,
        )

        result = resolver.resolve("Microsoft.Authorization/roleAssignments")
        assert result.effective_mode == ReconciliationMode.PROTECT
        assert "Global policy" in result.reason

    def test_restrict_action_only_makes_more_restrictive(self) -> None:
        """Test RESTRICT action only increases restriction."""
        resolver = ModeResolver(
            global_mode=ReconciliationMode.OBSERVE,
            global_overrides=[
                ResourceModeOverride.model_validate({
                    "resourceTypes": ["*"],
                    "mode": "enforce",
                    "action": "restrict",
                })
            ],
            auto_protect_high_risk=False,
        )

        # ENFORCE is less restrictive than OBSERVE, so no change
        result = resolver.resolve("Microsoft.Network/virtualNetworks")
        assert result.effective_mode == ReconciliationMode.OBSERVE

    def test_escalate_action_only_makes_less_restrictive(self) -> None:
        """Test ESCALATE action only decreases restriction."""
        resolver = ModeResolver(
            global_mode=ReconciliationMode.OBSERVE,
            global_overrides=[
                ResourceModeOverride.model_validate({
                    "resourceTypes": ["Microsoft.Insights/*"],
                    "mode": "enforce",
                    "action": "escalate",
                })
            ],
            auto_protect_high_risk=False,
            allow_spec_escalation=False,
        )

        # Global overrides can always escalate
        result = resolver.resolve("Microsoft.Insights/diagnosticSettings")
        assert result.effective_mode == ReconciliationMode.ENFORCE


class TestHighRiskResourceTypes:
    """Tests for HIGH_RISK_RESOURCE_TYPES constant."""

    def test_includes_role_assignments(self) -> None:
        """Test that role assignments are high-risk."""
        assert "Microsoft.Authorization/roleAssignments" in HIGH_RISK_RESOURCE_TYPES

    def test_includes_firewalls(self) -> None:
        """Test that firewalls are high-risk."""
        assert "Microsoft.Network/azureFirewalls" in HIGH_RISK_RESOURCE_TYPES

    def test_includes_key_vaults(self) -> None:
        """Test that Key Vaults are high-risk."""
        assert "Microsoft.KeyVault/vaults" in HIGH_RISK_RESOURCE_TYPES


class TestLowRiskResourceTypes:
    """Tests for LOW_RISK_RESOURCE_TYPES constant."""

    def test_includes_diagnostic_settings(self) -> None:
        """Test that diagnostic settings are low-risk."""
        assert "Microsoft.Insights/diagnosticSettings" in LOW_RISK_RESOURCE_TYPES

    def test_includes_private_dns_zones(self) -> None:
        """Test that private DNS zones are low-risk."""
        assert "Microsoft.Network/privateDnsZones" in LOW_RISK_RESOURCE_TYPES


class TestCreateModeResolverFromEnv:
    """Tests for create_mode_resolver_from_env function."""

    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test default values."""
        for var in ["AUTO_PROTECT_HIGH_RISK", "ALLOW_SPEC_ESCALATION", "GLOBAL_MODE_OVERRIDES"]:
            monkeypatch.delenv(var, raising=False)

        resolver = create_mode_resolver_from_env(ReconciliationMode.OBSERVE)

        assert resolver.global_mode == ReconciliationMode.OBSERVE
        assert resolver.auto_protect_high_risk is True
        assert resolver.allow_spec_escalation is False

    def test_disable_auto_protect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test disabling auto-protect."""
        monkeypatch.setenv("AUTO_PROTECT_HIGH_RISK", "false")

        resolver = create_mode_resolver_from_env(ReconciliationMode.OBSERVE)
        assert resolver.auto_protect_high_risk is False

    def test_enable_escalation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test enabling spec escalation."""
        monkeypatch.setenv("ALLOW_SPEC_ESCALATION", "true")

        resolver = create_mode_resolver_from_env(ReconciliationMode.OBSERVE)
        assert resolver.allow_spec_escalation is True

    def test_parse_global_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test parsing global overrides from JSON."""
        overrides_json = """[
            {"resourceTypes": ["Microsoft.Authorization/*"], "mode": "protect"}
        ]"""
        monkeypatch.setenv("GLOBAL_MODE_OVERRIDES", overrides_json)

        resolver = create_mode_resolver_from_env(ReconciliationMode.OBSERVE)
        assert len(resolver.global_overrides) == 1
        assert resolver.global_overrides[0].mode == ReconciliationMode.PROTECT
