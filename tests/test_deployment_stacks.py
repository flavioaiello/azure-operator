"""Tests for Deployment Stacks protection layer."""

from __future__ import annotations

import pytest

from controller.deployment_stacks import (
    DEFAULT_ACTION_ON_UNMANAGE,
    DEFAULT_DENY_MODE,
    HIGH_VALUE_DENY_DOMAINS,
    MG_SCOPE_DOMAINS,
    ActionOnUnmanage,
    DenySettingsMode,
    DeploymentScope,
    DeploymentStackManager,
    DeploymentStackSpec,
    StackMetadata,
    StackProtectionConfig,
    create_stack_manager_from_env,
    generate_stack_name,
    should_enable_stack_protection,
)


class TestDenySettingsMode:
    """Tests for DenySettingsMode enum."""

    def test_deny_write_and_delete_is_default(self) -> None:
        """Verify strictest mode is default."""
        assert DEFAULT_DENY_MODE == DenySettingsMode.DENY_WRITE_AND_DELETE

    def test_all_modes_have_values(self) -> None:
        """Verify all modes have string values."""
        assert DenySettingsMode.NONE.value == "none"
        assert DenySettingsMode.DENY_DELETE.value == "denyDelete"
        assert DenySettingsMode.DENY_WRITE_AND_DELETE.value == "denyWriteAndDelete"


class TestActionOnUnmanage:
    """Tests for ActionOnUnmanage enum."""

    def test_detach_is_default(self) -> None:
        """Verify detach (safer) is default."""
        assert DEFAULT_ACTION_ON_UNMANAGE == ActionOnUnmanage.DETACH

    def test_all_actions_have_values(self) -> None:
        """Verify all actions have string values."""
        assert ActionOnUnmanage.DELETE.value == "delete"
        assert ActionOnUnmanage.DETACH.value == "detach"


class TestStackProtectionConfig:
    """Tests for StackProtectionConfig."""

    def test_defaults(self) -> None:
        """Test default configuration values."""
        config = StackProtectionConfig()

        assert config.enabled is True
        assert config.deny_mode == DenySettingsMode.DENY_WRITE_AND_DELETE
        assert config.action_on_unmanage_resources == ActionOnUnmanage.DETACH
        assert config.apply_to_child_scopes is True

    def test_from_dict_empty(self) -> None:
        """Test from_dict with None returns defaults."""
        config = StackProtectionConfig.from_dict(None)
        assert config.enabled is True

    def test_from_dict_with_values(self) -> None:
        """Test from_dict with explicit values."""
        data = {
            "enabled": False,
            "denyMode": "denyDelete",
            "actionOnUnmanageResources": "delete",
            "excludedActions": ["Microsoft.Resources/deployments/write"],
        }

        config = StackProtectionConfig.from_dict(data)

        assert config.enabled is False
        assert config.deny_mode == DenySettingsMode.DENY_DELETE
        assert config.action_on_unmanage_resources == ActionOnUnmanage.DELETE
        assert "Microsoft.Resources/deployments/write" in config.excluded_actions

    def test_from_env_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with no env vars."""
        for var in ["STACK_PROTECTION_ENABLED", "STACK_DENY_MODE", "STACK_ACTION_ON_UNMANAGE"]:
            monkeypatch.delenv(var, raising=False)

        config = StackProtectionConfig.from_env()

        assert config.enabled is True
        assert config.deny_mode == DenySettingsMode.DENY_WRITE_AND_DELETE

    def test_from_env_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with protection disabled."""
        monkeypatch.setenv("STACK_PROTECTION_ENABLED", "false")

        config = StackProtectionConfig.from_env()
        assert config.enabled is False

    def test_from_env_deny_delete_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test from_env with denyDelete mode."""
        monkeypatch.setenv("STACK_DENY_MODE", "denyDelete")

        config = StackProtectionConfig.from_env()
        assert config.deny_mode == DenySettingsMode.DENY_DELETE

    def test_to_deny_settings(self) -> None:
        """Test conversion to Azure deny settings format."""
        config = StackProtectionConfig(
            deny_mode=DenySettingsMode.DENY_WRITE_AND_DELETE,
            excluded_actions=("Microsoft.Resources/deployments/write",),
            apply_to_child_scopes=True,
        )

        settings = config.to_deny_settings(["principal-id-123"])

        assert settings["mode"] == "denyWriteAndDelete"
        assert "principal-id-123" in settings["excludedPrincipals"]
        assert "Microsoft.Resources/deployments/write" in settings["excludedActions"]
        assert settings["applyToChildScopes"] is True


class TestStackMetadata:
    """Tests for StackMetadata."""

    def test_to_tags(self) -> None:
        """Test conversion to Azure tags."""
        metadata = StackMetadata(
            operator_name="test-operator",
            domain="hub-network",
            spec_name="hub-westeurope",
            spec_version="abc123def456",
            commit_sha="1234567890abcdef",
            operator_version="1.0.0",
        )

        tags = metadata.to_tags()

        assert tags["azure-operator/managed"] == "true"
        assert tags["azure-operator/domain"] == "hub-network"
        assert tags["azure-operator/spec-name"] == "hub-westeurope"
        assert tags["azure-operator/spec-version"] == "abc123de"  # Truncated
        assert tags["azure-operator/commit-sha"] == "12345678"  # Truncated
        assert tags["azure-operator/operator-version"] == "1.0.0"

    def test_to_tags_without_optional(self) -> None:
        """Test tags without optional fields."""
        metadata = StackMetadata(
            operator_name="test-operator",
            domain="firewall",
            spec_name="fw-primary",
            spec_version="xyz789",
        )

        tags = metadata.to_tags()

        assert "azure-operator/managed" in tags
        assert "azure-operator/commit-sha" not in tags
        assert "azure-operator/operator-version" not in tags


class TestGenerateStackName:
    """Tests for generate_stack_name."""

    def test_deterministic(self) -> None:
        """Test name generation is deterministic."""
        name1 = generate_stack_name(
            operator_name="my-operator",
            domain="hub-network",
            subscription_id="12345678-1234-1234-1234-123456789012",
            spec_name="hub-westeurope",
        )
        name2 = generate_stack_name(
            operator_name="my-operator",
            domain="hub-network",
            subscription_id="12345678-1234-1234-1234-123456789012",
            spec_name="hub-westeurope",
        )

        assert name1 == name2

    def test_unique_per_spec(self) -> None:
        """Test different specs get different names."""
        name1 = generate_stack_name(
            operator_name="op",
            domain="hub-network",
            subscription_id="12345678-1234-1234-1234-123456789012",
            spec_name="hub-westeurope",
        )
        name2 = generate_stack_name(
            operator_name="op",
            domain="hub-network",
            subscription_id="12345678-1234-1234-1234-123456789012",
            spec_name="hub-eastus",  # Different spec
        )

        assert name1 != name2

    def test_valid_characters(self) -> None:
        """Test name contains only valid characters."""
        name = generate_stack_name(
            operator_name="my operator",  # Space
            domain="hub-network",
            subscription_id="12345678",
            spec_name="test_spec",  # Underscore
        )

        # Only alphanumeric and hyphens
        assert all(c.isalnum() or c == "-" for c in name)
        assert name.islower()

    def test_max_length(self) -> None:
        """Test name is under max length."""
        name = generate_stack_name(
            operator_name="very-long-operator-name-that-is-really-long",
            domain="hub-network-with-extra-stuff",
            subscription_id="12345678-1234-1234-1234-123456789012",
            spec_name="my-very-long-spec-name-in-westeurope-region",
        )

        assert len(name) <= 64


class TestShouldEnableStackProtection:
    """Tests for should_enable_stack_protection."""

    def test_mg_scope_disabled(self) -> None:
        """Test MG scope always disabled."""
        result = should_enable_stack_protection(
            domain="hub-network",  # Normally enabled
            scope=DeploymentScope.MANAGEMENT_GROUP,
        )

        assert result is False

    def test_mg_domain_disabled(self) -> None:
        """Test MG-scoped domains disabled."""
        for domain in MG_SCOPE_DOMAINS:
            result = should_enable_stack_protection(
                domain=domain,
                scope=DeploymentScope.SUBSCRIPTION,
            )
            assert result is False, f"Expected disabled for {domain}"

    def test_high_value_domains_enabled(self) -> None:
        """Test high-value domains enabled by default."""
        for domain in HIGH_VALUE_DENY_DOMAINS:
            result = should_enable_stack_protection(
                domain=domain,
                scope=DeploymentScope.SUBSCRIPTION,
            )
            assert result is True, f"Expected enabled for {domain}"

    def test_explicit_config_overrides(self) -> None:
        """Test explicit config overrides default behavior."""
        # Disable a normally-enabled domain
        config = StackProtectionConfig(enabled=False)
        result = should_enable_stack_protection(
            domain="hub-network",
            scope=DeploymentScope.SUBSCRIPTION,
            explicit_config=config,
        )
        assert result is False

        # Enable a normally-disabled domain
        config = StackProtectionConfig(enabled=True)
        result = should_enable_stack_protection(
            domain="log-analytics",
            scope=DeploymentScope.SUBSCRIPTION,
            explicit_config=config,
        )
        assert result is True

    def test_optional_domains_disabled_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test optional domains are disabled by default."""
        monkeypatch.delenv("STACK_PROTECTION_OPTIONAL_DOMAINS", raising=False)

        result = should_enable_stack_protection(
            domain="log-analytics",
            scope=DeploymentScope.SUBSCRIPTION,
        )

        assert result is False

    def test_optional_domains_enabled_via_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test optional domains can be enabled via env var."""
        monkeypatch.setenv("STACK_PROTECTION_OPTIONAL_DOMAINS", "true")

        result = should_enable_stack_protection(
            domain="log-analytics",
            scope=DeploymentScope.SUBSCRIPTION,
        )

        assert result is True


class TestDeploymentStackSpec:
    """Tests for DeploymentStackSpec."""

    @pytest.fixture
    def sample_spec(self) -> DeploymentStackSpec:
        """Create a sample Stack spec."""
        return DeploymentStackSpec(
            name="azop-hub-network-12345678-abc123",
            scope=DeploymentScope.SUBSCRIPTION,
            subscription_id="12345678-1234-1234-1234-123456789012",
            resource_group=None,
            management_group_id=None,
            location="westeurope",
            template={"$schema": "...", "resources": []},
            parameters={"location": {"value": "westeurope"}},
            protection_config=StackProtectionConfig(),
            metadata=StackMetadata(
                operator_name="test",
                domain="hub-network",
                spec_name="hub",
                spec_version="abc123",
            ),
            operator_principal_id="operator-principal-id",
        )

    def test_deny_supported_for_subscription(self, sample_spec: DeploymentStackSpec) -> None:
        """Test deny is supported for subscription scope."""
        assert sample_spec.deny_supported is True

    def test_deny_not_supported_for_mg(self) -> None:
        """Test deny is not supported for MG scope."""
        spec = DeploymentStackSpec(
            name="test",
            scope=DeploymentScope.MANAGEMENT_GROUP,
            subscription_id="",
            resource_group=None,
            management_group_id="my-mg",
            location="westeurope",
            template={},
            parameters={},
            protection_config=StackProtectionConfig(),
            metadata=StackMetadata(
                operator_name="test",
                domain="test",
                spec_name="test",
                spec_version="test",
            ),
            operator_principal_id="test",
        )

        assert spec.deny_supported is False

    def test_to_azure_payload(self, sample_spec: DeploymentStackSpec) -> None:
        """Test conversion to Azure API payload."""
        payload = sample_spec.to_azure_payload()

        assert payload["location"] == "westeurope"
        assert "azure-operator/managed" in payload["tags"]
        assert "template" in payload["properties"]
        assert "parameters" in payload["properties"]
        assert "actionOnUnmanage" in payload["properties"]
        assert "denySettings" in payload["properties"]

        # Verify operator is excluded from deny
        deny_settings = payload["properties"]["denySettings"]
        assert "operator-principal-id" in deny_settings["excludedPrincipals"]

    def test_to_azure_payload_no_deny_for_mg(self) -> None:
        """Test MG-scoped spec has no deny settings."""
        spec = DeploymentStackSpec(
            name="test",
            scope=DeploymentScope.MANAGEMENT_GROUP,
            subscription_id="",
            resource_group=None,
            management_group_id="my-mg",
            location="westeurope",
            template={},
            parameters={},
            protection_config=StackProtectionConfig(),
            metadata=StackMetadata(
                operator_name="test",
                domain="test",
                spec_name="test",
                spec_version="test",
            ),
            operator_principal_id="test",
        )

        payload = spec.to_azure_payload()

        assert "denySettings" not in payload["properties"]


class TestDeploymentStackManager:
    """Tests for DeploymentStackManager."""

    @pytest.fixture
    def manager(self) -> DeploymentStackManager:
        """Create a Stack manager for testing."""
        return DeploymentStackManager(
            operator_name="test-operator",
            operator_principal_id="test-principal-id",
        )

    def test_init_requires_operator_name(self) -> None:
        """Test operator_name is required."""
        with pytest.raises(ValueError, match="operator_name"):
            DeploymentStackManager(
                operator_name="",
                operator_principal_id="test",
            )

    def test_init_requires_principal_id(self) -> None:
        """Test operator_principal_id is required."""
        with pytest.raises(ValueError, match="operator_principal_id"):
            DeploymentStackManager(
                operator_name="test",
                operator_principal_id="",
            )

    def test_create_stack_spec_for_enabled_domain(
        self, manager: DeploymentStackManager
    ) -> None:
        """Test creating spec for enabled domain."""
        spec = manager.create_stack_spec(
            domain="hub-network",
            spec_name="hub-westeurope",
            spec_content_hash="abc123",
            scope=DeploymentScope.SUBSCRIPTION,
            subscription_id="12345678-1234-1234-1234-123456789012",
            location="westeurope",
            template={"resources": []},
            parameters={},
        )

        assert spec is not None
        assert spec.name.startswith("azop-hub-network-")
        assert spec.protection_config.enabled is True

    def test_create_stack_spec_returns_none_for_mg(
        self, manager: DeploymentStackManager
    ) -> None:
        """Test returns None for MG-scoped domain."""
        spec = manager.create_stack_spec(
            domain="management-group",
            spec_name="platform",
            spec_content_hash="abc123",
            scope=DeploymentScope.MANAGEMENT_GROUP,
            subscription_id="",
            location="westeurope",
            template={},
            parameters={},
            management_group_id="platform",
        )

        assert spec is None

    def test_create_stack_spec_tracks_stack(
        self, manager: DeploymentStackManager
    ) -> None:
        """Test created spec is tracked."""
        spec = manager.create_stack_spec(
            domain="firewall",
            spec_name="fw-primary",
            spec_content_hash="xyz789",
            scope=DeploymentScope.SUBSCRIPTION,
            subscription_id="11111111-1111-1111-1111-111111111111",
            location="eastus",
            template={},
            parameters={},
        )

        assert spec is not None
        assert manager.tracked_stack_count == 1
        assert spec.name in manager.list_tracked_stacks()

    def test_get_tracked_stack(self, manager: DeploymentStackManager) -> None:
        """Test retrieving tracked stack."""
        spec = manager.create_stack_spec(
            domain="hub-network",
            spec_name="hub",
            spec_content_hash="hash",
            scope=DeploymentScope.SUBSCRIPTION,
            subscription_id="12345678-1234-1234-1234-123456789012",
            location="westeurope",
            template={},
            parameters={},
        )

        retrieved = manager.get_tracked_stack(spec.name)
        assert retrieved is spec

    def test_remove_tracked_stack(self, manager: DeploymentStackManager) -> None:
        """Test removing tracked stack."""
        spec = manager.create_stack_spec(
            domain="hub-network",
            spec_name="hub",
            spec_content_hash="hash",
            scope=DeploymentScope.SUBSCRIPTION,
            subscription_id="12345678-1234-1234-1234-123456789012",
            location="westeurope",
            template={},
            parameters={},
        )

        assert manager.remove_tracked_stack(spec.name) is True
        assert manager.tracked_stack_count == 0


class TestCreateStackManagerFromEnv:
    """Tests for create_stack_manager_from_env."""

    def test_creates_manager(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test factory function creates manager."""
        # Clear env vars
        for var in ["STACK_PROTECTION_ENABLED", "STACK_DENY_MODE"]:
            monkeypatch.delenv(var, raising=False)

        manager = create_stack_manager_from_env(
            operator_name="my-operator",
            operator_principal_id="my-principal",
        )

        assert manager.operator_name == "my-operator"
        assert manager.operator_principal_id == "my-principal"
        assert manager.default_config.enabled is True


class TestHighValueDomains:
    """Tests for HIGH_VALUE_DENY_DOMAINS constant."""

    def test_includes_hub_network(self) -> None:
        """Hub network should be protected."""
        assert "hub-network" in HIGH_VALUE_DENY_DOMAINS

    def test_includes_firewall(self) -> None:
        """Firewall should be protected."""
        assert "firewall" in HIGH_VALUE_DENY_DOMAINS

    def test_includes_vpn_gateway(self) -> None:
        """VPN gateway should be protected."""
        assert "vpn-gateway" in HIGH_VALUE_DENY_DOMAINS

    def test_includes_vwan(self) -> None:
        """Virtual WAN should be protected."""
        assert "vwan" in HIGH_VALUE_DENY_DOMAINS


class TestMGScopeDomains:
    """Tests for MG_SCOPE_DOMAINS constant."""

    def test_includes_management_group(self) -> None:
        """Management group domain should be excluded."""
        assert "management-group" in MG_SCOPE_DOMAINS

    def test_includes_bootstrap(self) -> None:
        """Bootstrap domain should be excluded."""
        assert "bootstrap" in MG_SCOPE_DOMAINS
