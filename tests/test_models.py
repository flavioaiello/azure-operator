"""Tests for the Pydantic models."""

import pytest
from pydantic import ValidationError

from controller.models import (
    ConnectivitySpec,
    IdentitySpec,
    ManagementSpec,
    SecuritySpec,
    get_spec_class,
)


class TestManagementSpec:
    """Tests for ManagementSpec model."""

    def test_valid_spec(self) -> None:
        """Test parsing a valid management spec."""
        data = {
            "location": "westeurope",
            "resourceGroupName": "rg-test",
            "logAnalytics": {
                "name": "law-test",
                "retentionDays": 365,
                "sku": "PerGB2018",
            },
            "tags": {"env": "test"},
        }
        spec = ManagementSpec.model_validate(data)

        assert spec.location == "westeurope"
        assert spec.resource_group_name == "rg-test"
        assert spec.log_analytics.name == "law-test"
        assert spec.log_analytics.retention_days == 365
        assert spec.tags == {"env": "test"}

    def test_missing_required_field(self) -> None:
        """Test that missing logAnalytics raises validation error."""
        data = {
            "location": "westeurope",
            "resourceGroupName": "rg-test",
        }
        with pytest.raises(ValidationError) as exc_info:
            ManagementSpec.model_validate(data)

        assert "logAnalytics" in str(exc_info.value)

    def test_invalid_retention_days(self) -> None:
        """Test that retention days out of range raises error."""
        data = {
            "location": "westeurope",
            "logAnalytics": {
                "name": "law-test",
                "retentionDays": 10,  # Below minimum of 30
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            ManagementSpec.model_validate(data)

        assert "retentionDays" in str(exc_info.value) or "retention" in str(exc_info.value).lower()

    def test_invalid_sku(self) -> None:
        """Test that invalid SKU raises validation error."""
        data = {
            "logAnalytics": {
                "name": "law-test",
                "sku": "InvalidSku",
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            ManagementSpec.model_validate(data)

        assert "sku" in str(exc_info.value).lower()

    def test_to_arm_parameters(self) -> None:
        """Test ARM parameter conversion."""
        data = {
            "location": "westeurope",
            "resourceGroupName": "rg-test",
            "logAnalytics": {
                "name": "law-test",
                "retentionDays": 90,
                "sku": "PerGB2018",
            },
        }
        spec = ManagementSpec.model_validate(data)
        params = spec.to_arm_parameters()

        assert params["location"]["value"] == "westeurope"
        assert params["resourceGroupName"]["value"] == "rg-test"
        assert params["logAnalyticsName"]["value"] == "law-test"
        assert params["logAnalyticsRetentionDays"]["value"] == 90


class TestConnectivitySpec:
    """Tests for ConnectivitySpec model."""

    def test_valid_spec(self) -> None:
        """Test parsing a valid connectivity spec."""
        data = {
            "location": "westeurope",
            "resourceGroupName": "rg-connectivity",
            "hub": {
                "name": "vnet-hub",
                "addressSpace": "10.0.0.0/16",
                "subnets": [
                    {"name": "AzureFirewallSubnet", "addressPrefix": "10.0.0.0/24"},
                ],
            },
            "firewall": {
                "enabled": True,
                "name": "afw-hub",
                "sku": "Standard",
            },
        }
        spec = ConnectivitySpec.model_validate(data)

        assert spec.hub.name == "vnet-hub"
        assert spec.hub.address_space == "10.0.0.0/16"
        assert len(spec.hub.subnets) == 1
        assert spec.firewall.enabled is True

    def test_invalid_cidr(self) -> None:
        """Test that invalid CIDR notation raises error."""
        data = {
            "hub": {
                "name": "vnet-hub",
                "addressSpace": "10.0.0.0",  # Missing /prefix
            },
        }
        with pytest.raises(ValidationError):
            ConnectivitySpec.model_validate(data)

    def test_extra_field_ignored(self) -> None:
        """Test that extra fields are ignored (ignore mode for forward compatibility)."""
        data = {
            "hub": {
                "name": "vnet-hub",
                "addressSpace": "10.0.0.0/16",
                "unknownField": "value",  # Should be ignored
            },
        }
        # Extra fields are now ignored for forward compatibility
        spec = ConnectivitySpec.model_validate(data)
        assert spec.hub.name == "vnet-hub"


class TestPolicySpec:
    """Tests for PolicySpec model."""

    def test_valid_spec(self) -> None:
        """Test parsing a valid policy spec."""
        from controller.models import PolicySpec

        data = {
            "managementGroupId": "alz-root",
            "managementGroups": [
                {
                    "name": "alz-platform",
                    "displayName": "Platform",
                    "parentId": "alz-root",
                },
            ],
        }
        spec = PolicySpec.model_validate(data)

        assert spec.root_management_group_name == "alz-root"
        assert len(spec.management_groups) == 1
        assert spec.management_groups[0].name == "alz-platform"


class TestSecuritySpec:
    """Tests for SecuritySpec model."""

    def test_valid_spec(self) -> None:
        """Test parsing a valid security spec."""
        data = {
            "location": "westeurope",
            "resourceGroupName": "rg-security",
            "defender": {
                "pricingTier": "Standard",
                "plans": ["VirtualMachines", "KeyVaults"],
            },
            "keyVaults": [
                {
                    "name": "kv-test-001",
                    "sku": "premium",
                },
            ],
        }
        spec = SecuritySpec.model_validate(data)

        assert spec.defender.pricing_tier == "Standard"
        assert len(spec.defender.plans) == 2
        assert len(spec.key_vaults) == 1
        assert spec.key_vaults[0].name == "kv-test-001"


class TestIdentitySpec:
    """Tests for IdentitySpec model."""

    def test_empty_spec_valid(self) -> None:
        """Test that identity spec with no roles is valid."""
        data: dict = {}
        spec = IdentitySpec.model_validate(data)

        assert spec.custom_roles == []
        assert spec.role_assignments == []


class TestSpecRegistry:
    """Tests for spec class registry - granular operators."""

    def test_get_known_domain(self) -> None:
        """Test getting spec class for known domains (granular operators)."""
        # Hub-Spoke connectivity operators
        from controller.models import (
            BastionSpec,
            DnsSpec,
            ExpressRouteSpec,
            FirewallSpec,
            HubNetworkSpec,
            VpnGatewaySpec,
        )

        assert get_spec_class("firewall") is FirewallSpec
        assert get_spec_class("bastion") is BastionSpec
        assert get_spec_class("dns") is DnsSpec
        assert get_spec_class("hub-network") is HubNetworkSpec
        assert get_spec_class("vpn-gateway") is VpnGatewaySpec
        assert get_spec_class("expressroute") is ExpressRouteSpec

        # vWAN per-resource operators
        from controller.models import (
            VwanExpressRouteSpec,
            VwanFirewallSpec,
            VwanHubSpec,
            VwanSpec,
            VwanVpnGatewaySpec,
        )

        assert get_spec_class("vwan") is VwanSpec
        assert get_spec_class("vwan-hub") is VwanHubSpec
        assert get_spec_class("vwan-firewall") is VwanFirewallSpec
        assert get_spec_class("vwan-vpn-gateway") is VwanVpnGatewaySpec
        assert get_spec_class("vwan-expressroute") is VwanExpressRouteSpec

        # Management operators
        from controller.models import AutomationSpec, LogAnalyticsSpec, MonitorSpec

        assert get_spec_class("log-analytics") is LogAnalyticsSpec
        assert get_spec_class("automation") is AutomationSpec
        assert get_spec_class("monitor") is MonitorSpec

        # Security operators
        from controller.models import DefenderSpec, KeyVaultSpec, SentinelSpec

        assert get_spec_class("defender") is DefenderSpec
        assert get_spec_class("keyvault") is KeyVaultSpec
        assert get_spec_class("sentinel") is SentinelSpec

        # Governance operators
        from controller.models import ManagementGroupSpec, PolicySpec, RoleSpec

        assert get_spec_class("management-group") is ManagementGroupSpec
        assert get_spec_class("policy") is PolicySpec
        assert get_spec_class("role") is RoleSpec

    def test_get_unknown_domain(self) -> None:
        """Test that unknown domain raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_spec_class("unknown")

        assert "unknown" in str(exc_info.value).lower()

    def test_legacy_domains_removed(self) -> None:
        """Test that legacy bundled domain specs are not in registry."""
        # These legacy specs bundled multiple resources and were replaced
        # by granular per-resource operators
        with pytest.raises(ValueError):
            get_spec_class("management")  # Use log-analytics, automation, monitor
        with pytest.raises(ValueError):
            get_spec_class("connectivity")  # Use hub-network, firewall, etc.
        with pytest.raises(ValueError):
            get_spec_class("security")  # Use defender, keyvault, sentinel
        with pytest.raises(ValueError):
            get_spec_class("identity")  # Use role operator


class TestRoleAssignmentDefinitionSecurity:
    """Tests for RoleAssignmentDefinition security validators.
    
    These tests verify that bootstrap RBAC definitions enforce:
    1. No high-privilege roles (Owner, User Access Administrator, Contributor)
    2. No overly broad scopes (tenant root, root management group)
    """

    def test_deny_owner_role(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that Owner role is denied by default."""
        from controller.models import RoleAssignmentDefinition

        # Ensure env override is not set
        monkeypatch.delenv("ALLOW_HIGH_PRIVILEGE_ROLES", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            RoleAssignmentDefinition(
                scope="/subscriptions/00000000-1111-2222-3333-444444444444",
                role_definition_name="Owner",
            )

        assert "Owner" in str(exc_info.value)
        assert "high-privilege" in str(exc_info.value).lower()

    def test_deny_user_access_administrator_role(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that User Access Administrator role is denied by default."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_HIGH_PRIVILEGE_ROLES", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            RoleAssignmentDefinition(
                scope="/subscriptions/00000000-1111-2222-3333-444444444444",
                role_definition_name="User Access Administrator",
            )

        assert "User Access Administrator" in str(exc_info.value)

    def test_deny_contributor_role(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that Contributor role is denied by default."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_HIGH_PRIVILEGE_ROLES", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            RoleAssignmentDefinition(
                scope="/subscriptions/00000000-1111-2222-3333-444444444444",
                role_definition_name="Contributor",
            )

        assert "Contributor" in str(exc_info.value)

    def test_allow_high_privilege_with_env_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that env override allows high-privilege roles."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.setenv("ALLOW_HIGH_PRIVILEGE_ROLES", "true")

        # Should not raise with override
        role = RoleAssignmentDefinition(
            scope="/subscriptions/00000000-1111-2222-3333-444444444444",
            role_definition_name="Owner",
        )
        assert role.role_definition_name == "Owner"

    def test_allow_least_privilege_roles(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that least-privilege roles are allowed."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_HIGH_PRIVILEGE_ROLES", raising=False)

        # Reader role should be allowed
        role = RoleAssignmentDefinition(
            scope="/subscriptions/00000000-1111-2222-3333-444444444444",
            role_definition_name="Reader",
        )
        assert role.role_definition_name == "Reader"

    def test_deny_tenant_root_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that tenant root scope is denied by default."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_BROAD_RBAC_SCOPES", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            RoleAssignmentDefinition(
                scope="/",
                role_definition_name="Reader",
            )

        # The validation catches the '/' as tenant root
        assert "tenant root" in str(exc_info.value).lower() or "denied" in str(exc_info.value).lower()

    def test_deny_root_management_group_scope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that root management group scope is denied by default."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_BROAD_RBAC_SCOPES", raising=False)

        # Test with "Tenant Root Group" pattern in scope
        with pytest.raises(ValidationError) as exc_info:
            RoleAssignmentDefinition(
                scope="/providers/Microsoft.Management/managementGroups/Tenant Root Group",
                role_definition_name="Reader",
            )

        # Check it was rejected for root MG
        assert "root" in str(exc_info.value).lower() or "denied" in str(exc_info.value).lower()

    def test_allow_subscription_scope(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that subscription scope is allowed."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_BROAD_RBAC_SCOPES", raising=False)

        role = RoleAssignmentDefinition(
            scope="/subscriptions/00000000-1111-2222-3333-444444444444",
            role_definition_name="Reader",
        )
        assert role.scope == "/subscriptions/00000000-1111-2222-3333-444444444444"

    def test_allow_resource_group_scope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that resource group scope is allowed."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_BROAD_RBAC_SCOPES", raising=False)
        monkeypatch.delenv("ALLOW_HIGH_PRIVILEGE_ROLES", raising=False)

        role = RoleAssignmentDefinition(
            scope="/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-test",
            role_definition_name="Reader",
        )
        assert "resourceGroups" in role.scope

    def test_allow_broad_scope_with_env_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that env override allows broad scopes."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.setenv("ALLOW_BROAD_RBAC_SCOPES", "true")

        # Root scope should be allowed with override
        role = RoleAssignmentDefinition(
            scope="/",
            role_definition_name="Reader",
        )
        assert role.scope == "/"

    def test_child_management_group_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that child management groups are allowed."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_BROAD_RBAC_SCOPES", raising=False)

        # Child MG (not matching root patterns)
        role = RoleAssignmentDefinition(
            scope="/providers/Microsoft.Management/managementGroups/mg-landing-zones",
            role_definition_name="Reader",
        )
        assert "mg-landing-zones" in role.scope

    def test_network_contributor_allowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that specific service roles are allowed (least privilege)."""
        from controller.models import RoleAssignmentDefinition

        monkeypatch.delenv("ALLOW_HIGH_PRIVILEGE_ROLES", raising=False)

        # Network Contributor is a service-specific role, not high-privilege
        role = RoleAssignmentDefinition(
            scope="/subscriptions/00000000-1111-2222-3333-444444444444",
            role_definition_name="Network Contributor",
        )
        assert role.role_definition_name == "Network Contributor"
