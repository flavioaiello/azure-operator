"""Tests for bootstrap cascade functionality."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from controller.bootstrap import is_bootstrap_operator
from controller.models import (
    BootstrapSpec,
    OperatorIdentityConfig,
    RoleAssignmentDefinition,
    get_spec_class,
)


class TestBootstrapSpec:
    """Tests for BootstrapSpec model."""

    def test_valid_spec(self) -> None:
        """Test valid bootstrap spec loads correctly."""
        spec = BootstrapSpec.model_validate(
            {
                "location": "westeurope",
                "identityResourceGroup": "rg-operator-identities",
                "operators": [
                    {
                        "name": "firewall",
                        "scope": "subscription",
                        "subscriptionId": "00000000-0000-0000-0000-000000000000",
                        "roleAssignments": [
                            {
                                "roleDefinitionName": "Network Contributor",
                                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                            }
                        ],
                    }
                ],
            }
        )
        assert spec.location == "westeurope"
        assert spec.identity_resource_group == "rg-operator-identities"
        assert len(spec.operators) == 1
        assert spec.operators[0].name == "firewall"

    def test_missing_identity_resource_group(self) -> None:
        """Test that identity_resource_group is required."""
        with pytest.raises(ValidationError) as exc_info:
            BootstrapSpec.model_validate(
                {
                    "location": "westeurope",
                    "operators": [],
                }
            )
        assert "identityResourceGroup" in str(exc_info.value)

    def test_default_values(self) -> None:
        """Test default values are applied correctly."""
        spec = BootstrapSpec.model_validate(
            {
                "location": "westeurope",
                "identityResourceGroup": "rg-identities",
                "operators": [],
            }
        )
        assert spec.rbac_propagation_seconds == 120
        assert spec.deploy_operators is True
        assert spec.operator_image_tag == "latest"

    def test_to_arm_parameters(self) -> None:
        """Test ARM parameter conversion."""
        spec = BootstrapSpec.model_validate(
            {
                "location": "westeurope",
                "identityResourceGroup": "rg-identities",
                "containerRegistry": "myacr.azurecr.io",
                "operators": [
                    {
                        "name": "firewall",
                        "scope": "subscription",
                        "subscriptionId": "sub-id",
                        "roleAssignments": [
                            {
                                "roleDefinitionName": "Network Contributor",
                                "scope": "/subscriptions/sub-id",
                            }
                        ],
                    }
                ],
            }
        )
        params = spec.to_arm_parameters()

        assert params["location"]["value"] == "westeurope"
        assert params["identityResourceGroup"]["value"] == "rg-identities"
        assert params["containerRegistry"]["value"] == "myacr.azurecr.io"
        assert len(params["operators"]["value"]) == 1
        assert params["operators"]["value"][0]["name"] == "firewall"


class TestOperatorIdentityConfig:
    """Tests for OperatorIdentityConfig model."""

    def test_valid_subscription_scope(self) -> None:
        """Test valid subscription-scoped operator."""
        config = OperatorIdentityConfig.model_validate(
            {
                "name": "firewall",
                "scope": "subscription",
                "subscriptionId": "00000000-0000-0000-0000-000000000000",
            }
        )
        assert config.scope == "subscription"
        assert config.subscription_id == "00000000-0000-0000-0000-000000000000"

    def test_valid_management_group_scope(self) -> None:
        """Test valid management-group-scoped operator."""
        config = OperatorIdentityConfig.model_validate(
            {
                "name": "management-group",
                "scope": "management_group",
                "managementGroupId": "root-mg",
            }
        )
        assert config.scope == "management_group"
        assert config.management_group_id == "root-mg"

    def test_invalid_scope(self) -> None:
        """Test invalid scope is rejected."""
        with pytest.raises(ValidationError):
            OperatorIdentityConfig.model_validate(
                {
                    "name": "test",
                    "scope": "invalid_scope",
                }
            )

    def test_default_resource_allocation(self) -> None:
        """Test default CPU/memory allocation."""
        config = OperatorIdentityConfig.model_validate({"name": "test"})
        assert abs(config.cpu_cores - 0.5) < 1e-9
        assert abs(config.memory_gb - 1.0) < 1e-9

    def test_display_name_alias(self) -> None:
        """Test displayName alias works."""
        config = OperatorIdentityConfig.model_validate(
            {
                "name": "firewall",
                "displayName": "Azure Operator - Firewall",
            }
        )
        assert config.display_name == "Azure Operator - Firewall"


class TestRoleAssignmentDefinition:
    """Tests for RoleAssignmentDefinition model."""

    def test_valid_role_assignment(self) -> None:
        """Test valid role assignment."""
        ra = RoleAssignmentDefinition.model_validate(
            {
                "roleDefinitionName": "Network Contributor",
                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
                "description": "Manage network resources",
            }
        )
        assert ra.role_definition_name == "Network Contributor"
        assert ra.scope.startswith("/subscriptions/")
        assert ra.description == "Manage network resources"

    def test_role_definition_name_alias(self) -> None:
        """Test roleDefinitionName alias works."""
        ra = RoleAssignmentDefinition.model_validate(
            {
                "roleDefinitionName": "Reader",
                "scope": "/subscriptions/test",
            }
        )
        assert ra.role_definition_name == "Reader"


class TestBootstrapRegistry:
    """Tests for bootstrap spec in registry."""

    def test_bootstrap_in_registry(self) -> None:
        """Test bootstrap is registered in SPEC_REGISTRY."""
        spec_class = get_spec_class("bootstrap")
        assert spec_class is BootstrapSpec


class TestIsBootstrapOperator:
    """Tests for is_bootstrap_operator function."""

    def test_bootstrap_domain(self) -> None:
        """Test bootstrap domain is identified."""
        assert is_bootstrap_operator("bootstrap") is True

    def test_non_bootstrap_domain(self) -> None:
        """Test non-bootstrap domains are not identified as bootstrap."""
        assert is_bootstrap_operator("firewall") is False
        assert is_bootstrap_operator("policy") is False
        assert is_bootstrap_operator("management") is False


class TestWaitForIdentityValidation:
    """Tests for wait_for_identity input validation."""

    @pytest.mark.asyncio
    async def test_invalid_subscription_id_rejected(self) -> None:
        """Test that invalid subscription ID format is rejected."""
        from controller.bootstrap import wait_for_identity

        with pytest.raises(ValueError) as exc_info:
            await wait_for_identity(
                subscription_id="not-a-valid-guid",
                resource_group="rg-test",
                identity_name="uami-test",
            )

        assert "Invalid subscription_id format" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_empty_subscription_id_rejected(self) -> None:
        """Test that empty subscription ID is rejected."""
        from controller.bootstrap import wait_for_identity

        with pytest.raises(ValueError) as exc_info:
            await wait_for_identity(
                subscription_id="",
                resource_group="rg-test",
                identity_name="uami-test",
            )

        assert "Invalid subscription_id format" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_resource_group_name_too_long_rejected(self) -> None:
        """Test that overly long resource group name is rejected."""
        from controller.bootstrap import wait_for_identity

        long_name = "a" * 100  # Exceeds 90 char limit

        with pytest.raises(ValueError) as exc_info:
            await wait_for_identity(
                subscription_id="00000000-0000-0000-0000-000000000000",
                resource_group=long_name,
                identity_name="uami-test",
            )

        assert "exceeds" in str(exc_info.value).lower()
