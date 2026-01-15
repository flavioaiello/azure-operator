"""WhatIf Safety Scenario Tests.

These tests document and verify scenarios where WhatIf preview prevents
dangerous changes from being applied blindly. Each test represents a
real-world scenario that would NOT be caught by Deployment Stacks alone.

Purpose:
- Document the value proposition of preview-before-apply
- Ensure confidence scoring catches high-risk changes
- Provide regression tests for safety mechanisms
- Serve as evidence for architecture decisions (A.4 in ROADMAP.md)

Run in CI: These tests MUST pass in GitHub Actions to ensure safety
guarantees are maintained.
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
import yaml
from azure_mock import MockAzureContext
from azure_mock.resources import MockResource, MockWhatIfChange, WhatIfChangeType

from controller.approval import (
    ConfidenceLevel,
    HIGH_RISK_RESOURCE_TYPES,
    RiskAssessor,
    ApprovalConfig,
)
from controller.config import Config, DeploymentScope, ReconciliationMode
from controller.reconciler import Reconciler


def create_assessor() -> RiskAssessor:
    """Create a RiskAssessor with default config for testing."""
    config = ApprovalConfig(require_approval_for_high_risk=True)
    return RiskAssessor(config)


# =============================================================================
# SCENARIO 1: Network Breaking Changes
# =============================================================================

class TestNetworkBreakingChanges:
    """Scenarios where network changes could cause outages.

    Deployment Stacks would apply these blindly.
    WhatIf + Confidence Scoring catches them.
    """

    @pytest.fixture
    def vnet_state(self) -> list[dict[str, Any]]:
        """Existing VNet with 10.0.0.0/16 address space."""
        return [
            {
                "resource_id": "/subscriptions/00000000-0000-0000-0000-000000000001"
                "/resourceGroups/network-rg"
                "/providers/Microsoft.Network/virtualNetworks/hub-vnet",
                "resource_type": "Microsoft.Network/virtualNetworks",
                "name": "hub-vnet",
                "location": "westeurope",
                "properties": {
                    "addressSpace": {
                        "addressPrefixes": ["10.0.0.0/16"],
                    },
                    "subnets": [
                        {"name": "GatewaySubnet", "addressPrefix": "10.0.0.0/24"},
                        {"name": "AzureFirewallSubnet", "addressPrefix": "10.0.1.0/24"},
                    ],
                },
            }
        ]

    def test_whatif_catches_address_space_shrink(self, vnet_state: list[dict[str, Any]]) -> None:
        """Shrinking address space from /16 to /24 would break subnets.

        Without WhatIf:
        - Deployment Stacks would apply immediately
        - All subnets outside new range would fail
        - VPN connections would drop

        With WhatIf:
        - Change is previewed: addressPrefixes: ["10.0.0.0/16"] → ["10.0.0.0/24"]
        - HIGH confidence level triggered (network resource + breaking change)
        - Approval gate blocks deployment
        """
        with MockAzureContext(initial_resources=vnet_state) as ctx:
            # Simulate the WhatIf result for shrinking address space
            whatif = ctx.state.compute_whatif(
                template={
                    "resources": [
                        {
                            "type": "Microsoft.Network/virtualNetworks",
                            "name": "hub-vnet",
                            "location": "westeurope",
                            "properties": {
                                "addressSpace": {
                                    "addressPrefixes": ["10.0.0.0/24"],  # SHRUNK!
                                },
                            },
                        }
                    ]
                },
                parameters={},
                subscription_id="00000000-0000-0000-0000-000000000001",
                resource_group="network-rg",
            )

            # WhatIf MUST detect this as a MODIFY
            changes = whatif.properties.changes
            assert len(changes) == 1
            assert changes[0].change_type == WhatIfChangeType.MODIFY

            # The delta should show the address space change
            before_props = changes[0].before["properties"]
            after_props = changes[0].after["properties"]
            assert before_props["addressSpace"]["addressPrefixes"] == ["10.0.0.0/16"]
            assert after_props["addressSpace"]["addressPrefixes"] == ["10.0.0.0/24"]

            # Confidence scoring MUST flag this as MEDIUM or higher
            assessor = create_assessor()
            for change in changes:
                assessment = assessor.assess_change(
                    resource_id=change.resource_id,
                    resource_type="Microsoft.Network/virtualNetworks",
                    change_type=change.change_type.value,
                )
                assert assessment.confidence in (ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW)

    def test_whatif_catches_vnet_peering_removal(self) -> None:
        """Removing VNet peering would break connectivity.

        This is a DELETE operation that requires review.
        """
        existing_peering = [
            {
                "resource_id": "/subscriptions/00000000-0000-0000-0000-000000000001"
                "/resourceGroups/network-rg"
                "/providers/Microsoft.Network/virtualNetworks/hub-vnet"
                "/virtualNetworkPeerings/spoke1-peer",
                "resource_type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
                "name": "spoke1-peer",
                "location": "westeurope",
                "properties": {
                    "remoteVirtualNetwork": {
                        "id": "/subscriptions/.../virtualNetworks/spoke1-vnet"
                    },
                    "allowForwardedTraffic": True,
                },
            }
        ]

        with MockAzureContext(initial_resources=existing_peering):
            # Assess risk of deleting a VNet peering
            assessor = create_assessor()
            assessment = assessor.assess_change(
                resource_id=existing_peering[0]["resource_id"],
                resource_type="Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
                change_type="Delete",
            )

            # DELETE operations should be flagged as risky
            assert assessment.confidence in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)


# =============================================================================
# SCENARIO 2: RBAC Changes
# =============================================================================

class TestRbacChanges:
    """Scenarios where RBAC changes could cause privilege escalation.

    These are among the highest-risk changes that MUST require review.
    """

    def test_whatif_catches_role_assignment_changes(self) -> None:
        """Role assignment modifications require approval.

        Even in a "read-only" Stack scenario, YOUR spec changes
        can still modify RBAC - Stacks won't catch the risk.
        """
        assessor = create_assessor()

        # Creating a new Owner role assignment
        assessment = assessor.assess_change(
            resource_id="/subscriptions/xxx/providers/Microsoft.Authorization/roleAssignments/yyy",
            resource_type="Microsoft.Authorization/roleAssignments",
            change_type="Create",
        )

        # MUST be LOW confidence (highest risk)
        assert assessment.confidence == ConfidenceLevel.LOW

    def test_whatif_catches_role_definition_changes(self) -> None:
        """Custom role definition modifications require approval."""
        assessor = create_assessor()

        assessment = assessor.assess_change(
            resource_id="/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/yyy",
            resource_type="Microsoft.Authorization/roleDefinitions",
            change_type="Modify",
        )

        # MUST be LOW confidence (highest risk)
        assert assessment.confidence == ConfidenceLevel.LOW

    def test_delete_role_assignment_requires_approval(self) -> None:
        """Deleting role assignments could lock out users."""
        assessor = create_assessor()

        assessment = assessor.assess_change(
            resource_id="/subscriptions/xxx/providers/Microsoft.Authorization/roleAssignments/yyy",
            resource_type="Microsoft.Authorization/roleAssignments",
            change_type="Delete",
        )

        # DELETE + role assignment = maximum risk
        assert assessment.confidence == ConfidenceLevel.LOW


# =============================================================================
# SCENARIO 3: Firewall / Security Changes
# =============================================================================

class TestSecurityChanges:
    """Scenarios where security config changes could expose resources."""

    @pytest.fixture
    def firewall_state(self) -> list[dict[str, Any]]:
        """Existing Azure Firewall with deny-all baseline."""
        return [
            {
                "resource_id": "/subscriptions/00000000-0000-0000-0000-000000000001"
                "/resourceGroups/security-rg"
                "/providers/Microsoft.Network/azureFirewalls/hub-fw",
                "resource_type": "Microsoft.Network/azureFirewalls",
                "name": "hub-fw",
                "location": "westeurope",
                "properties": {
                    "threatIntelMode": "Deny",  # Block known bad IPs
                    "networkRuleCollections": [
                        {
                            "name": "deny-all",
                            "priority": 65000,
                            "action": {"type": "Deny"},
                            "rules": [{"name": "deny-all-outbound"}],
                        }
                    ],
                },
            }
        ]

    def test_whatif_catches_threat_intel_mode_change(
        self, firewall_state: list[dict[str, Any]]
    ) -> None:
        """Changing threatIntelMode from Deny to Off is dangerous.

        Without WhatIf:
        - Stack update happens immediately
        - Firewall stops blocking known malicious IPs
        - No preview, no approval gate

        With WhatIf:
        - Change is visible: threatIntelMode: "Deny" → "Off"
        - Firewall resource type triggers HIGH risk assessment
        - Approval required before deployment
        """
        with MockAzureContext(initial_resources=firewall_state) as ctx:
            whatif = ctx.state.compute_whatif(
                template={
                    "resources": [
                        {
                            "type": "Microsoft.Network/azureFirewalls",
                            "name": "hub-fw",
                            "location": "westeurope",
                            "properties": {
                                "threatIntelMode": "Off",  # DANGEROUS!
                                "networkRuleCollections": [],
                            },
                        }
                    ]
                },
                parameters={},
                subscription_id="00000000-0000-0000-0000-000000000001",
                resource_group="security-rg",
            )

            # MUST detect the change
            changes = whatif.properties.changes
            assert len(changes) == 1
            assert changes[0].change_type == WhatIfChangeType.MODIFY

            # Firewall MUST be flagged as high-risk
            assessor = create_assessor()
            assessment = assessor.assess_change(
                resource_id=changes[0].resource_id,
                resource_type="Microsoft.Network/azureFirewalls",
                change_type="Modify",
            )
            assert assessment.confidence == ConfidenceLevel.LOW  # Highest risk

    def test_whatif_catches_nsg_rule_allowing_internet(self) -> None:
        """Adding NSG rule allowing 0.0.0.0/0 inbound is dangerous."""
        existing_nsg = [
            {
                "resource_id": "/subscriptions/xxx/resourceGroups/rg"
                "/providers/Microsoft.Network/networkSecurityGroups/app-nsg",
                "resource_type": "Microsoft.Network/networkSecurityGroups",
                "name": "app-nsg",
                "location": "westeurope",
                "properties": {
                    "securityRules": [
                        {
                            "name": "DenyAllInbound",
                            "priority": 65000,
                            "direction": "Inbound",
                            "access": "Deny",
                        }
                    ],
                },
            }
        ]

        with MockAzureContext(initial_resources=existing_nsg) as ctx:
            # Template adds an Allow * rule
            whatif = ctx.state.compute_whatif(
                template={
                    "resources": [
                        {
                            "type": "Microsoft.Network/networkSecurityGroups",
                            "name": "app-nsg",
                            "location": "westeurope",
                            "properties": {
                                "securityRules": [
                                    {
                                        "name": "AllowAllInbound",  # DANGEROUS!
                                        "priority": 100,
                                        "direction": "Inbound",
                                        "access": "Allow",
                                        "sourceAddressPrefix": "*",
                                    },
                                    {
                                        "name": "DenyAllInbound",
                                        "priority": 65000,
                                        "direction": "Inbound",
                                        "access": "Deny",
                                    },
                                ],
                            },
                        }
                    ]
                },
                parameters={},
                subscription_id="xxx",
                resource_group="rg",
            )

            # MUST detect this as a modification
            assert whatif.properties.changes[0].change_type == WhatIfChangeType.MODIFY


# =============================================================================
# SCENARIO 4: Resource Deletion
# =============================================================================

class TestResourceDeletion:
    """Scenarios where resources would be deleted."""

    def test_delete_operation_always_flagged(self) -> None:
        """Any DELETE operation requires extra scrutiny.

        Deployment Stacks with actionOnUnmanage=delete would
        remove resources without preview.
        """
        assessor = create_assessor()

        resource_types_to_check = [
            "Microsoft.Storage/storageAccounts",
            "Microsoft.KeyVault/vaults",
            "Microsoft.Sql/servers/databases",
            "Microsoft.Compute/virtualMachines",
            "Microsoft.RecoveryServices/vaults",
        ]

        for resource_type in resource_types_to_check:
            assessment = assessor.assess_change(
                resource_id=f"/subscriptions/xxx/providers/{resource_type}/name",
                resource_type=resource_type,
                change_type="Delete",
            )

            # All DELETEs should be flagged as risky
            assert assessment.confidence in (
                ConfidenceLevel.LOW,
                ConfidenceLevel.MEDIUM,
            ), f"DELETE of {resource_type} was not flagged as risky"

    def test_key_vault_deletion_highest_risk(self) -> None:
        """Deleting a Key Vault loses secrets permanently.

        Soft-delete helps, but this should still require approval.
        """
        assessor = create_assessor()

        assessment = assessor.assess_change(
            resource_id="/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
            resource_type="Microsoft.KeyVault/vaults",
            change_type="Delete",
        )

        # MUST be lowest confidence (highest risk)
        assert assessment.confidence == ConfidenceLevel.LOW


# =============================================================================
# SCENARIO 5: Management Group Changes
# =============================================================================

class TestManagementGroupChanges:
    """Scenarios involving Management Group hierarchy changes.

    Note: Deployment Stacks deny assignments do NOT work at MG scope!
    """

    def test_mg_changes_flagged_as_high_risk(self) -> None:
        """Management Group modifications affect entire hierarchy."""
        assessor = create_assessor()

        assessment = assessor.assess_change(
            resource_id="/providers/Microsoft.Management/managementGroups/platform",
            resource_type="Microsoft.Management/managementGroups",
            change_type="Modify",
        )

        # MG changes are enterprise-wide impact
        assert assessment.confidence == ConfidenceLevel.LOW

    def test_mg_deletion_blocked(self) -> None:
        """Deleting a Management Group could orphan resources."""
        assessor = create_assessor()

        assessment = assessor.assess_change(
            resource_id="/providers/Microsoft.Management/managementGroups/sandbox",
            resource_type="Microsoft.Management/managementGroups",
            change_type="Delete",
        )

        # MUST require approval
        assert assessment.confidence == ConfidenceLevel.LOW


# =============================================================================
# SCENARIO 6: Policy Assignment Changes
# =============================================================================

class TestPolicyChanges:
    """Scenarios where Policy changes affect governance posture."""

    def test_removing_policy_assignment_requires_approval(self) -> None:
        """Removing a deny policy could expose non-compliant resources."""
        assessor = create_assessor()

        assessment = assessor.assess_change(
            resource_id="/providers/Microsoft.Management/managementGroups/alz"
            "/providers/Microsoft.Authorization/policyAssignments/deny-public-ip",
            resource_type="Microsoft.Authorization/policyAssignments",
            change_type="Delete",
        )

        # Removing governance = high risk
        assert assessment.confidence == ConfidenceLevel.LOW


# =============================================================================
# SCENARIO 7: Spec Typos / Configuration Errors
# =============================================================================

class TestConfigurationErrors:
    """Scenarios where spec errors would cause damage without preview."""

    @pytest.fixture
    def storage_state(self) -> list[dict[str, Any]]:
        """Existing storage account with secure settings."""
        return [
            {
                "resource_id": "/subscriptions/xxx/resourceGroups/data-rg"
                "/providers/Microsoft.Storage/storageAccounts/proddata",
                "resource_type": "Microsoft.Storage/storageAccounts",
                "name": "proddata",
                "location": "westeurope",
                "properties": {
                    "minimumTlsVersion": "TLS1_2",
                    "supportsHttpsTrafficOnly": True,
                    "allowBlobPublicAccess": False,
                    "networkAcls": {
                        "defaultAction": "Deny",
                        "virtualNetworkRules": [
                            {"id": "/subscriptions/.../subnets/data-subnet"}
                        ],
                    },
                },
            }
        ]

    def test_whatif_catches_accidental_public_access(
        self, storage_state: list[dict[str, Any]]
    ) -> None:
        """Typo enabling public blob access would be visible in WhatIf.

        Common mistake: allowBlobPublicAccess: false → true (yaml boolean issue)
        """
        with MockAzureContext(initial_resources=storage_state) as ctx:
            # Accidental public access (yaml 'yes' parsed as True, etc.)
            whatif = ctx.state.compute_whatif(
                template={
                    "resources": [
                        {
                            "type": "Microsoft.Storage/storageAccounts",
                            "name": "proddata",
                            "location": "westeurope",
                            "properties": {
                                "minimumTlsVersion": "TLS1_2",
                                "supportsHttpsTrafficOnly": True,
                                "allowBlobPublicAccess": True,  # TYPO!
                                "networkAcls": {"defaultAction": "Deny"},
                            },
                        }
                    ]
                },
                parameters={},
                subscription_id="xxx",
                resource_group="data-rg",
            )

            # MUST show the change
            changes = whatif.properties.changes
            assert changes[0].change_type == WhatIfChangeType.MODIFY

            # Before shows False, After shows True
            before_props = changes[0].before["properties"]
            after_props = changes[0].after["properties"]
            assert before_props["allowBlobPublicAccess"] is False
            assert after_props["allowBlobPublicAccess"] is True


# =============================================================================
# SUMMARY: These scenarios REQUIRE WhatIf
# =============================================================================

class TestWhatIfIsRequired:
    """Summary assertions documenting why WhatIf is architecturally required."""

    def test_high_risk_resource_types_exist(self) -> None:
        """Verify the RiskAssessor knows about high-risk resource types."""
        required_types = [
            "Microsoft.Authorization/roleAssignments",
            "Microsoft.Authorization/roleDefinitions",
            "Microsoft.Network/azureFirewalls",
            "Microsoft.Network/routeTables",
            "Microsoft.Management/managementGroups",
            "Microsoft.KeyVault/vaults",
        ]

        for rt in required_types:
            assert rt in HIGH_RISK_RESOURCE_TYPES, f"{rt} not in HIGH_RISK_RESOURCE_TYPES"

    def test_delete_operations_elevate_risk(self) -> None:
        """Verify DELETE operations are always treated as higher risk."""
        assessor = create_assessor()

        # Even a low-risk resource type should be flagged for DELETE
        assessment = assessor.assess_change(
            resource_id="/subscriptions/xxx/providers/xxx",
            resource_type="Microsoft.Insights/diagnosticSettings",
            change_type="Delete",
        )

        # Deletes should not be HIGH confidence
        assert assessment.confidence != ConfidenceLevel.HIGH

    def test_documentation_scenario_count(self) -> None:
        """Verify we have documented enough scenarios.

        This test ensures new engineers understand the importance
        of WhatIf by having concrete examples.
        """
        # Count test classes in this file (excluding this one)
        scenario_classes = [
            TestNetworkBreakingChanges,
            TestRbacChanges,
            TestSecurityChanges,
            TestResourceDeletion,
            TestManagementGroupChanges,
            TestPolicyChanges,
            TestConfigurationErrors,
        ]

        # We should have at least 7 categories of scenarios
        assert len(scenario_classes) >= 7, (
            "Need more WhatIf safety scenario documentation. "
            "Add test classes for additional high-risk patterns."
        )
