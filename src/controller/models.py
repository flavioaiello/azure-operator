"""Pydantic models for domain specifications with validation.

These models provide:
1. Type-safe YAML parsing
2. Validation at the boundary (fail fast, fail loudly)
3. Clean transformation to ARM parameters
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator

# =============================================================================
# Base Models
# =============================================================================

# Forward reference for SpecModeConfig to avoid circular import
# Actual import happens at runtime in resource_modes.py


class BaseSpec(BaseModel):
    """Base specification with common fields."""

    model_config = {"extra": "ignore"}  # Reject unknown fields

    location: str | None = None
    resource_group_name: str | None = Field(None, alias="resourceGroupName")
    tags: dict[str, str] = Field(default_factory=dict)

    # Dependency ordering - list of domain names that must deploy first
    # Example: depends_on: ["hub-network", "log-analytics"]
    depends_on: list[str] = Field(default_factory=list, alias="dependsOn")

    # Per-resource mode overrides
    # Allows spec to declare mode preferences and resource-level overrides
    # Example:
    #   modeConfig:
    #     defaultMode: observe
    #     overrides:
    #       - resourceTypes: ["Microsoft.Authorization/roleAssignments"]
    #         mode: protect
    mode_config: Any | None = Field(None, alias="modeConfig")

    def to_arm_parameters(self) -> dict[str, Any]:
        """Convert spec to ARM template parameters format."""
        raise NotImplementedError("Subclasses must implement to_arm_parameters")


# =============================================================================
# Management Domain
# =============================================================================


class LogAnalyticsConfig(BaseModel):
    """Log Analytics workspace configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=63)]
    retention_days: Annotated[int, Field(ge=30, le=730, alias="retentionDays")] = 365
    sku: str = "PerGB2018"

    @field_validator("sku")
    @classmethod
    def validate_sku(cls, v: str) -> str:
        valid_skus = {"PerGB2018", "CapacityReservation", "Free", "Standalone"}
        if v not in valid_skus:
            raise ValueError(f"sku must be one of {valid_skus}")
        return v


class AutomationConfig(BaseModel):
    """Automation account configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=50)]


class DataCollectionRuleConfig(BaseModel):
    """Data collection rule configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1)]
    description: str | None = None
    kind: str | None = None
    streams: list[str] = Field(default_factory=list)
    destinations: Any | None = None  # Can be dict (logAnalytics: [...]) or list
    data_sources: Any | None = Field(None, alias="dataSources")
    data_flows: list[Any] | None = Field(None, alias="dataFlows")


class ManagedIdentityConfig(BaseModel):
    """Managed identity configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1)]
    description: str | None = None


class ManagementSpec(BaseSpec):
    """Management domain specification."""

    log_analytics: LogAnalyticsConfig = Field(alias="logAnalytics")
    automation: AutomationConfig | None = None
    data_collection_rules: list[DataCollectionRuleConfig] = Field(
        default_factory=list, alias="dataCollectionRules"
    )
    managed_identities: list[ManagedIdentityConfig] = Field(
        default_factory=list, alias="managedIdentities"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        """Convert to ARM template parameters."""
        params: dict[str, Any] = {}

        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}

        # Log Analytics
        params["logAnalyticsName"] = {"value": self.log_analytics.name}
        params["logAnalyticsRetentionDays"] = {"value": self.log_analytics.retention_days}
        params["logAnalyticsSku"] = {"value": self.log_analytics.sku}

        # Automation
        if self.automation:
            params["automationAccountName"] = {"value": self.automation.name}

        # Data Collection Rules
        if self.data_collection_rules:
            params["dataCollectionRules"] = {
                "value": [
                    {
                        "name": dcr.name,
                        "description": dcr.description,
                        "streams": dcr.streams,
                    }
                    for dcr in self.data_collection_rules
                ]
            }

        # Managed Identities
        if self.managed_identities:
            params["managedIdentities"] = {
                "value": [
                    {"name": mi.name, "description": mi.description}
                    for mi in self.managed_identities
                ]
            }

        if self.tags:
            params["tags"] = {"value": self.tags}

        return params


# =============================================================================
# Connectivity Domain
# =============================================================================


class SubnetConfig(BaseModel):
    """Virtual network subnet configuration."""

    model_config = {"extra": "ignore"}  # Allow extra fields for forward compatibility

    name: Annotated[str, Field(min_length=1)]
    prefix: str = Field(alias="addressPrefix")

    @field_validator("prefix")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        # Basic CIDR validation
        if "/" not in v:
            raise ValueError("prefix must be in CIDR notation (e.g., 10.0.0.0/24)")
        return v


class HubConfig(BaseModel):
    """Hub virtual network configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=64)]
    address_space: str = Field(alias="addressSpace")
    subnets: list[SubnetConfig] = Field(default_factory=list)

    @field_validator("address_space")
    @classmethod
    def validate_address_space(cls, v: str) -> str:
        if "/" not in v:
            raise ValueError("addressSpace must be in CIDR notation")
        return v


class FirewallConfig(BaseModel):
    """Azure Firewall configuration."""

    model_config = {"extra": "ignore"}

    enabled: bool = False
    name: str | None = None
    sku: str = "Standard"
    threat_intel_mode: str = Field("Alert", alias="threatIntelMode")
    availability_zones: list[int] = Field(default_factory=list, alias="availabilityZones")

    @field_validator("sku")
    @classmethod
    def validate_sku(cls, v: str) -> str:
        valid = {"Basic", "Standard", "Premium"}
        if v not in valid:
            raise ValueError(f"sku must be one of {valid}")
        return v


class GatewayConfig(BaseModel):
    """VPN or ExpressRoute gateway configuration."""

    model_config = {"extra": "ignore"}

    enabled: bool = False
    name: str | None = None
    sku: str | None = None
    type: str | None = None


class BastionConfig(BaseModel):
    """Azure Bastion configuration."""

    model_config = {"extra": "ignore"}

    enabled: bool = False
    name: str | None = None
    sku: str = "Standard"


class PrivateDnsZoneConfig(BaseModel):
    """Private DNS zone configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1)]


class ConnectivitySpec(BaseSpec):
    """Connectivity domain specification."""

    hub: HubConfig
    firewall: FirewallConfig = Field(default_factory=FirewallConfig)
    vpn_gateway: GatewayConfig = Field(default_factory=GatewayConfig, alias="vpnGateway")
    express_route_gateway: GatewayConfig = Field(
        default_factory=GatewayConfig, alias="expressRouteGateway"
    )
    bastion: BastionConfig = Field(default_factory=BastionConfig)
    private_dns_zones: list[PrivateDnsZoneConfig] = Field(
        default_factory=list, alias="privateDnsZones"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        """Convert to ARM template parameters."""
        params: dict[str, Any] = {}

        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}

        # Hub VNet
        params["hubVnetName"] = {"value": self.hub.name}
        params["hubAddressSpace"] = {"value": self.hub.address_space}
        params["subnets"] = {
            "value": [{"name": s.name, "addressPrefix": s.prefix} for s in self.hub.subnets]
        }

        # Firewall
        params["deployFirewall"] = {"value": self.firewall.enabled}
        if self.firewall.name:
            params["firewallName"] = {"value": self.firewall.name}
        params["firewallSku"] = {"value": self.firewall.sku}

        # Bastion
        params["deployBastion"] = {"value": self.bastion.enabled}
        if self.bastion.name:
            params["bastionName"] = {"value": self.bastion.name}

        # VPN Gateway
        params["deployVpnGateway"] = {"value": self.vpn_gateway.enabled}
        if self.vpn_gateway.name:
            params["vpnGatewayName"] = {"value": self.vpn_gateway.name}

        # ExpressRoute Gateway
        params["deployExpressRouteGateway"] = {"value": self.express_route_gateway.enabled}
        if self.express_route_gateway.name:
            params["expressRouteGatewayName"] = {"value": self.express_route_gateway.name}

        # Private DNS Zones
        if self.private_dns_zones:
            params["privateDnsZones"] = {"value": [z.name for z in self.private_dns_zones]}

        if self.tags:
            params["tags"] = {"value": self.tags}

        return params


# =============================================================================
# Policy Domain
# =============================================================================


class ManagementGroupConfig(BaseModel):
    """Management group configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1)]
    display_name: str = Field(alias="displayName")
    parent_id: str = Field(alias="parentId")


class CustomPolicyConfig(BaseModel):
    """Custom policy definition configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1)]
    display_name: str = Field(alias="displayName")
    description: str | None = None
    mode: str = "All"
    policy_rule: dict[str, Any] = Field(alias="policyRule")


class PolicyAssignmentConfig(BaseModel):
    """Policy assignment configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1)]
    policy_definition_id: str = Field(alias="policyDefinitionId")
    scope: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    enforcement_mode: str = Field("Default", alias="enforcementMode")
    non_compliance_message: str | None = Field(None, alias="nonComplianceMessage")


# =============================================================================
# Security Domain
# =============================================================================


class SecurityContactConfig(BaseModel):
    """Security contact configuration."""

    model_config = {"extra": "ignore"}

    email: str
    phone: str | None = None
    alert_notifications: bool = Field(True, alias="alertNotifications")
    alerts_to_admins: bool = Field(True, alias="alertsToAdmins")


class AutoProvisioningConfig(BaseModel):
    """Auto-provisioning configuration."""

    model_config = {"extra": "ignore"}

    log_analytics: bool = Field(True, alias="logAnalytics")
    vulnerability_assessment: bool = Field(True, alias="vulnerabilityAssessment")


class WorkspaceSettingsConfig(BaseModel):
    """Defender workspace settings."""

    model_config = {"extra": "ignore"}

    scope: str = "subscription"
    workspace_resource_id: str | None = Field(None, alias="workspaceResourceId")


class DefenderConfig(BaseModel):
    """Microsoft Defender for Cloud configuration."""

    model_config = {"extra": "ignore"}

    pricing_tier: str = Field("Standard", alias="pricingTier")
    plans: list[str] = Field(default_factory=list)
    security_contacts: list[SecurityContactConfig] = Field(
        default_factory=list, alias="securityContacts"
    )
    auto_provisioning: AutoProvisioningConfig | None = Field(None, alias="autoProvisioning")
    workspace_settings: WorkspaceSettingsConfig | None = Field(None, alias="workspaceSettings")


class NetworkAclConfig(BaseModel):
    """Network ACL configuration."""

    model_config = {"extra": "ignore"}

    default_action: str = Field("Deny", alias="defaultAction")
    bypass: str = "AzureServices"


class KeyVaultConfig(BaseModel):
    """Key Vault configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=3, max_length=24)]
    sku: str = "standard"
    enable_purge_protection: bool = Field(True, alias="enablePurgeProtection")
    enable_soft_delete: bool = Field(True, alias="enableSoftDelete")
    soft_delete_retention_days: int = Field(90, alias="softDeleteRetentionDays")
    enable_rbac_authorization: bool = Field(True, alias="enableRbacAuthorization")
    network_acls: NetworkAclConfig | None = Field(None, alias="networkAcls")

    @field_validator("sku")
    @classmethod
    def validate_sku(cls, v: str) -> str:
        valid = {"standard", "premium"}
        if v.lower() not in valid:
            raise ValueError(f"sku must be one of {valid}")
        return v


class SecuritySpec(BaseSpec):
    """Security domain specification."""

    defender: DefenderConfig = Field(default_factory=DefenderConfig)
    key_vaults: list[KeyVaultConfig] = Field(default_factory=list, alias="keyVaults")

    def to_arm_parameters(self) -> dict[str, Any]:
        """Convert to ARM template parameters."""
        params: dict[str, Any] = {}

        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}

        # Defender
        params["defenderPricingTier"] = {"value": self.defender.pricing_tier}
        params["defenderPlans"] = {"value": self.defender.plans}

        if self.defender.security_contacts:
            params["securityContacts"] = {
                "value": [
                    {
                        "email": c.email,
                        "phone": c.phone,
                        "alertNotifications": c.alert_notifications,
                        "alertsToAdmins": c.alerts_to_admins,
                    }
                    for c in self.defender.security_contacts
                ]
            }

        # Key Vaults
        if self.key_vaults:
            params["keyVaults"] = {
                "value": [
                    {
                        "name": kv.name,
                        "sku": kv.sku,
                        "enablePurgeProtection": kv.enable_purge_protection,
                        "softDeleteRetentionDays": kv.soft_delete_retention_days,
                        "enableRbacAuthorization": kv.enable_rbac_authorization,
                    }
                    for kv in self.key_vaults
                ]
            }

        if self.tags:
            params["tags"] = {"value": self.tags}

        return params


# =============================================================================
# Identity Domain
# =============================================================================


class CustomRoleConfig(BaseModel):
    """Custom RBAC role definition."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1)]
    description: str | None = None
    actions: list[str] = Field(default_factory=list)
    not_actions: list[str] = Field(default_factory=list, alias="notActions")
    data_actions: list[str] = Field(default_factory=list, alias="dataActions")
    not_data_actions: list[str] = Field(default_factory=list, alias="notDataActions")
    assignable_scopes: list[str] = Field(default_factory=list, alias="assignableScopes")


class RoleAssignmentConfig(BaseModel):
    """Role assignment configuration."""

    model_config = {"extra": "ignore"}

    principal_id: str = Field(alias="principalId")
    principal_type: str = Field("ServicePrincipal", alias="principalType")
    role_definition_id: str = Field(alias="roleDefinitionId")
    scope: str


class IdentitySpec(BaseSpec):
    """Identity domain specification."""

    custom_roles: list[CustomRoleConfig] = Field(default_factory=list, alias="customRoles")
    role_assignments: list[RoleAssignmentConfig] = Field(
        default_factory=list, alias="roleAssignments"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        """Convert to ARM template parameters."""
        params: dict[str, Any] = {}

        if self.custom_roles:
            params["customRoles"] = {
                "value": [
                    {
                        "name": r.name,
                        "description": r.description,
                        "actions": r.actions,
                        "notActions": r.not_actions,
                        "dataActions": r.data_actions,
                        "notDataActions": r.not_data_actions,
                        "assignableScopes": r.assignable_scopes,
                    }
                    for r in self.custom_roles
                ]
            }

        if self.role_assignments:
            params["roleAssignments"] = {
                "value": [
                    {
                        "principalId": a.principal_id,
                        "principalType": a.principal_type,
                        "roleDefinitionId": a.role_definition_id,
                        "scope": a.scope,
                    }
                    for a in self.role_assignments
                ]
            }

        if self.tags:
            params["tags"] = {"value": self.tags}

        return params


# =============================================================================
# Spec Registry - Granular Per-Concern Operators
# =============================================================================


# Connectivity operators reuse existing config classes
class FirewallSpec(BaseSpec):
    """Firewall operator specification."""

    firewall: FirewallConfig

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        if self.firewall.name:
            params["firewallName"] = {"value": self.firewall.name}
        params["firewallSku"] = {"value": self.firewall.sku}
        params["threatIntelMode"] = {"value": self.firewall.threat_intel_mode}
        if self.firewall.availability_zones:
            params["availabilityZones"] = {"value": self.firewall.availability_zones}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class VpnGatewaySpec(BaseSpec):
    """VPN Gateway operator specification."""

    vpn_gateway: GatewayConfig = Field(alias="vpnGateway")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        if self.vpn_gateway.name:
            params["vpnGatewayName"] = {"value": self.vpn_gateway.name}
        if self.vpn_gateway.sku:
            params["vpnGatewaySku"] = {"value": self.vpn_gateway.sku}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class ExpressRouteSpec(BaseSpec):
    """ExpressRoute operator specification."""

    express_route: GatewayConfig = Field(alias="expressRoute")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        if self.express_route.name:
            params["expressRouteGatewayName"] = {"value": self.express_route.name}
        if self.express_route.sku:
            params["expressRouteGatewaySku"] = {"value": self.express_route.sku}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class BastionSpec(BaseSpec):
    """Bastion operator specification."""

    bastion: BastionConfig

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        if self.bastion.name:
            params["bastionName"] = {"value": self.bastion.name}
        params["bastionSku"] = {"value": self.bastion.sku}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class DnsSpec(BaseSpec):
    """DNS operator specification."""

    private_dns_zones: list[PrivateDnsZoneConfig] = Field(
        default_factory=list, alias="privateDnsZones"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        if self.private_dns_zones:
            params["privateDnsZones"] = {
                "value": [{"name": z.name} for z in self.private_dns_zones]
            }
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class HubNetworkSpec(BaseSpec):
    """Hub Network operator specification."""

    hub: HubConfig

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["hubVnetName"] = {"value": self.hub.name}
        params["hubAddressSpace"] = {"value": self.hub.address_space}
        if self.hub.subnets:
            params["subnets"] = {
                "value": [{"name": s.name, "addressPrefix": s.prefix} for s in self.hub.subnets]
            }
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


# =============================================================================
# Virtual WAN Per-Resource Operators
# =============================================================================


class VwanConfig(BaseModel):
    """Virtual WAN resource configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=80)]
    type: str = "Standard"  # Standard or Basic
    disable_vpn_encryption: bool = Field(False, alias="disableVpnEncryption")
    allow_branch_to_branch_traffic: bool = Field(True, alias="allowBranchToBranchTraffic")


class VwanSpec(BaseSpec):
    """Virtual WAN operator specification.

    Manages ONLY the Virtual WAN resource itself.
    Virtual Hubs, Firewalls, Gateways are separate operators.
    """

    virtual_wan: VwanConfig = Field(alias="virtualWan")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["virtualWanName"] = {"value": self.virtual_wan.name}
        params["virtualWanType"] = {"value": self.virtual_wan.type}
        params["disableVpnEncryption"] = {"value": self.virtual_wan.disable_vpn_encryption}
        params["allowBranchToBranchTraffic"] = {
            "value": self.virtual_wan.allow_branch_to_branch_traffic
        }
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class VwanHubConfig(BaseModel):
    """Virtual Hub configuration."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=80)]
    address_prefix: str = Field(alias="addressPrefix")
    virtual_wan_id: str = Field(alias="virtualWanId")
    hub_routing_preference: str = Field("ExpressRoute", alias="hubRoutingPreference")
    sku: str = "Standard"


class VwanHubSpec(BaseSpec):
    """Virtual Hub operator specification.

    Manages a single Virtual Hub within a Virtual WAN.
    Requires the Virtual WAN to exist (created by vwan operator).
    """

    virtual_hub: VwanHubConfig = Field(alias="virtualHub")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["virtualHubName"] = {"value": self.virtual_hub.name}
        params["virtualHubAddressPrefix"] = {"value": self.virtual_hub.address_prefix}
        params["virtualWanId"] = {"value": self.virtual_hub.virtual_wan_id}
        params["hubRoutingPreference"] = {"value": self.virtual_hub.hub_routing_preference}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class VwanFirewallConfig(BaseModel):
    """Azure Firewall configuration for vWAN secured hub."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=80)]
    virtual_hub_id: str = Field(alias="virtualHubId")
    sku: str = "Standard"  # Standard or Premium
    threat_intel_mode: str = Field("Alert", alias="threatIntelMode")
    firewall_policy_id: str | None = Field(None, alias="firewallPolicyId")


class VwanFirewallSpec(BaseSpec):
    """Azure Firewall in vWAN Secured Hub operator specification.

    Manages Azure Firewall deployed within a Virtual Hub (Secured Hub).
    Requires the Virtual Hub to exist (created by vwan-hub operator).
    """

    azure_firewall: VwanFirewallConfig = Field(alias="azureFirewall")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["azureFirewallName"] = {"value": self.azure_firewall.name}
        params["virtualHubId"] = {"value": self.azure_firewall.virtual_hub_id}
        params["azureFirewallSku"] = {"value": self.azure_firewall.sku}
        params["threatIntelMode"] = {"value": self.azure_firewall.threat_intel_mode}
        if self.azure_firewall.firewall_policy_id:
            params["firewallPolicyId"] = {"value": self.azure_firewall.firewall_policy_id}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class VwanVpnGatewayConfig(BaseModel):
    """VPN Gateway configuration for vWAN."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=80)]
    virtual_hub_id: str = Field(alias="virtualHubId")
    scale_unit: int = Field(1, alias="scaleUnit", ge=1, le=20)
    bgp_settings: dict[str, Any] | None = Field(None, alias="bgpSettings")


class VwanVpnGatewaySpec(BaseSpec):
    """VPN Gateway in vWAN operator specification.

    Manages VPN Gateway deployed within a Virtual Hub.
    Requires the Virtual Hub to exist (created by vwan-hub operator).
    """

    vpn_gateway: VwanVpnGatewayConfig = Field(alias="vpnGateway")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["vpnGatewayName"] = {"value": self.vpn_gateway.name}
        params["virtualHubId"] = {"value": self.vpn_gateway.virtual_hub_id}
        params["scaleUnit"] = {"value": self.vpn_gateway.scale_unit}
        if self.vpn_gateway.bgp_settings:
            params["bgpSettings"] = {"value": self.vpn_gateway.bgp_settings}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class VwanExpressRouteConfig(BaseModel):
    """ExpressRoute Gateway configuration for vWAN."""

    model_config = {"extra": "ignore"}

    name: Annotated[str, Field(min_length=1, max_length=80)]
    virtual_hub_id: str = Field(alias="virtualHubId")
    scale_unit: int = Field(1, alias="scaleUnit", ge=1, le=10)


class VwanExpressRouteSpec(BaseSpec):
    """ExpressRoute Gateway in vWAN operator specification.

    Manages ExpressRoute Gateway deployed within a Virtual Hub.
    Requires the Virtual Hub to exist (created by vwan-hub operator).
    """

    expressroute_gateway: VwanExpressRouteConfig = Field(alias="expressRouteGateway")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["expressRouteGatewayName"] = {"value": self.expressroute_gateway.name}
        params["virtualHubId"] = {"value": self.expressroute_gateway.virtual_hub_id}
        params["scaleUnit"] = {"value": self.expressroute_gateway.scale_unit}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


# Management operators
class LogAnalyticsSpec(BaseSpec):
    """Log Analytics operator specification."""

    log_analytics: LogAnalyticsConfig = Field(alias="workspace")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["logAnalyticsName"] = {"value": self.log_analytics.name}
        params["logAnalyticsRetentionDays"] = {"value": self.log_analytics.retention_days}
        params["logAnalyticsSku"] = {"value": self.log_analytics.sku}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class AutomationSpec(BaseSpec):
    """Automation operator specification."""

    automation: AutomationConfig = Field(alias="automationAccount")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        params["automationAccountName"] = {"value": self.automation.name}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class MonitorSpec(BaseSpec):
    """Monitor operator specification (DCRs, alerts)."""

    data_collection_rules: list[DataCollectionRuleConfig] = Field(
        default_factory=list, alias="dataCollectionRules"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        if self.data_collection_rules:
            params["dataCollectionRules"] = {
                "value": [
                    {
                        "name": dcr.name,
                        "description": dcr.description,
                        "streams": dcr.streams,
                    }
                    for dcr in self.data_collection_rules
                ]
            }
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


# Security operators
class DefenderPlanConfig(BaseModel):
    """Defender plan configuration."""

    model_config = {"extra": "ignore"}

    name: str
    pricing_tier: str = Field("Standard", alias="pricingTier")
    sub_plan: str | None = Field(None, alias="subPlan")


class DefenderSecurityContactConfig(BaseModel):
    """Defender security contact configuration."""

    model_config = {"extra": "ignore"}

    email: str
    phone: str | None = None
    alert_notifications: str = Field("On", alias="alertNotifications")
    alerts_to_admins: str = Field("On", alias="alertsToAdmins")


class DefenderSpec(BaseSpec):
    """Defender operator specification.

    Supports both legacy format (defender: DefenderConfig) and
    new format (enabledPlans, securityContacts at root).
    """

    # Legacy format
    defender: DefenderConfig | None = None

    # New format - inline fields
    management_group_id: str | None = Field(None, alias="managementGroupId")
    enabled_plans: list[DefenderPlanConfig] = Field(default_factory=list, alias="enabledPlans")
    security_contacts: list[DefenderSecurityContactConfig] = Field(
        default_factory=list, alias="securityContacts"
    )
    auto_provisioning: dict[str, str] | None = Field(None, alias="autoProvisioning")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}

        # Handle legacy format
        if self.defender:
            params["defenderPricingTier"] = {"value": self.defender.pricing_tier}
            if self.defender.plans:
                params["defenderPlans"] = {"value": self.defender.plans}
            if self.defender.security_contacts:
                params["securityContacts"] = {
                    "value": [
                        {"email": c.email, "phone": c.phone}
                        for c in self.defender.security_contacts
                    ]
                }
        # Handle new format
        else:
            if self.enabled_plans:
                params["enabledPlans"] = {
                    "value": [
                        {"name": p.name, "pricingTier": p.pricing_tier, "subPlan": p.sub_plan}
                        for p in self.enabled_plans
                    ]
                }
            if self.security_contacts:
                params["securityContacts"] = {
                    "value": [
                        {
                            "email": c.email,
                            "phone": c.phone,
                            "alertNotifications": c.alert_notifications,
                        }
                        for c in self.security_contacts
                    ]
                }
            if self.auto_provisioning:
                params["autoProvisioning"] = {"value": self.auto_provisioning}

        if self.management_group_id:
            params["managementGroupId"] = {"value": self.management_group_id}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class KeyVaultSpec(BaseSpec):
    """Key Vault operator specification."""

    key_vaults: list[KeyVaultConfig] = Field(default_factory=list, alias="keyVaults")

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}
        if self.key_vaults:
            params["keyVaults"] = {
                "value": [
                    {
                        "name": kv.name,
                        "sku": kv.sku,
                        "enablePurgeProtection": kv.enable_purge_protection,
                        "enableSoftDelete": kv.enable_soft_delete,
                        "softDeleteRetentionDays": kv.soft_delete_retention_days,
                        "enableRbacAuthorization": kv.enable_rbac_authorization,
                    }
                    for kv in self.key_vaults
                ]
            }
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


class SentinelWorkspaceConfig(BaseModel):
    """Sentinel workspace reference configuration."""

    model_config = {"extra": "ignore"}

    name: str
    resource_group: str | None = Field(None, alias="resourceGroup")


class SentinelSpec(BaseSpec):
    """Sentinel operator specification.

    Supports both legacy format (workspaceName as string) and
    new format (workspace as object with name/resourceGroup).
    """

    # Legacy format
    workspace_name: str | None = Field(None, alias="workspaceName")

    # New format
    workspace: SentinelWorkspaceConfig | None = None

    enabled: bool = True
    data_connectors: list[dict[str, Any]] = Field(default_factory=list, alias="dataConnectors")
    analytics_rules: dict[str, Any] | None = Field(None, alias="analyticsRules")
    automation_rules: list[dict[str, Any]] = Field(default_factory=list, alias="automationRules")
    playbooks: list[dict[str, Any]] = Field(default_factory=list)

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.location:
            params["location"] = {"value": self.location}
        if self.resource_group_name:
            params["resourceGroupName"] = {"value": self.resource_group_name}

        # Handle both formats
        if self.workspace_name:
            params["workspaceName"] = {"value": self.workspace_name}
        elif self.workspace:
            params["workspaceName"] = {"value": self.workspace.name}
            if self.workspace.resource_group:
                params["workspaceResourceGroup"] = {"value": self.workspace.resource_group}

        params["sentinelEnabled"] = {"value": self.enabled}
        if self.tags:
            params["tags"] = {"value": self.tags}
        return params


# Governance operators
class ManagementGroupSpec(BaseSpec):
    """Management Group operator specification."""

    root_management_group_name: str | None = Field(None, alias="rootManagementGroupName")
    management_groups: list[ManagementGroupConfig] = Field(
        default_factory=list, alias="managementGroups"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.root_management_group_name:
            params["rootManagementGroupName"] = {"value": self.root_management_group_name}
        if self.management_groups:
            params["managementGroups"] = {
                "value": [
                    {
                        "name": mg.name,
                        "displayName": mg.display_name,
                        "parentId": mg.parent_id,
                    }
                    for mg in self.management_groups
                ]
            }
        return params


class RoleSpec(BaseSpec):
    """Role operator specification (RBAC)."""

    custom_roles: list[CustomRoleConfig] = Field(default_factory=list, alias="customRoles")
    role_assignments: list[RoleAssignmentConfig] = Field(
        default_factory=list, alias="roleAssignments"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.custom_roles:
            params["customRoles"] = {
                "value": [
                    {
                        "name": r.name,
                        "description": r.description,
                        "actions": r.actions,
                        "notActions": r.not_actions,
                        "dataActions": r.data_actions,
                        "notDataActions": r.not_data_actions,
                        "assignableScopes": r.assignable_scopes,
                    }
                    for r in self.custom_roles
                ]
            }
        if self.role_assignments:
            params["roleAssignments"] = {
                "value": [
                    {
                        "principalId": a.principal_id,
                        "principalType": a.principal_type,
                        "roleDefinitionId": a.role_definition_id,
                        "scope": a.scope,
                    }
                    for a in self.role_assignments
                ]
            }
        return params


class PolicySpec(BaseSpec):
    """Policy domain specification."""

    root_management_group_name: str = Field(alias="managementGroupId")
    management_groups: list[ManagementGroupConfig] = Field(
        default_factory=list, alias="managementGroups"
    )
    custom_policies: list[CustomPolicyConfig] = Field(default_factory=list, alias="customPolicies")
    policy_assignments: list[PolicyAssignmentConfig] = Field(
        default_factory=list, alias="policyAssignments"
    )

    def to_arm_parameters(self) -> dict[str, Any]:
        """Convert to ARM template parameters."""
        params: dict[str, Any] = {}

        params["rootManagementGroupName"] = {"value": self.root_management_group_name}

        if self.management_groups:
            params["managementGroups"] = {
                "value": [
                    {
                        "name": mg.name,
                        "displayName": mg.display_name,
                        "parentId": mg.parent_id,
                    }
                    for mg in self.management_groups
                ]
            }

        if self.custom_policies:
            params["customPolicies"] = {
                "value": [
                    {
                        "name": p.name,
                        "displayName": p.display_name,
                        "description": p.description,
                        "mode": p.mode,
                        "policyRule": p.policy_rule,
                    }
                    for p in self.custom_policies
                ]
            }

        if self.policy_assignments:
            params["policyAssignments"] = {
                "value": [
                    {
                        "name": a.name,
                        "policyDefinitionId": a.policy_definition_id,
                        "scope": a.scope,
                        "parameters": a.parameters,
                        "enforcementMode": a.enforcement_mode,
                        "nonComplianceMessage": a.non_compliance_message,
                    }
                    for a in self.policy_assignments
                ]
            }

        if self.tags:
            params["tags"] = {"value": self.tags}

        return params


# =============================================================================
# Bootstrap Cascade Domain
# =============================================================================

# SECURITY: High-privilege roles that require explicit allowlisting
# These roles grant broad permissions and should not be assigned without
# explicit configuration to prevent privilege escalation
HIGH_PRIVILEGE_ROLES: frozenset[str] = frozenset({
    "Owner",
    "User Access Administrator",
    "Contributor",  # Too broad for most operators
})

# SECURITY: Scope patterns that indicate overly broad assignments
# Assignments at these scopes are blocked by default
DENIED_SCOPE_PATTERNS: tuple[str, ...] = (
    "/",  # Tenant root (just a slash)
    "/providers/Microsoft.Management/managementGroups/",  # Bare MG without ID
)

# SECURITY: Root management group scope patterns to deny
ROOT_MG_PATTERNS: tuple[str, ...] = (
    "Tenant Root Group",
    "Root Management Group",
)


class RoleAssignmentDefinition(BaseModel):
    """RBAC role assignment definition for an operator identity.

    SECURITY: Validates that role assignments follow least-privilege principles:
    - Denies high-privilege roles (Owner, UAA, Contributor) by default
    - Denies assignments at tenant root or bare management group scopes
    - Requires explicit scope (subscription, RG, or resource level)
    """

    model_config = {"extra": "ignore", "populate_by_name": True}

    role_definition_name: Annotated[str, Field(min_length=1, alias="roleDefinitionName")]
    scope: Annotated[str, Field(min_length=1)]
    description: str | None = None

    @field_validator("role_definition_name")
    @classmethod
    def validate_role_not_high_privilege(cls, v: str) -> str:
        """Deny high-privilege roles unless explicitly allowed.

        SECURITY: Operators should use least-privilege roles.
        Owner, UAA, and Contributor are too broad for automated operators.

        To override, set ALLOW_HIGH_PRIVILEGE_ROLES=true in bootstrap environment.
        """
        import os

        allow_high_priv = os.environ.get("ALLOW_HIGH_PRIVILEGE_ROLES", "").lower() in (
            "true", "1", "yes"
        )

        if not allow_high_priv and v in HIGH_PRIVILEGE_ROLES:
            raise ValueError(
                f"Role '{v}' is a high-privilege role and is denied by default. "
                f"Use a more specific role (e.g., 'Network Contributor', 'Reader') "
                f"or set ALLOW_HIGH_PRIVILEGE_ROLES=true to override."
            )
        return v

    @field_validator("scope")
    @classmethod
    def validate_scope_not_too_broad(cls, v: str) -> str:
        """Deny overly broad scopes that could lead to privilege escalation.

        SECURITY: Scopes must be specific (subscription, RG, or resource).
        Tenant root and bare management group scopes are denied.
        """
        import os

        allow_broad = os.environ.get("ALLOW_BROAD_RBAC_SCOPES", "").lower() in (
            "true", "1", "yes"
        )

        if allow_broad:
            return v

        # Check for denied patterns
        scope_lower = v.lower().strip()

        # Deny bare slash (tenant root)
        if scope_lower == "/" or scope_lower == "":
            raise ValueError(
                "Role assignment scope '/' (tenant root) is denied. "
                "Use a subscription or resource group scope instead."
            )

        # Deny root management group patterns
        for root_pattern in ROOT_MG_PATTERNS:
            if root_pattern.lower() in scope_lower:
                raise ValueError(
                    f"Role assignment at root management group '{root_pattern}' is denied. "
                    f"Scope to a child management group or subscription instead."
                )

        # Validate scope format - must start with /subscriptions/ or /providers/Microsoft.Management/managementGroups/{id}
        if not scope_lower.startswith("/subscriptions/"):
            # Check if it's a valid management group scope with an ID
            if scope_lower.startswith("/providers/microsoft.management/managementgroups/"):
                # Extract the MG ID portion
                parts = v.split("/")
                # Pattern: /providers/Microsoft.Management/managementGroups/{mgId}
                if len(parts) < 5 or not parts[4]:
                    raise ValueError(
                        "Management group scope must include the management group ID. "
                        "Example: /providers/Microsoft.Management/managementGroups/mg-platform"
                    )
            else:
                raise ValueError(
                    f"Invalid scope format: '{v}'. "
                    f"Scope must start with '/subscriptions/' or be a valid management group path."
                )

        return v


class OperatorIdentityConfig(BaseModel):
    """Configuration for a single operator's managed identity and RBAC.

    Each operator gets:
    - A User-Assigned Managed Identity (UAMI)
    - One or more RBAC role assignments scoped to specific resources

    SECURITY: Role assignments are validated to ensure least-privilege.
    """

    model_config = {"extra": "ignore"}

    # Operator identification
    name: Annotated[str, Field(min_length=1, max_length=128)]
    display_name: str | None = Field(None, alias="displayName")

    # Deployment target for the operator
    scope: str = "subscription"  # "subscription" or "management_group"
    subscription_id: str | None = Field(None, alias="subscriptionId")
    management_group_id: str | None = Field(None, alias="managementGroupId")

    # RBAC assignments for this operator
    role_assignments: list[RoleAssignmentDefinition] = Field(
        default_factory=list, alias="roleAssignments"
    )

    # Container configuration (optional, for ACI deployment)
    cpu_cores: float = Field(0.5, alias="cpuCores", ge=0.1, le=4.0)
    memory_gb: float = Field(1.0, alias="memoryGb", ge=0.5, le=16.0)

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        valid_scopes = {"subscription", "management_group"}
        if v not in valid_scopes:
            raise ValueError(f"scope must be one of {valid_scopes}")
        return v

class BootstrapSpec(BaseSpec):
    """Bootstrap cascade specification.

    The bootstrap operator (management) provisions:
    1. User-Assigned Managed Identities for all downstream operators
    2. RBAC role assignments for each identity
    3. Optionally, ACI container groups for operators

    This creates a cascade where:
    - Phase 0: Infrastructure deploys Bootstrap operator with constrained UAA
    - Phase 1: Bootstrap operator reads this spec and provisions all identities
    - Phase 2: Other operators start and use their provisioned UAMIs

    Tokens remain ephemeral - only the identity infrastructure is provisioned.
    """

    # Resource group where operator identities are created
    identity_resource_group: Annotated[str, Field(min_length=1, alias="identityResourceGroup")]

    # Resource group where operators (ACI) are deployed
    operators_resource_group: str | None = Field(None, alias="operatorsResourceGroup")

    # ACR for operator images
    container_registry: str | None = Field(None, alias="containerRegistry")
    operator_image_tag: str = Field("latest", alias="operatorImageTag")

    # Operator identity definitions
    operators: list[OperatorIdentityConfig] = Field(default_factory=list)

    # RBAC propagation wait time (Azure AD replication delay)
    # SECURITY: Minimum 60s required - Azure AD replication typically needs 60-120s
    rbac_propagation_seconds: int = Field(120, alias="rbacPropagationSeconds", ge=60, le=600)

    # Deploy operators as ACI containers (vs just creating identities)
    deploy_operators: bool = Field(True, alias="deployOperators")

    def to_arm_parameters(self) -> dict[str, Any]:
        """Convert spec to ARM parameters for identity provisioning."""
        params: dict[str, Any] = {
            "location": {"value": self.location},
            "identityResourceGroup": {"value": self.identity_resource_group},
            "tags": {"value": self.tags},
        }

        if self.operators_resource_group:
            params["operatorsResourceGroup"] = {"value": self.operators_resource_group}
        if self.container_registry:
            params["containerRegistry"] = {"value": self.container_registry}

        # Serialize operator configs
        params["operators"] = {
            "value": [
                {
                    "name": op.name,
                    "displayName": op.display_name or f"Azure Operator - {op.name}",
                    "scope": op.scope,
                    "subscriptionId": op.subscription_id,
                    "managementGroupId": op.management_group_id,
                    "roleAssignments": [
                        {
                            "roleDefinitionName": ra.role_definition_name,
                            "scope": ra.scope,
                            "description": ra.description,
                        }
                        for ra in op.role_assignments
                    ],
                    "cpuCores": op.cpu_cores,
                    "memoryGb": op.memory_gb,
                }
                for op in self.operators
            ]
        }

        return params


# Registry mapping operator names to spec classes
SPEC_REGISTRY: dict[str, type[BaseSpec]] = {
    # Bootstrap cascade operator (provisions downstream identities)
    "bootstrap": BootstrapSpec,
    # Granular connectivity operators - Hub-Spoke topology
    "firewall": FirewallSpec,
    "vpn-gateway": VpnGatewaySpec,
    "expressroute": ExpressRouteSpec,
    "bastion": BastionSpec,
    "dns": DnsSpec,
    "hub-network": HubNetworkSpec,
    # Granular connectivity operators - vWAN topology (per-resource)
    "vwan": VwanSpec,
    "vwan-hub": VwanHubSpec,
    "vwan-firewall": VwanFirewallSpec,
    "vwan-vpn-gateway": VwanVpnGatewaySpec,
    "vwan-expressroute": VwanExpressRouteSpec,
    # Granular management operators
    "log-analytics": LogAnalyticsSpec,
    "automation": AutomationSpec,
    "monitor": MonitorSpec,
    # Granular security operators
    "defender": DefenderSpec,
    "keyvault": KeyVaultSpec,
    "sentinel": SentinelSpec,
    # Granular governance operators
    "management-group": ManagementGroupSpec,
    "policy": PolicySpec,
    "role": RoleSpec,
    # Secondary region specs (reuse primary spec classes)
    # Multi-region archetypes use -secondary suffix for second region
    "bastion-secondary": BastionSpec,
    "firewall-secondary": FirewallSpec,
    "hub-network-secondary": HubNetworkSpec,
    "vpn-gateway-secondary": VpnGatewaySpec,
    "expressroute-secondary": ExpressRouteSpec,
    "dns-secondary": DnsSpec,
    "vwan-hub-secondary": VwanHubSpec,
    "vwan-firewall-secondary": VwanFirewallSpec,
    "vwan-vpn-gateway-secondary": VwanVpnGatewaySpec,
    "vwan-expressroute-secondary": VwanExpressRouteSpec,
}


def get_spec_class(domain: str) -> type[BaseSpec]:
    """Get the spec class for a domain.

    Raises:
        ValueError: If domain is not recognized.
    """
    spec_class = SPEC_REGISTRY.get(domain)
    if spec_class is None:
        valid_domains = list(SPEC_REGISTRY.keys())
        raise ValueError(f"Unknown domain '{domain}'. Valid domains: {valid_domains}")
    return spec_class
