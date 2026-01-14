// ============================================================================
// Azure Operator Infrastructure - Fine-Grained RBAC Assignments
// ============================================================================
// Assigns least-privilege roles to each operator managed identity
// Each operator gets ONLY the permissions needed for its specific concern
// Must be deployed separately after main infrastructure with elevated permissions
// ============================================================================

targetScope = 'managementGroup'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The principal IDs of operator managed identities (one per concern).')
param operatorPrincipalIds object = {
  // Connectivity operators
  firewall: ''
  vpnGateway: ''
  expressroute: ''
  bastion: ''
  dns: ''
  hubNetwork: ''
  // Management operators
  logAnalytics: ''
  automation: ''
  monitor: ''
  // Security operators
  defender: ''
  keyvault: ''
  sentinel: ''
  // Governance operators
  managementGroup: ''
  role: ''
}

@description('Required. Subscription IDs for subscription-scoped operators.')
param subscriptionIds object = {
  management: ''
  connectivity: ''
  security: ''
}

@description('Required. Root management group ID.')
param rootManagementGroupId string

@description('Optional. Location for deployment metadata.')
param location string = 'westeurope'

// ============================================================================
// Built-in Role Definition IDs
// ============================================================================

// General roles
var contributorRoleId = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
var readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

// Network-specific roles
var networkContributorRoleId = '4d97b98b-1d4f-4787-a291-c67834d212e7'

// Security-specific roles
var securityAdminRoleId = 'fb1c8493-542b-48eb-b624-b4c8fea62acd'
var keyVaultAdministratorRoleId = '00482a5a-887f-4fb3-b363-3b7fe8e74483'

// Monitoring-specific roles
var logAnalyticsContributorRoleId = '92aaf0da-9dab-42b6-94a3-d43ce8d16293'
var monitoringContributorRoleId = '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
var automationContributorRoleId = 'f353d9bd-d4a6-484e-a77a-8050b599b867'

// Governance roles
var managementGroupContributorRoleId = '5d58bcaf-24a5-4b20-bdb6-eed9f69fbe4c'
var resourcePolicyContributorRoleId = '36243c78-bf99-498c-9df9-86d9f8d28608'
var userAccessAdministratorRoleId = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'

// DNS-specific roles
var privateDnsZoneContributorRoleId = 'b12aa53e-6015-4669-85d0-8515ebb3ae7f'

// ============================================================================
// CONNECTIVITY OPERATORS - Subscription Scope (Connectivity)
// ============================================================================

// Firewall Operator - Network Contributor only
module firewallOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.firewall)) {
  name: 'deploy-rbac-firewall'
  scope: subscription(subscriptionIds.connectivity)
  params: {
    principalId: operatorPrincipalIds.firewall
    roleDefinitionId: networkContributorRoleId
    description: 'Firewall operator - Network Contributor for Azure Firewall management'
  }
}

// VPN Gateway Operator - Network Contributor only
module vpnGatewayOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.vpnGateway)) {
  name: 'deploy-rbac-vpn-gateway'
  scope: subscription(subscriptionIds.connectivity)
  params: {
    principalId: operatorPrincipalIds.vpnGateway
    roleDefinitionId: networkContributorRoleId
    description: 'VPN Gateway operator - Network Contributor for VPN Gateway management'
  }
}

// ExpressRoute Operator - Network Contributor only
module expressrouteOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.expressroute)) {
  name: 'deploy-rbac-expressroute'
  scope: subscription(subscriptionIds.connectivity)
  params: {
    principalId: operatorPrincipalIds.expressroute
    roleDefinitionId: networkContributorRoleId
    description: 'ExpressRoute operator - Network Contributor for ExpressRoute management'
  }
}

// Bastion Operator - Network Contributor only
module bastionOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.bastion)) {
  name: 'deploy-rbac-bastion'
  scope: subscription(subscriptionIds.connectivity)
  params: {
    principalId: operatorPrincipalIds.bastion
    roleDefinitionId: networkContributorRoleId
    description: 'Bastion operator - Network Contributor for Azure Bastion management'
  }
}

// DNS Operator - Private DNS Zone Contributor
module dnsOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.dns)) {
  name: 'deploy-rbac-dns'
  scope: subscription(subscriptionIds.connectivity)
  params: {
    principalId: operatorPrincipalIds.dns
    roleDefinitionId: privateDnsZoneContributorRoleId
    description: 'DNS operator - Private DNS Zone Contributor for DNS management'
  }
}

// Hub Network Operator - Network Contributor only
module hubNetworkOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.hubNetwork)) {
  name: 'deploy-rbac-hub-network'
  scope: subscription(subscriptionIds.connectivity)
  params: {
    principalId: operatorPrincipalIds.hubNetwork
    roleDefinitionId: networkContributorRoleId
    description: 'Hub Network operator - Network Contributor for Hub VNet management'
  }
}

// ============================================================================
// MANAGEMENT OPERATORS - Subscription Scope (Management)
// ============================================================================

// Log Analytics Operator - Log Analytics Contributor
module logAnalyticsOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.logAnalytics)) {
  name: 'deploy-rbac-log-analytics'
  scope: subscription(subscriptionIds.management)
  params: {
    principalId: operatorPrincipalIds.logAnalytics
    roleDefinitionId: logAnalyticsContributorRoleId
    description: 'Log Analytics operator - Log Analytics Contributor'
  }
}

// Automation Operator - Automation Contributor
module automationOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.automation)) {
  name: 'deploy-rbac-automation'
  scope: subscription(subscriptionIds.management)
  params: {
    principalId: operatorPrincipalIds.automation
    roleDefinitionId: automationContributorRoleId
    description: 'Automation operator - Automation Contributor'
  }
}

// Monitor Operator - Monitoring Contributor
module monitorOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.monitor)) {
  name: 'deploy-rbac-monitor'
  scope: subscription(subscriptionIds.management)
  params: {
    principalId: operatorPrincipalIds.monitor
    roleDefinitionId: monitoringContributorRoleId
    description: 'Monitor operator - Monitoring Contributor for DCRs and alerts'
  }
}

// ============================================================================
// SECURITY OPERATORS - Subscription Scope (Security)
// ============================================================================

// Defender Operator - Security Admin
module defenderOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.defender)) {
  name: 'deploy-rbac-defender'
  scope: subscription(subscriptionIds.security)
  params: {
    principalId: operatorPrincipalIds.defender
    roleDefinitionId: securityAdminRoleId
    description: 'Defender operator - Security Admin for Defender for Cloud'
  }
}

// Key Vault Operator - Key Vault Administrator
module keyvaultOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.keyvault)) {
  name: 'deploy-rbac-keyvault'
  scope: subscription(subscriptionIds.security)
  params: {
    principalId: operatorPrincipalIds.keyvault
    roleDefinitionId: keyVaultAdministratorRoleId
    description: 'Key Vault operator - Key Vault Administrator'
  }
}

// Sentinel Operator - Log Analytics Contributor (for Sentinel workspace)
module sentinelOperatorRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.sentinel)) {
  name: 'deploy-rbac-sentinel'
  scope: subscription(subscriptionIds.security)
  params: {
    principalId: operatorPrincipalIds.sentinel
    roleDefinitionId: logAnalyticsContributorRoleId
    description: 'Sentinel operator - Log Analytics Contributor for Sentinel'
  }
}

// Sentinel also needs Security Admin for security features
module sentinelSecurityRbac 'modules/subscription-rbac.bicep' = if (!empty(operatorPrincipalIds.sentinel)) {
  name: 'deploy-rbac-sentinel-security'
  scope: subscription(subscriptionIds.security)
  params: {
    principalId: operatorPrincipalIds.sentinel
    roleDefinitionId: securityAdminRoleId
    description: 'Sentinel operator - Security Admin for Sentinel analytics'
  }
}

// ============================================================================
// GOVERNANCE OPERATORS - Management Group Scope
// ============================================================================

// Management Group Operator - Management Group Contributor only
resource mgOperatorMgContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorPrincipalIds.managementGroup)) {
  name: guid(rootManagementGroupId, operatorPrincipalIds.managementGroup, managementGroupContributorRoleId)
  properties: {
    principalId: operatorPrincipalIds.managementGroup
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', managementGroupContributorRoleId)
    principalType: 'ServicePrincipal'
    description: 'Management Group operator - MG Contributor for hierarchy management'
  }
}

// Role Operator - User Access Administrator + Reader
resource roleOperatorUaa 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorPrincipalIds.role)) {
  name: guid(rootManagementGroupId, operatorPrincipalIds.role, userAccessAdministratorRoleId)
  properties: {
    principalId: operatorPrincipalIds.role
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', userAccessAdministratorRoleId)
    principalType: 'ServicePrincipal'
    description: 'Role operator - User Access Administrator for RBAC management'
  }
}

resource roleOperatorReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorPrincipalIds.role)) {
  name: guid(rootManagementGroupId, operatorPrincipalIds.role, readerRoleId)
  properties: {
    principalId: operatorPrincipalIds.role
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', readerRoleId)
    principalType: 'ServicePrincipal'
    description: 'Role operator - Reader for resource discovery'
  }
}

// ============================================================================
// Outputs
// ============================================================================

@description('RBAC assignments created.')
output rbacAssigned bool = true

@description('Number of operators with RBAC configured.')
output operatorCount int = 15
4