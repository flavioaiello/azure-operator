// ============================================================================
// Management Operator - Bicep Entry Point
// ============================================================================
// This module deploys management resources for Azure Landing Zones:
// - Log Analytics Workspace
// - Automation Account
// - Data Collection Rules
// - User-Assigned Managed Identities
//
// Leverages AVM modules from bicep-registry-modules
// ============================================================================

targetScope = 'subscription'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The location for all resources.')
param location string

@description('Required. The name of the resource group for management resources.')
param resourceGroupName string

@description('Required. The name of the Log Analytics workspace.')
param logAnalyticsWorkspaceName string

@description('Optional. The retention period for Log Analytics data in days.')
@minValue(30)
@maxValue(730)
param logAnalyticsRetentionDays int = 365

@description('Optional. The SKU for Log Analytics workspace.')
@allowed([
  'PerGB2018'
  'CapacityReservation'
])
param logAnalyticsSku string = 'PerGB2018'

@description('Optional. Enable/Disable usage telemetry for module.')
param enableTelemetry bool = true

@description('Optional. Tags to apply to all resources.')
param tags object = {}

@description('Optional. Automation Account name. Leave empty to skip.')
param automationAccountName string = ''

@description('Optional. User-Assigned Managed Identities to create.')
param userAssignedIdentities array = []

@description('Optional. Data Collection Rules to create.')
param dataCollectionRules array = []

// ============================================================================
// Resources
// ============================================================================

// Resource Group for Management resources
resource managementRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

// Log Analytics Workspace
module logAnalyticsWorkspace 'br/public:avm/res/operational-insights/workspace:0.9.1' = {
  name: 'deploy-law-${uniqueString(deployment().name, location)}'
  scope: managementRg
  params: {
    name: logAnalyticsWorkspaceName
    location: location
    skuName: logAnalyticsSku
    dataRetention: logAnalyticsRetentionDays
    enableTelemetry: enableTelemetry
    tags: tags
  }
}

// Automation Account (optional)
module automationAccount 'br/public:avm/res/automation/automation-account:0.11.1' = if (!empty(automationAccountName)) {
  name: 'deploy-aa-${uniqueString(deployment().name, location)}'
  scope: managementRg
  params: {
    name: automationAccountName
    location: location
    linkedWorkspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
    enableTelemetry: enableTelemetry
    tags: tags
  }
}

// User-Assigned Managed Identities
module managedIdentities 'br/public:avm/res/managed-identity/user-assigned-identity:0.4.1' = [
  for (identity, index) in userAssignedIdentities: {
    name: 'deploy-uami-${index}-${uniqueString(deployment().name, location)}'
    scope: managementRg
    params: {
      name: identity.name
      location: location
      enableTelemetry: enableTelemetry
      tags: union(tags, identity.?tags ?? {})
    }
  }
]

// Data Collection Rules
module dcr 'br/public:avm/res/insights/data-collection-rule:0.4.2' = [
  for (rule, index) in dataCollectionRules: {
    name: 'deploy-dcr-${index}-${uniqueString(deployment().name, location)}'
    scope: managementRg
    params: {
      name: rule.name
      location: location
      kind: rule.?kind ?? 'Linux'
      dataFlows: rule.dataFlows
      dataSources: rule.?dataSources ?? {}
      destinations: {
        logAnalytics: [
          {
            name: 'defaultWorkspace'
            workspaceResourceId: logAnalyticsWorkspace.outputs.resourceId
          }
        ]
      }
      enableTelemetry: enableTelemetry
      tags: union(tags, rule.?tags ?? {})
    }
  }
]

// ============================================================================
// Outputs
// ============================================================================

@description('The resource ID of the Log Analytics workspace.')
output logAnalyticsWorkspaceId string = logAnalyticsWorkspace.outputs.resourceId

@description('The name of the Log Analytics workspace.')
output logAnalyticsWorkspaceName string = logAnalyticsWorkspace.outputs.name

@description('The resource ID of the management resource group.')
output resourceGroupId string = managementRg.id

@description('The resource ID of the Automation Account.')
output automationAccountId string = !empty(automationAccountName) ? automationAccount.outputs.resourceId : ''

@description('The resource IDs of User-Assigned Managed Identities.')
output managedIdentityIds array = [for (identity, index) in userAssignedIdentities: managedIdentities[index].outputs.resourceId]
