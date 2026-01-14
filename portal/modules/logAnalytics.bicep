// ============================================================================
// Azure Landing Zones Operator - Log Analytics Module
// ============================================================================
// Creates a Log Analytics workspace for operator monitoring and diagnostics.
// ============================================================================

targetScope = 'resourceGroup'

// Parameters
@description('Name of the Log Analytics workspace')
param workspaceName string

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('Retention period in days')
@minValue(30)
@maxValue(730)
param retentionDays int = 90

@description('SKU for the workspace')
@allowed(['Free', 'PerGB2018', 'PerNode', 'Premium', 'Standalone', 'Standard'])
param sku string = 'PerGB2018'

@description('Tags to apply to the workspace')
param tags object = {}

// Resources
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: location
  tags: union(tags, {
    purpose: 'azure-operator-monitoring'
    managedBy: 'azure-operator'
  })
  properties: {
    sku: {
      name: sku
    }
    retentionInDays: retentionDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: -1 // No daily cap
    }
  }
}

// Container Insights solution for ACI logs
resource containerInsightsSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'ContainerInsights(${logAnalyticsWorkspace.name})'
  location: location
  tags: tags
  properties: {
    workspaceResourceId: logAnalyticsWorkspace.id
  }
  plan: {
    name: 'ContainerInsights(${logAnalyticsWorkspace.name})'
    publisher: 'Microsoft'
    product: 'OMSGallery/ContainerInsights'
    promotionCode: ''
  }
}

// Outputs
@description('Log Analytics workspace resource ID')
output workspaceId string = logAnalyticsWorkspace.id

@description('Log Analytics workspace resource ID (alias for listKeys usage)')
output resourceId string = logAnalyticsWorkspace.id

@description('Log Analytics workspace name')
output workspaceName string = logAnalyticsWorkspace.name

@description('Log Analytics customer ID (for container diagnostics)')
output customerId string = logAnalyticsWorkspace.properties.customerId

// SECURITY: primarySharedKey output removed to prevent secret exposure in deployment history.
// Use listKeys() inline at consumption site or migrate to Azure Monitor Agent with managed identity.
// See: https://learn.microsoft.com/en-us/azure/azure-monitor/containers/container-insights-authentication
