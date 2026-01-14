// ============================================================================
// Azure Landing Zones Operator - Main Deployment
// ============================================================================
// Orchestrates the deployment of all operator infrastructure components:
// - Resource Group
// - Bootstrap Identity (UAMI)
// - RBAC Role Assignment
// - Log Analytics Workspace
// - Container Group (Operator + Git-Sync)
// ============================================================================

targetScope = 'subscription'

// Parameters
@description('Azure region for deployment')
param location string

@description('Name of the resource group for operator infrastructure')
param resourceGroupName string = 'rg-azure-operator'

@description('Name of the bootstrap identity')
param bootstrapIdentityName string = 'uami-azure-operator-bootstrap'

@description('Git repository URL for specs')
param gitRepoUrl string

@description('Git branch to sync')
param gitBranch string = 'main'

@description('Path to specs within the repository')
param gitSpecsPath string = 'specs/'

@description('Git sync interval in seconds')
@minValue(30)
@maxValue(600)
param gitSyncIntervalSeconds int = 60

@description('Reconciliation interval in seconds')
@minValue(60)
@maxValue(3600)
param reconcileIntervalSeconds int = 300

@description('Enable dry-run mode (detect drift without applying)')
param dryRun bool = false

@description('Operator container image')
param containerImage string = 'ghcr.io/flavioaiello/azure-operator:latest'

@description('Create a new Log Analytics workspace')
param createLogAnalytics bool = true

@description('Tags to apply to all resources')
param tags object = {
  deployedBy: 'azure-operator-wizard'
  environment: 'production'
}

// Variables
var logAnalyticsName = 'log-azure-operator-${uniqueString(resourceGroupName)}'
// Construct resource ID for listKeys() - must be compile-time evaluable
var logAnalyticsResourceId = resourceId(subscription().subscriptionId, resourceGroupName, 'Microsoft.OperationalInsights/workspaces', logAnalyticsName)

// Resource Group
resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

// Bootstrap Identity
module identity 'modules/identity.bicep' = {
  name: 'deploy-identity'
  scope: rg
  params: {
    identityName: bootstrapIdentityName
    location: location
    tags: tags
  }
}

// RBAC: Owner at subscription scope for bootstrap
// SECURITY NOTE: This grants Owner at subscription scope which is overly permissive.
// This is intentional for the Azure Portal wizard deployment to bootstrap operators.
// After initial deployment, consider:
// 1. Scope down to specific resource groups
// 2. Use a custom role with only required permissions:
//    - Microsoft.ManagedIdentity/userAssignedIdentities/* (for creating operator identities)
//    - Microsoft.Authorization/roleAssignments/write (with conditions)
//    - Microsoft.ContainerInstance/containerGroups/* (for deploying operators)
// See: https://learn.microsoft.com/azure/role-based-access-control/custom-roles
resource ownerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, bootstrapIdentityName, 'Owner')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' // Owner
    )
    principalId: identity.outputs.principalId
    principalType: 'ServicePrincipal'
    description: 'Bootstrap identity for azure-operator - Owner at subscription scope (reduce after initial setup)'
  }
}

// Log Analytics (optional)
module logAnalytics 'modules/logAnalytics.bicep' = if (createLogAnalytics) {
  name: 'deploy-log-analytics'
  scope: rg
  params: {
    workspaceName: logAnalyticsName
    location: location
    retentionDays: 90
    tags: tags
  }
}

// Container Group with operator
module containerGroup 'modules/containerGroup.bicep' = {
  name: 'deploy-container-group'
  scope: rg
  dependsOn: [
    ownerRoleAssignment // Wait for RBAC to propagate
    logAnalytics // Ensure Log Analytics is created before listKeys() is called
  ]
  params: {
    containerGroupName: 'azure-operator-bootstrap'
    location: location
    operatorImage: containerImage
    identityResourceId: identity.outputs.identityResourceId
    identityClientId: identity.outputs.clientId
    operatorDomain: 'bootstrap'
    gitRepoUrl: gitRepoUrl
    gitBranch: gitBranch
    gitSpecsPath: gitSpecsPath
    gitSyncIntervalSeconds: gitSyncIntervalSeconds
    reconcileIntervalSeconds: reconcileIntervalSeconds
    dryRun: dryRun
    // SECURITY: Use listKeys() inline at consumption rather than passing through outputs.
    // This avoids persisting the key in multiple deployment layers.
    // TECH DEBT: Migrate to Azure Monitor Agent with managed identity to eliminate keys entirely.
    // Tracked in: https://github.com/example/azure-operator/issues/1 (Long-term remediation)
    // Risk: Primary shared key is used for container log ingestion. Acceptable for now as:
    // 1. Key is not exposed in outputs (consumed inline only)
    // 2. Container logs are non-sensitive operational telemetry
    // 3. AMA migration requires DCR infrastructure not yet implemented
    logAnalyticsWorkspaceId: createLogAnalytics ? logAnalytics.outputs.customerId : ''
    // Use pre-computed resource ID for listKeys() to satisfy compile-time requirement
    logAnalyticsWorkspaceKey: createLogAnalytics ? listKeys(logAnalyticsResourceId, '2022-10-01').primarySharedKey : ''
    tags: tags
  }
}

// Outputs
@description('Resource group name')
output resourceGroupName string = rg.name

@description('Bootstrap identity resource ID')
output bootstrapIdentityResourceId string = identity.outputs.identityResourceId

@description('Bootstrap identity client ID')
output bootstrapIdentityClientId string = identity.outputs.clientId

@description('Container group name')
output containerGroupName string = containerGroup.outputs.containerGroupName

@description('Log Analytics workspace ID')
output logAnalyticsWorkspaceId string = createLogAnalytics ? logAnalytics.outputs.workspaceId : ''

@description('Deployment summary')
output deploymentSummary object = {
  resourceGroup: rg.name
  identity: identity.outputs.identityName
  containerGroup: containerGroup.outputs.containerGroupName
  gitRepository: gitRepoUrl
  gitBranch: gitBranch
  reconcileIntervalSeconds: reconcileIntervalSeconds
  dryRunEnabled: dryRun
}
