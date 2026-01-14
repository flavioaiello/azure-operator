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

// RBAC: Least-privilege roles for bootstrap operator
// SECURITY: Grant only the permissions needed for bootstrap:
// 1. User Access Administrator: Create RBAC assignments for downstream operators
// 2. Managed Identity Contributor: Create UAMIs for each operator
// These roles are scoped to subscription level (not root MG) for reduced blast radius.
// For org-wide Landing Zones, create separate role assignments at each target MG.

// User Access Administrator - for creating role assignments
resource userAccessAdminRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, bootstrapIdentityName, 'UserAccessAdministrator')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' // User Access Administrator
    )
    principalId: identity.outputs.principalId
    principalType: 'ServicePrincipal'
    description: 'Bootstrap operator - User Access Administrator for assigning RBAC to downstream operators'
    // SECURITY: Condition limits to creating assignments for specific roles only
    condition: '''
      (
        !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
      )
      OR
      (
        @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {
          4d97b98b-1d4f-4787-a291-c67834d212e7,
          92aaf0da-9dab-42b6-94a3-d43ce8d16293,
          749f88d5-cbae-40b8-bcfc-e573ddc772fa,
          fb1c8493-542b-48eb-b624-b4c8fea62acd,
          5d58bcaf-24a5-4b20-bdb6-eed9f69fbe4c,
          b12aa53e-6015-4669-85d0-8515ebb3ae7f,
          00482a5a-887f-4fb3-b363-3b7fe8e74483,
          f353d9bd-d4a6-484e-a77a-8050b599b867
        }
      )
    '''
    conditionVersion: '2.0'
  }
}

// Managed Identity Contributor - for creating UAMIs
resource managedIdentityContributorRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, bootstrapIdentityName, 'ManagedIdentityContributor')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'e40ec5ca-96e0-45a2-b4ff-59039f2c2b59' // Managed Identity Contributor
    )
    principalId: identity.outputs.principalId
    principalType: 'ServicePrincipal'
    description: 'Bootstrap operator - Managed Identity Contributor for creating downstream operator UAMIs'
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
    userAccessAdminRoleAssignment // Wait for RBAC to propagate
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
