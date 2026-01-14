// ============================================================================
// Azure Landing Zones Operator - Container Group Module
// ============================================================================
// Deploys Azure Container Instances with:
// - Operator container (reconciliation loop)
// - Git-sync sidecar (pulls specs from Git repository)
// ============================================================================

targetScope = 'resourceGroup'

// Parameters
@description('Name of the container group')
param containerGroupName string = 'azure-operator-bootstrap'

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('Operator container image')
param operatorImage string = 'ghcr.io/azure-operator/azure-operator:latest'

@description('Git-sync container image')
param gitSyncImage string = 'registry.k8s.io/git-sync/git-sync:v4.2.1'

@description('Resource ID of the User-Assigned Managed Identity')
param identityResourceId string

@description('Client ID of the User-Assigned Managed Identity')
param identityClientId string

@description('Azure subscription ID for operator')
param subscriptionId string = subscription().subscriptionId

@description('Operator domain (e.g., bootstrap, firewall, bastion)')
param operatorDomain string = 'bootstrap'

@description('Git repository URL')
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

@description('Enable dry-run mode')
param dryRun bool = false

@description('Log Analytics workspace ID for container logs')
param logAnalyticsWorkspaceId string = ''

@description('Log Analytics workspace key')
@secure()
param logAnalyticsWorkspaceKey string = ''

@description('Tags to apply to resources')
param tags object = {}

@description('CPU cores for operator container')
param operatorCpu string = '0.5'

@description('Memory in GB for operator container')
param operatorMemoryGb string = '1'

// Variables
var hasLogAnalytics = !empty(logAnalyticsWorkspaceId) && !empty(logAnalyticsWorkspaceKey)

// Resources
resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: containerGroupName
  location: location
  tags: union(tags, {
    operator: operatorDomain
    managedBy: 'azure-operator'
  })
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityResourceId}': {}
    }
  }
  properties: {
    osType: 'Linux'
    restartPolicy: 'Always'
    containers: [
      // Main operator container
      {
        name: 'operator'
        properties: {
          image: operatorImage
          resources: {
            requests: {
              cpu: json(operatorCpu)
              memoryInGB: json(operatorMemoryGb)
            }
            limits: {
              cpu: json(operatorCpu) * 2
              memoryInGB: json(operatorMemoryGb) * 2
            }
          }
          environmentVariables: [
            { name: 'DOMAIN', value: operatorDomain }
            { name: 'AZURE_SUBSCRIPTION_ID', value: subscriptionId }
            { name: 'AZURE_LOCATION', value: location }
            { name: 'AZURE_CLIENT_ID', value: identityClientId }
            { name: 'RECONCILE_INTERVAL', value: string(reconcileIntervalSeconds) }
            { name: 'DRY_RUN', value: dryRun ? 'true' : 'false' }
            { name: 'SPECS_DIR', value: '/specs/current/${gitSpecsPath}' }
            { name: 'TEMPLATES_DIR', value: '/templates' }
            { name: 'ENABLE_AUDIT_LOGGING', value: 'true' }
          ]
          volumeMounts: [
            { name: 'specs', mountPath: '/specs', readOnly: true }
            { name: 'templates', mountPath: '/templates', readOnly: true }
          ]
        }
      }
      // Git-sync sidecar
      {
        name: 'git-sync'
        properties: {
          image: gitSyncImage
          resources: {
            requests: {
              cpu: json('0.1')
              memoryInGB: json('0.25')
            }
            limits: {
              cpu: json('0.25')
              memoryInGB: json('0.5')
            }
          }
          environmentVariables: [
            { name: 'GITSYNC_REPO', value: gitRepoUrl }
            { name: 'GITSYNC_REF', value: gitBranch }
            { name: 'GITSYNC_ROOT', value: '/git' }
            { name: 'GITSYNC_LINK', value: 'current' }
            { name: 'GITSYNC_PERIOD', value: '${gitSyncIntervalSeconds}s' }
            { name: 'GITSYNC_ONE_TIME', value: 'false' }
            { name: 'GITSYNC_MAX_FAILURES', value: '5' }
          ]
          volumeMounts: [
            { name: 'specs', mountPath: '/git' }
          ]
        }
      }
    ]
    volumes: [
      { name: 'specs', emptyDir: {} }
      { name: 'templates', emptyDir: {} }
    ]
    diagnostics: hasLogAnalytics ? {
      logAnalytics: {
        workspaceId: logAnalyticsWorkspaceId
        workspaceKey: logAnalyticsWorkspaceKey
        logType: 'ContainerInsights'
      }
    } : null
  }
}

// Outputs
@description('Container group resource ID')
output containerGroupId string = containerGroup.id

@description('Container group name')
output containerGroupName string = containerGroup.name

@description('Container group FQDN (if applicable)')
output fqdn string = containerGroup.properties.?ipAddress.?fqdn ?? ''

@description('Container group provisioning state')
output provisioningState string = containerGroup.properties.provisioningState
