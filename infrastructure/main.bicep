// ============================================================================
// Azure Operator Infrastructure - Secure Deployment
// ============================================================================
// Deploys Azure Container Instances in isolated VNet to run ALZ operators
// Each operator runs in its own ACI with Managed Identity authentication
// 
// SECURITY ARCHITECTURE:
// - Dedicated management subscription (isolation from managed resources)
// - Private VNet with no public IPs
// - NSG: Deny all inbound, restrict outbound to Azure services only
// - Separate managed identity per operator (least privilege)
// - Cross-subscription RBAC for resource management
// ============================================================================

targetScope = 'subscription'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The location for all resources.')
param location string

@description('Required. The name prefix for all resources.')
param namePrefix string = 'alz-operator'

@description('Optional. Tags to apply to all resources.')
param tags object = {}

@description('Required. Container Registry name where operator images are stored.')
param containerRegistryName string

@description('Required. Container Registry resource group.')
param containerRegistryResourceGroup string

@description('Optional. Image tag for operator containers.')
param imageTag string = 'latest'

@description('Required. Subscription IDs for each operator scope.')
param subscriptionIds object = {
  management: ''
  connectivity: ''
  security: ''
}

@description('Required. Root management group ID.')
param rootManagementGroupId string

@description('Required. Git repository URL for specs.')
param gitRepoUrl string

@description('Optional. Git branch to sync.')
param gitBranch string = 'main'

@description('Optional. Reconciliation interval in seconds.')
param reconcileIntervalSeconds int = 300

@description('Optional. Enable dry-run mode (no changes applied).')
param dryRun bool = false

// ============================================================================
// Security Parameters
// ============================================================================

@description('Optional. VNet address space for operator network.')
param vnetAddressSpace string = '10.250.0.0/24'

@description('Optional. Subnet prefix for operator containers.')
param operatorSubnetPrefix string = '10.250.0.0/26'

@description('Optional. Subnet prefix for private endpoints.')
param privateEndpointSubnetPrefix string = '10.250.0.64/26'

@description('Optional. Enable private endpoints for Azure services.')
param enablePrivateEndpoints bool = true

// ============================================================================
// Variables
// ============================================================================

var resourceGroupName = 'rg-${namePrefix}-${location}'

// Granular operators - one per concern for minimal blast radius
// Each operator manages a single resource type with least-privilege RBAC
var operators = [
  // ==================== Connectivity Operators ====================
  {
    name: 'firewall'
    description: 'Azure Firewall and policies'
    scope: 'sub'
    subscriptionId: subscriptionIds.connectivity
    managementGroupId: ''
    cpu: '0.5'
    memoryInGb: '1'
  }
  {
    name: 'vpn-gateway'
    description: 'VPN Gateway and connections'
    scope: 'sub'
    subscriptionId: subscriptionIds.connectivity
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'expressroute'
    description: 'ExpressRoute Gateway and circuits'
    scope: 'sub'
    subscriptionId: subscriptionIds.connectivity
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'bastion'
    description: 'Azure Bastion hosts'
    scope: 'sub'
    subscriptionId: subscriptionIds.connectivity
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'dns'
    description: 'Private DNS zones and resolver'
    scope: 'sub'
    subscriptionId: subscriptionIds.connectivity
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'hub-network'
    description: 'Hub VNet and peerings'
    scope: 'sub'
    subscriptionId: subscriptionIds.connectivity
    managementGroupId: ''
    cpu: '0.5'
    memoryInGb: '1'
  }
  // ==================== Management Operators ====================
  {
    name: 'log-analytics'
    description: 'Log Analytics workspaces and solutions'
    scope: 'sub'
    subscriptionId: subscriptionIds.management
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'automation'
    description: 'Automation accounts and runbooks'
    scope: 'sub'
    subscriptionId: subscriptionIds.management
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'monitor'
    description: 'Data collection rules and alerts'
    scope: 'sub'
    subscriptionId: subscriptionIds.management
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  // ==================== Security Operators ====================
  {
    name: 'defender'
    description: 'Defender for Cloud plans and settings'
    scope: 'sub'
    subscriptionId: subscriptionIds.security
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'keyvault'
    description: 'Key Vaults for platform secrets'
    scope: 'sub'
    subscriptionId: subscriptionIds.security
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'sentinel'
    description: 'Microsoft Sentinel workspace and rules'
    scope: 'sub'
    subscriptionId: subscriptionIds.security
    managementGroupId: ''
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  // ==================== Governance Operators ====================
  {
    name: 'management-group'
    description: 'Management group hierarchy'
    scope: 'mg'
    subscriptionId: ''
    managementGroupId: rootManagementGroupId
    cpu: '0.25'
    memoryInGb: '0.5'
  }
  {
    name: 'policy'
    description: 'Policy definitions and assignments'
    scope: 'mg'
    subscriptionId: ''
    managementGroupId: rootManagementGroupId
    cpu: '0.5'
    memoryInGb: '1'
  }
  {
    name: 'role'
    description: 'Custom roles and role assignments'
    scope: 'mg'
    subscriptionId: ''
    managementGroupId: rootManagementGroupId
    cpu: '0.25'
    memoryInGb: '0.5'
  }
]

// ============================================================================
// Resources
// ============================================================================

// Resource Group for operators (dedicated management subscription)
resource operatorRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: union(tags, {
    Purpose: 'ALZ Operator Control Plane'
    SecurityZone: 'Management'
  })
}

// Reference to existing Container Registry
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: containerRegistryName
  scope: resourceGroup(containerRegistryResourceGroup)
}

// ============================================================================
// Network Isolation
// ============================================================================

module network 'modules/network.bicep' = {
  name: 'deploy-network'
  scope: operatorRg
  params: {
    location: location
    namePrefix: namePrefix
    tags: tags
    vnetAddressSpace: vnetAddressSpace
    operatorSubnetPrefix: operatorSubnetPrefix
    privateEndpointSubnetPrefix: privateEndpointSubnetPrefix
  }
}

// ============================================================================
// Monitoring
// ============================================================================

// Log Analytics Workspace for operator logs
module logAnalytics 'br/public:avm/res/operational-insights/workspace:0.9.1' = {
  name: 'deploy-law-operators'
  scope: operatorRg
  params: {
    name: 'law-${namePrefix}'
    location: location
    dataRetention: 30
    tags: tags
  }
}

// ============================================================================
// Container Registry Private Endpoint (if enabled)
// ============================================================================

module acrPrivateEndpoint 'br/public:avm/res/network/private-endpoint:0.9.0' = if (enablePrivateEndpoints) {
  name: 'deploy-pe-acr'
  scope: operatorRg
  params: {
    name: 'pe-${namePrefix}-acr'
    location: location
    tags: tags
    subnetResourceId: network.outputs.privateEndpointSubnetId
    privateLinkServiceConnections: [
      {
        name: 'acr-connection'
        properties: {
          privateLinkServiceId: acr.id
          groupIds: ['registry']
        }
      }
    ]
    privateDnsZoneGroup: {
      privateDnsZoneGroupConfigs: [
        {
          privateDnsZoneResourceId: acrPrivateDnsZone.id
        }
      ]
    }
  }
}

// Private DNS Zone for ACR
resource acrPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = if (enablePrivateEndpoints) {
  name: 'privatelink.azurecr.io'
  location: 'global'
  tags: tags
}

resource acrPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = if (enablePrivateEndpoints) {
  parent: acrPrivateDnsZone
  name: 'link-${namePrefix}-acr'
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: network.outputs.vnetId
    }
  }
}

// ============================================================================
// Managed Identities
// ============================================================================

// User-Assigned Managed Identities for each operator
module operatorIdentities 'br/public:avm/res/managed-identity/user-assigned-identity:0.4.1' = [
  for operator in operators: {
    name: 'deploy-uami-${operator.name}'
    scope: operatorRg
    params: {
      name: 'uami-${namePrefix}-${operator.name}'
      location: location
      tags: union(tags, { 
        Operator: operator.name
        Scope: operator.scope
      })
    }
  }
]

// ============================================================================
// ACR Pull Role for Managed Identities
// ============================================================================

// Grant AcrPull role to each operator identity
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

module acrPullRoleAssignments 'modules/subscription-rbac.bicep' = [
  for (operator, index) in operators: {
    name: 'deploy-acr-pull-${operator.name}'
    scope: resourceGroup(containerRegistryResourceGroup)
    params: {
      principalId: operatorIdentities[index].outputs.principalId
      roleDefinitionId: acrPullRoleId
      description: '${operator.name} operator - ACR Pull access'
    }
  }
]

// Container Instances for each operator (VNet integrated - no public IP)
resource operatorContainers 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = [
  for (operator, index) in operators: {
    name: 'aci-${namePrefix}-${operator.name}'
    location: location
    tags: union(tags, { Operator: operator.name })
    identity: {
      type: 'UserAssigned'
      userAssignedIdentities: {
        '${operatorIdentities[index].outputs.resourceId}': {}
      }
    }
    properties: {
      osType: 'Linux'
      restartPolicy: 'Always'
      // VNet integration - operators run in private subnet with no public IP
      subnetIds: [
        {
          id: network.outputs.operatorSubnetId
        }
      ]
      imageRegistryCredentials: [
        {
          server: '${containerRegistryName}.azurecr.io'
          identity: operatorIdentities[index].outputs.resourceId
        }
      ]
      containers: [
        {
          name: operator.name
          properties: {
            image: '${containerRegistryName}.azurecr.io/${namePrefix}-controller:${imageTag}'
            resources: {
              requests: {
                cpu: json(operator.cpu)
                memoryInGB: json(operator.memoryInGb)
              }
            }
            environmentVariables: [
              // Domain maps to the operator name for config loading
              { name: 'DOMAIN', value: operator.name }
              { name: 'DEPLOYMENT_SCOPE', value: operator.scope }
              { name: 'AZURE_LOCATION', value: location }
              { name: 'AZURE_SUBSCRIPTION_ID', value: operator.subscriptionId }
              { name: 'AZURE_MANAGEMENT_GROUP', value: operator.managementGroupId }
              // Git-sync creates: /data/repo -> cloned content
              // Specs and templates are in /data/repo/specs and /data/repo/templates
              { name: 'SPECS_DIR', value: '/data/repo/specs' }
              { name: 'TEMPLATES_DIR', value: '/data/repo/templates' }
              { name: 'RECONCILE_INTERVAL', value: string(reconcileIntervalSeconds) }
              { name: 'DRY_RUN', value: string(dryRun) }
              { name: 'LOG_LEVEL', value: 'INFO' }
              // Use managed identity for Azure authentication
              { name: 'AZURE_CLIENT_ID', value: operatorIdentities[index].outputs.clientId }
            ]
            volumeMounts: [
              {
                name: 'git-data'
                mountPath: '/data'
                readOnly: true
              }
            ]
          }
        }
        // Git sync sidecar - syncs entire repo to /data
        // Provides both /data/specs (operator YAML) and /data/templates (compiled ARM JSON)
        {
          name: 'git-sync'
          properties: {
            image: 'registry.k8s.io/git-sync/git-sync:v4.2.1'
            resources: {
              requests: {
                cpu: json('0.1')
                memoryInGB: json('0.25')
              }
            }
            environmentVariables: [
              { name: 'GITSYNC_REPO', value: gitRepoUrl }
              { name: 'GITSYNC_BRANCH', value: gitBranch }
              { name: 'GITSYNC_ROOT', value: '/data' }
              // Link name creates /data/repo -> actual clone
              { name: 'GITSYNC_LINK', value: 'repo' }
              { name: 'GITSYNC_PERIOD', value: '60s' }
              { name: 'GITSYNC_ONE_TIME', value: 'false' }
              // Sync only what we need (specs + templates folders)
              { name: 'GITSYNC_SPARSE_CHECKOUT_FILE', value: '/sparse-checkout' }
            ]
            volumeMounts: [
              {
                name: 'git-data'
                mountPath: '/data'
                readOnly: false
              }
              {
                name: 'sparse-checkout-config'
                mountPath: '/sparse-checkout'
                readOnly: true
              }
            ]
          }
        }
      ]
      volumes: [
        {
          name: 'git-data'
          emptyDir: {}
        }
        {
          // Sparse checkout config to sync only specs and templates
          name: 'sparse-checkout-config'
          secret: {
            // Content: specs/\ntemplates/\n
            'sparse-checkout': base64('specs/\ntemplates/\n')
          }
        }
      ]
      diagnostics: {
        logAnalytics: {
          workspaceId: logAnalytics.outputs.logAnalyticsWorkspaceId
          workspaceKey: listKeys(logAnalytics.outputs.resourceId, '2023-09-01').primarySharedKey
        }
      }
    }
    dependsOn: [
      operatorIdentities
    ]
  }
]

// ============================================================================
// Outputs
// ============================================================================

@description('The resource group ID.')
output resourceGroupId string = operatorRg.id

@description('The VNet resource ID.')
output vnetId string = network.outputs.vnetId

@description('The operator subnet ID (VNet integrated ACI).')
output operatorSubnetId string = network.outputs.operatorSubnetId

@description('The private endpoint subnet ID.')
output privateEndpointSubnetId string = network.outputs.privateEndpointSubnetId

@description('The Log Analytics workspace ID.')
output logAnalyticsWorkspaceId string = logAnalytics.outputs.resourceId

@description('The managed identity resource IDs.')
output managedIdentityIds array = [for (operator, index) in operators: operatorIdentities[index].outputs.resourceId]

@description('The managed identity principal IDs for RBAC assignment.')
output managedIdentityPrincipalIds array = [for (operator, index) in operators: operatorIdentities[index].outputs.principalId]

@description('The container group resource IDs.')
output containerGroupIds array = [for (operator, index) in operators: operatorContainers[index].id]
