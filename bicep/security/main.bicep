// ============================================================================
// Security Operator - Bicep Entry Point
// ============================================================================
// This module deploys security resources for Azure Landing Zones:
// - Microsoft Defender for Cloud
// - Security Contacts
// - Key Vaults
// - Security Center Configuration
//
// Leverages AVM pattern modules from bicep-registry-modules
// ============================================================================

targetScope = 'subscription'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The location for all resources.')
param location string

@description('Required. The resource ID of the Log Analytics workspace for security data.')
param logAnalyticsWorkspaceId string

@description('Optional. Enable/Disable usage telemetry for module.')
param enableTelemetry bool = true

@description('Optional. Tags to apply to all resources.')
param tags object = {}

@description('Optional. Resource group name for security resources (Key Vaults, etc.).')
param resourceGroupName string = ''

@description('Required. Security contact email for Defender for Cloud alerts.')
param securityContactEmail string

@description('Optional. Security contact phone number.')
param securityContactPhone string = ''

@description('Optional. Defender for Cloud pricing configuration.')
param defenderPricing object = {
  virtualMachines: 'Standard'
  sqlServers: 'Standard'
  appServices: 'Standard'
  storageAccounts: 'Standard'
  sqlServerVirtualMachines: 'Standard'
  kubernetesService: 'Standard'
  containerRegistry: 'Standard'
  keyVaults: 'Standard'
  dns: 'Standard'
  arm: 'Standard'
  openSourceRelationalDatabases: 'Standard'
  containers: 'Standard'
  cosmosDb: 'Standard'
  cloudPosture: 'Standard'
}

@description('Optional. Key Vaults to create.')
param keyVaults array = []

@description('Optional. Enable auto-provisioning of security agents.')
param autoProvision bool = true

// ============================================================================
// Resources
// ============================================================================

// Resource Group for security resources (optional)
resource securityRg 'Microsoft.Resources/resourceGroups@2024-03-01' = if (!empty(resourceGroupName)) {
  name: resourceGroupName
  location: location
  tags: tags
}

// Defender for Cloud Configuration using AVM pattern module
module defenderForCloud 'br/public:avm/ptn/security/security-center:0.2.0' = {
  name: 'deploy-asc-${uniqueString(deployment().name, location)}'
  params: {
    workspaceResourceId: logAnalyticsWorkspaceId
    scope: subscription().id
    autoProvision: autoProvision ? 'On' : 'Off'
    
    // Pricing tiers
    virtualMachinesPricingTier: defenderPricing.?virtualMachines ?? 'Free'
    sqlServersPricingTier: defenderPricing.?sqlServers ?? 'Free'
    appServicesPricingTier: defenderPricing.?appServices ?? 'Free'
    storageAccountsPricingTier: defenderPricing.?storageAccounts ?? 'Free'
    sqlServerVirtualMachinesPricingTier: defenderPricing.?sqlServerVirtualMachines ?? 'Free'
    kubernetesServicePricingTier: defenderPricing.?kubernetesService ?? 'Free'
    containerRegistryPricingTier: defenderPricing.?containerRegistry ?? 'Free'
    keyVaultsPricingTier: defenderPricing.?keyVaults ?? 'Free'
  }
}

// Security Contact
resource securityContact 'Microsoft.Security/securityContacts@2023-12-01-preview' = {
  name: 'default'
  properties: {
    emails: securityContactEmail
    phone: !empty(securityContactPhone) ? securityContactPhone : null
    notificationsByRole: {
      state: 'On'
      roles: ['Owner', 'Contributor']
    }
    alertNotifications: {
      state: 'On'
      minimalSeverity: 'Medium'
    }
  }
}

// Key Vaults
module kvs 'br/public:avm/res/key-vault/vault:0.11.0' = [
  for (kv, index) in keyVaults: {
    name: 'deploy-kv-${index}-${uniqueString(deployment().name, location)}'
    scope: !empty(resourceGroupName) ? securityRg : resourceGroup(kv.resourceGroupName)
    params: {
      name: kv.name
      location: kv.?location ?? location
      
      // Security settings
      enableRbacAuthorization: kv.?enableRbacAuthorization ?? true
      enablePurgeProtection: kv.?enablePurgeProtection ?? true
      enableSoftDelete: kv.?enableSoftDelete ?? true
      softDeleteRetentionInDays: kv.?softDeleteRetentionInDays ?? 90
      
      // Network settings
      publicNetworkAccess: kv.?publicNetworkAccess ?? 'Disabled'
      networkAcls: kv.?networkAcls ?? {
        bypass: 'AzureServices'
        defaultAction: 'Deny'
      }
      
      // Diagnostics
      diagnosticSettings: [
        {
          workspaceResourceId: logAnalyticsWorkspaceId
          logCategoriesAndGroups: [{ categoryGroup: 'allLogs' }]
          metricCategories: [{ category: 'AllMetrics' }]
        }
      ]
      
      enableTelemetry: enableTelemetry
      tags: union(tags, kv.?tags ?? {})
    }
  }
]

// ============================================================================
// Outputs
// ============================================================================

@description('Defender for Cloud configuration applied.')
output defenderConfigured bool = true

@description('Security contact email configured.')
output securityContactEmail string = securityContactEmail

@description('The resource IDs of Key Vaults.')
output keyVaultIds array = [for (kv, index) in keyVaults: kvs[index].outputs.resourceId]

@description('The resource group ID for security resources.')
output resourceGroupId string = !empty(resourceGroupName) ? securityRg.id : ''
