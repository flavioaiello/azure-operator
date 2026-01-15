// ============================================================================
// Network Security Module for Operator Infrastructure
// ============================================================================
// Creates an isolated VNet with NSG hardening for operator containers
// Implements zero-trust network architecture:
// - No public IPs on operators
// - Deny all inbound traffic
// - Outbound restricted to Azure management endpoints only
// ============================================================================

targetScope = 'resourceGroup'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The location for network resources.')
param location string

@description('Required. The name prefix for resources.')
param namePrefix string

@description('Optional. Tags to apply to all resources.')
param tags object = {}

@description('Optional. VNet address space.')
param vnetAddressSpace string = '10.250.0.0/24'

@description('Optional. Subnet address prefix for operators.')
param operatorSubnetPrefix string = '10.250.0.0/26'

@description('Optional. Subnet address prefix for private endpoints.')
param privateEndpointSubnetPrefix string = '10.250.0.64/26'

// ============================================================================
// Variables
// ============================================================================

// Azure service tags for outbound access
// https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview
var azureManagementServiceTag = 'AzureResourceManager'
var azureActiveDirectoryServiceTag = 'AzureActiveDirectory'
var azureContainerRegistryServiceTag = 'AzureContainerRegistry.${location}'
var azureMonitorServiceTag = 'AzureMonitor'

// ============================================================================
// Network Security Group - Operator Subnet
// ============================================================================

resource operatorNsg 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: 'nsg-${namePrefix}-operators'
  location: location
  tags: tags
  properties: {
    securityRules: [
      // ========================================
      // INBOUND RULES - Deny All
      // ========================================
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          description: 'SECURITY: Deny all inbound traffic - operators do not accept connections'
        }
      }
      // ========================================
      // OUTBOUND RULES - Allow Only Required
      // ========================================
      {
        name: 'AllowAzureResourceManager'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: azureManagementServiceTag
          description: 'Allow Azure Resource Manager API for deployments'
        }
      }
      {
        name: 'AllowAzureActiveDirectory'
        properties: {
          priority: 110
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: azureActiveDirectoryServiceTag
          description: 'Allow Entra ID for managed identity authentication'
        }
      }
      {
        name: 'AllowAzureContainerRegistry'
        properties: {
          priority: 120
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: azureContainerRegistryServiceTag
          description: 'Allow Azure Container Registry for image pulls'
        }
      }
      {
        name: 'AllowAzureMonitor'
        properties: {
          priority: 130
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'VirtualNetwork'
          destinationAddressPrefix: azureMonitorServiceTag
          description: 'Allow Azure Monitor for logging'
        }
      }
      {
        name: 'AllowPrivateEndpoints'
        properties: {
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: operatorSubnetPrefix
          destinationAddressPrefix: privateEndpointSubnetPrefix
          description: 'Allow traffic to private endpoints subnet'
        }
      }
      {
        name: 'DenyAllOutbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          description: 'SECURITY: Deny all other outbound traffic'
        }
      }
    ]
  }
}

// ============================================================================
// Network Security Group - Private Endpoint Subnet
// ============================================================================

resource privateEndpointNsg 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: 'nsg-${namePrefix}-privateendpoints'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowOperatorSubnet'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: operatorSubnetPrefix
          destinationAddressPrefix: privateEndpointSubnetPrefix
          description: 'Allow traffic from operator subnet'
        }
      }
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          description: 'Deny all other inbound traffic'
        }
      }
      {
        name: 'DenyAllOutbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          description: 'Private endpoints do not initiate connections'
        }
      }
    ]
  }
}

// ============================================================================
// Virtual Network
// ============================================================================

resource vnet 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: 'vnet-${namePrefix}'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressSpace]
    }
    subnets: [
      {
        name: 'snet-operators'
        properties: {
          addressPrefix: operatorSubnetPrefix
          networkSecurityGroup: {
            id: operatorNsg.id
          }
          // Required for ACI VNet integration
          delegations: [
            {
              name: 'Microsoft.ContainerInstance.containerGroups'
              properties: {
                serviceName: 'Microsoft.ContainerInstance/containerGroups'
              }
            }
          ]
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'snet-privateendpoints'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
          networkSecurityGroup: {
            id: privateEndpointNsg.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// ============================================================================
// Private DNS Zone for ARM API
// ============================================================================

resource armPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.azure.com'
  location: 'global'
  tags: tags
}

resource armPrivateDnsZoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: armPrivateDnsZone
  name: 'link-${namePrefix}'
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// ============================================================================
// Outputs
// ============================================================================

@description('The VNet resource ID.')
output vnetId string = vnet.id

@description('The VNet name.')
output vnetName string = vnet.name

@description('The operator subnet resource ID.')
output operatorSubnetId string = vnet.properties.subnets[0].id

@description('The private endpoint subnet resource ID.')
output privateEndpointSubnetId string = vnet.properties.subnets[1].id

@description('The operator NSG resource ID.')
output operatorNsgId string = operatorNsg.id

@description('The ARM private DNS zone resource ID.')
output armPrivateDnsZoneId string = armPrivateDnsZone.id
