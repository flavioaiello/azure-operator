// ============================================================================
// Connectivity Operator - Bicep Entry Point
// ============================================================================
// This module deploys connectivity resources for Azure Landing Zones:
// - Hub Virtual Networks
// - Azure Firewall
// - VPN/ExpressRoute Gateways
// - Azure Bastion
// - DDoS Protection
// - Private DNS Zones
//
// Leverages AVM pattern modules from bicep-registry-modules
// ============================================================================

targetScope = 'subscription'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The location for all resources.')
param location string

@description('Required. The name of the resource group for connectivity resources.')
param resourceGroupName string

@description('Optional. Enable/Disable usage telemetry for module.')
param enableTelemetry bool = true

@description('Optional. Tags to apply to all resources.')
param tags object = {}

@description('Required. Hub virtual network configuration.')
param hubVirtualNetworks object

@description('Optional. Azure Firewall configuration. Leave empty to skip.')
param azureFirewall object = {}

@description('Optional. VPN Gateway configuration. Leave empty to skip.')
param vpnGateway object = {}

@description('Optional. ExpressRoute Gateway configuration. Leave empty to skip.')
param expressRouteGateway object = {}

@description('Optional. Azure Bastion configuration. Leave empty to skip.')
param bastion object = {}

@description('Optional. DDoS Protection Plan configuration. Leave empty to skip.')
param ddosProtectionPlan object = {}

@description('Optional. Private DNS Zones to create.')
param privateDnsZones array = []

@description('Optional. Log Analytics Workspace resource ID for diagnostics.')
param logAnalyticsWorkspaceId string = ''

// ============================================================================
// Resources
// ============================================================================

// Resource Group for Connectivity resources
resource connectivityRg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

// DDoS Protection Plan (optional - created first as VNets may reference it)
module ddos 'br/public:avm/res/network/ddos-protection-plan:0.4.0' = if (!empty(ddosProtectionPlan)) {
  name: 'deploy-ddos-${uniqueString(deployment().name, location)}'
  scope: connectivityRg
  params: {
    name: ddosProtectionPlan.?name ?? 'ddos-${location}'
    location: location
    enableTelemetry: enableTelemetry
    tags: tags
  }
}

// Hub Networking using AVM pattern module
module hubNetworking 'br/public:avm/ptn/network/hub-networking:0.5.0' = {
  name: 'deploy-hub-${uniqueString(deployment().name, location)}'
  scope: connectivityRg
  params: {
    location: location
    enableTelemetry: enableTelemetry
    hubVirtualNetworks: hubVirtualNetworks
  }
}

// Azure Firewall (optional)
module firewall 'br/public:avm/res/network/azure-firewall:0.6.0' = if (!empty(azureFirewall)) {
  name: 'deploy-fw-${uniqueString(deployment().name, location)}'
  scope: connectivityRg
  params: {
    name: azureFirewall.?name ?? 'fw-hub-${location}'
    location: location
    virtualNetworkResourceId: hubNetworking.outputs.hubVirtualNetworkResourceIds[0]
    azureSkuTier: azureFirewall.?skuTier ?? 'Standard'
    firewallPolicyId: azureFirewall.?firewallPolicyId
    threatIntelMode: azureFirewall.?threatIntelMode ?? 'Alert'
    zones: azureFirewall.?zones ?? ['1', '2', '3']
    diagnosticSettings: !empty(logAnalyticsWorkspaceId) ? [
      {
        workspaceResourceId: logAnalyticsWorkspaceId
        logCategoriesAndGroups: [{ categoryGroup: 'allLogs' }]
        metricCategories: [{ category: 'AllMetrics' }]
      }
    ] : []
    enableTelemetry: enableTelemetry
    tags: tags
  }
}

// VPN Gateway (optional)
module vpnGw 'br/public:avm/res/network/virtual-network-gateway:0.5.0' = if (!empty(vpnGateway)) {
  name: 'deploy-vpngw-${uniqueString(deployment().name, location)}'
  scope: connectivityRg
  params: {
    name: vpnGateway.?name ?? 'vpngw-${location}'
    location: location
    gatewayType: 'Vpn'
    skuName: vpnGateway.?skuName ?? 'VpnGw2AZ'
    vNetResourceId: hubNetworking.outputs.hubVirtualNetworkResourceIds[0]
    activeActive: vpnGateway.?activeActive ?? true
    enableBgp: vpnGateway.?enableBgp ?? true
    vpnType: vpnGateway.?vpnType ?? 'RouteBased'
    vpnGatewayGeneration: vpnGateway.?generation ?? 'Generation2'
    enableTelemetry: enableTelemetry
    tags: tags
  }
}

// ExpressRoute Gateway (optional)
module erGw 'br/public:avm/res/network/virtual-network-gateway:0.5.0' = if (!empty(expressRouteGateway)) {
  name: 'deploy-ergw-${uniqueString(deployment().name, location)}'
  scope: connectivityRg
  params: {
    name: expressRouteGateway.?name ?? 'ergw-${location}'
    location: location
    gatewayType: 'ExpressRoute'
    skuName: expressRouteGateway.?skuName ?? 'ErGw2AZ'
    vNetResourceId: hubNetworking.outputs.hubVirtualNetworkResourceIds[0]
    enableTelemetry: enableTelemetry
    tags: tags
  }
}

// Azure Bastion (optional)
module bastionHost 'br/public:avm/res/network/bastion-host:0.6.0' = if (!empty(bastion)) {
  name: 'deploy-bastion-${uniqueString(deployment().name, location)}'
  scope: connectivityRg
  params: {
    name: bastion.?name ?? 'bas-${location}'
    location: location
    virtualNetworkResourceId: hubNetworking.outputs.hubVirtualNetworkResourceIds[0]
    skuName: bastion.?skuName ?? 'Standard'
    enableTelemetry: enableTelemetry
    tags: tags
  }
}

// Private DNS Zones
module privateDns 'br/public:avm/res/network/private-dns-zone:0.7.0' = [
  for (zone, index) in privateDnsZones: {
    name: 'deploy-pdns-${index}-${uniqueString(deployment().name, location)}'
    scope: connectivityRg
    params: {
      name: zone.name
      virtualNetworkLinks: [
        {
          virtualNetworkResourceId: hubNetworking.outputs.hubVirtualNetworkResourceIds[0]
          registrationEnabled: zone.?registrationEnabled ?? false
        }
      ]
      enableTelemetry: enableTelemetry
      tags: union(tags, zone.?tags ?? {})
    }
  }
]

// ============================================================================
// Outputs
// ============================================================================

@description('The resource ID of the connectivity resource group.')
output resourceGroupId string = connectivityRg.id

@description('The resource IDs of hub virtual networks.')
output hubVirtualNetworkIds array = hubNetworking.outputs.hubVirtualNetworkResourceIds

@description('The resource ID of Azure Firewall.')
output firewallId string = !empty(azureFirewall) ? firewall.outputs.resourceId : ''

@description('The private IP of Azure Firewall.')
output firewallPrivateIp string = !empty(azureFirewall) ? firewall.outputs.privateIp : ''

@description('The resource ID of VPN Gateway.')
output vpnGatewayId string = !empty(vpnGateway) ? vpnGw.outputs.resourceId : ''

@description('The resource ID of ExpressRoute Gateway.')
output expressRouteGatewayId string = !empty(expressRouteGateway) ? erGw.outputs.resourceId : ''

@description('The resource ID of Azure Bastion.')
output bastionId string = !empty(bastion) ? bastionHost.outputs.resourceId : ''

@description('The resource IDs of Private DNS Zones.')
output privateDnsZoneIds array = [for (zone, index) in privateDnsZones: privateDns[index].outputs.resourceId]
