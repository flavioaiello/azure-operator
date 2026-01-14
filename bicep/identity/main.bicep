// ============================================================================
// Identity Operator - Bicep Entry Point
// ============================================================================
// This module deploys identity resources for Azure Landing Zones:
// - Custom Role Definitions
// - Role Assignments
// - User-Assigned Managed Identities
// - Federated Identity Credentials (for workload identity)
//
// Leverages AVM pattern modules from bicep-registry-modules
// ============================================================================

targetScope = 'managementGroup'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The ID of the management group for role definitions.')
param managementGroupId string

@description('Optional. Location for deployment metadata.')
param location string = 'westeurope'

@description('Optional. Enable/Disable usage telemetry for module.')
param enableTelemetry bool = true

@description('Optional. Custom role definitions to create.')
param roleDefinitions array = []

@description('Optional. Role assignments to create at management group scope.')
param managementGroupRoleAssignments array = []

@description('Optional. Role assignments to create at subscription scope.')
param subscriptionRoleAssignments array = []

// ============================================================================
// Resources
// ============================================================================

// Custom Role Definitions using AVM module
module customRoles 'br/public:avm/ptn/authorization/role-definition:0.1.1' = [
  for (role, index) in roleDefinitions: {
    name: 'deploy-role-${index}-${uniqueString(deployment().name, location)}'
    params: {
      name: role.name
      roleName: role.?roleName ?? role.name
      description: role.?description ?? ''
      actions: role.?actions ?? []
      notActions: role.?notActions ?? []
      dataActions: role.?dataActions ?? []
      notDataActions: role.?notDataActions ?? []
      assignableScopes: role.?assignableScopes ?? [
        '/providers/Microsoft.Management/managementGroups/${managementGroupId}'
      ]
      enableTelemetry: enableTelemetry
    }
  }
]

// Management Group Role Assignments using AVM module
module mgRoleAssignments 'br/public:avm/ptn/authorization/role-assignment:0.2.4' = [
  for (assignment, index) in managementGroupRoleAssignments: {
    name: 'deploy-mgra-${index}-${uniqueString(deployment().name, location)}'
    scope: managementGroup(assignment.?managementGroupId ?? managementGroupId)
    params: {
      principalId: assignment.principalId
      roleDefinitionIdOrName: assignment.roleDefinitionId
      principalType: assignment.?principalType ?? 'ServicePrincipal'
      description: assignment.?description ?? ''
      condition: assignment.?condition
      conditionVersion: assignment.?conditionVersion
      enableTelemetry: enableTelemetry
    }
  }
]

// Subscription-scoped role assignments using AVM module
module subRoleAssignments 'br/public:avm/ptn/authorization/role-assignment:0.2.4' = [
  for (assignment, index) in subscriptionRoleAssignments: {
    name: 'deploy-subra-${index}-${uniqueString(deployment().name, location)}'
    params: {
      principalId: assignment.principalId
      roleDefinitionIdOrName: assignment.roleDefinitionId
      subscriptionId: assignment.subscriptionId
      principalType: assignment.?principalType ?? 'ServicePrincipal'
      description: assignment.?description ?? ''
      enableTelemetry: enableTelemetry
    }
  }
]

// ============================================================================
// Outputs
// ============================================================================

@description('The custom role definitions (object with resourceId, roleDefinitionId, displayName).')
output roleDefinitions array = [for (role, index) in roleDefinitions: customRoles[index].outputs.managementGroupCustomRoleDefinitionIds]

@description('The IDs of management group role assignments.')
output managementGroupRoleAssignmentIds array = [for (assignment, index) in managementGroupRoleAssignments: mgRoleAssignments[index].outputs.resourceId]

@description('The IDs of subscription role assignments.')
output subscriptionRoleAssignmentIds array = [for (assignment, index) in subscriptionRoleAssignments: subRoleAssignments[index].outputs.resourceId]
