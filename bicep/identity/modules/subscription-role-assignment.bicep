// ============================================================================
// Subscription-scoped Role Assignment Module
// ============================================================================
// Helper module for assigning roles at subscription scope from management group
// ============================================================================

targetScope = 'subscription'

@description('Required. The principal ID to assign the role to.')
param principalId string

@description('Required. The role definition ID to assign.')
param roleDefinitionId string

@description('Optional. The type of principal.')
@allowed([
  'Device'
  'ForeignGroup'
  'Group'
  'ServicePrincipal'
  'User'
])
param principalType string = 'ServicePrincipal'

@description('Optional. Description of the role assignment.')
param description string = ''

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, principalId, roleDefinitionId)
  properties: {
    principalId: principalId
    roleDefinitionId: roleDefinitionId
    principalType: principalType
    description: description
  }
}

@description('The resource ID of the role assignment.')
output resourceId string = roleAssignment.id
