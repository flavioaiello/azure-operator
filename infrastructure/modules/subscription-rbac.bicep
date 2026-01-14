// ============================================================================
// Subscription-scoped RBAC Assignment Module
// ============================================================================

targetScope = 'subscription'

@description('Required. The principal ID to assign the role to.')
param principalId string

@description('Required. The role definition ID (GUID only, not full resource ID).')
param roleDefinitionId string

@description('Optional. Description of the role assignment.')
param description string = ''

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, principalId, roleDefinitionId)
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)
    principalType: 'ServicePrincipal'
    description: description
  }
}

@description('The resource ID of the role assignment.')
output resourceId string = roleAssignment.id
