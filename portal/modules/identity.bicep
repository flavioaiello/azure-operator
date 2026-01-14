// ============================================================================
// Azure Landing Zones Operator - Bootstrap Identity Module
// ============================================================================
// Creates the User-Assigned Managed Identity for the bootstrap operator
// and assigns Owner role at the specified scope.
// ============================================================================

targetScope = 'resourceGroup'

// Parameters
@description('Name of the bootstrap identity')
@minLength(3)
@maxLength(128)
param identityName string = 'uami-azure-operator-bootstrap'

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('Tags to apply to the identity')
param tags object = {}

// Resources
resource bootstrapIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
  tags: union(tags, {
    purpose: 'azure-operator-bootstrap'
    managedBy: 'azure-operator'
  })
}

// Outputs
@description('Resource ID of the created identity')
output identityResourceId string = bootstrapIdentity.id

@description('Principal ID for RBAC assignments')
output principalId string = bootstrapIdentity.properties.principalId

@description('Client ID for Azure SDK authentication')
output clientId string = bootstrapIdentity.properties.clientId

@description('Identity name')
output identityName string = bootstrapIdentity.name
