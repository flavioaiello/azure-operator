// ============================================================================
// Policy Operator - Bicep Entry Point
// ============================================================================
// This module deploys policy resources for Azure Landing Zones:
// - Management Group Hierarchy
// - Policy Definitions (custom) - loaded from lib/policies/definitions.json
// - Policy Set Definitions (initiatives) - loaded from lib/policies/initiatives.json
// - Policy Assignments
// - Subscription Placement
//
// Policy definitions are synced from Azure/Enterprise-Scale repository.
// Run lib/policies/sync.sh to update the policy library.
// ============================================================================

targetScope = 'managementGroup'

// ============================================================================
// Parameters
// ============================================================================

@description('Required. The ID of the root management group.')
param rootManagementGroupId string

@description('Optional. Enable/Disable usage telemetry for module.')
param enableTelemetry bool = true

@description('Optional. The management group structure to create.')
param managementGroups array = []

@description('Optional. Deploy ALZ policy definitions from lib/policies/.')
param deployAlzPolicies bool = true

@description('Optional. Additional custom policy definitions (beyond ALZ library).')
param customPolicyDefinitions array = []

@description('Optional. Deploy ALZ policy initiatives from lib/policies/.')
param deployAlzInitiatives bool = true

@description('Optional. Additional custom policy set definitions (beyond ALZ library).')
param customPolicySetDefinitions array = []

@description('Optional. Policy assignments to create.')
param policyAssignments array = []

@description('Optional. Subscription placements into management groups.')
param subscriptionPlacements array = []

@description('Optional. Location for deployment metadata.')
param location string = 'westeurope'

// ============================================================================
// Load ALZ Policy Library
// ============================================================================

// Load all ALZ policy definitions from synced library
var alzPolicyDefinitions = deployAlzPolicies ? loadJsonContent('../../lib/policies/definitions.json') : []

// Load all ALZ policy initiatives from synced library
var alzPolicySetDefinitions = deployAlzInitiatives ? loadJsonContent('../../lib/policies/initiatives.json') : []

// Combine ALZ + custom definitions
var allPolicyDefinitions = concat(alzPolicyDefinitions, customPolicyDefinitions)
var allPolicySetDefinitions = concat(alzPolicySetDefinitions, customPolicySetDefinitions)

// ============================================================================
// Variables
// ============================================================================

// Default ALZ management group structure
var defaultAlzStructure = [
  {
    name: '${rootManagementGroupId}-platform'
    displayName: 'Platform'
    parentId: rootManagementGroupId
    children: [
      { name: '${rootManagementGroupId}-identity', displayName: 'Identity' }
      { name: '${rootManagementGroupId}-management', displayName: 'Management' }
      { name: '${rootManagementGroupId}-connectivity', displayName: 'Connectivity' }
    ]
  }
  {
    name: '${rootManagementGroupId}-landingzones'
    displayName: 'Landing Zones'
    parentId: rootManagementGroupId
    children: [
      { name: '${rootManagementGroupId}-corp', displayName: 'Corp' }
      { name: '${rootManagementGroupId}-online', displayName: 'Online' }
    ]
  }
  {
    name: '${rootManagementGroupId}-sandbox'
    displayName: 'Sandbox'
    parentId: rootManagementGroupId
  }
  {
    name: '${rootManagementGroupId}-decommissioned'
    displayName: 'Decommissioned'
    parentId: rootManagementGroupId
  }
]

var mgStructure = !empty(managementGroups) ? managementGroups : defaultAlzStructure

// ============================================================================
// Resources
// ============================================================================

// Management Groups - Level 1 (directly under root)
resource mgLevel1 'Microsoft.Management/managementGroups@2023-04-01' = [
  for mg in mgStructure: {
    name: mg.name
    properties: {
      displayName: mg.displayName
      details: {
        parent: {
          id: '/providers/Microsoft.Management/managementGroups/${mg.?parentId ?? rootManagementGroupId}'
        }
      }
    }
  }
]

// Management Groups - Level 2 (children)
resource mgLevel2 'Microsoft.Management/managementGroups@2023-04-01' = [
  for (child, index) in flatten([for mg in mgStructure: mg.?children ?? []]): {
    name: child.name
    properties: {
      displayName: child.displayName
      details: {
        parent: {
          id: mgLevel1[index % length(mgStructure)].id
        }
      }
    }
  }
]

// Custom Policy Definitions (ALZ + custom)
resource policyDefinitionsResource 'Microsoft.Authorization/policyDefinitions@2023-04-01' = [
  for policy in allPolicyDefinitions: {
    name: policy.name
    properties: {
      displayName: policy.properties.displayName
      description: policy.properties.?description ?? ''
      policyType: 'Custom'
      mode: policy.properties.?mode ?? 'All'
      metadata: policy.properties.?metadata ?? {}
      parameters: policy.properties.?parameters ?? {}
      policyRule: policy.properties.policyRule
    }
  }
]

// Policy Set Definitions / Initiatives (ALZ + custom)
resource policySetDefinitionsResource 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = [
  for policySet in allPolicySetDefinitions: {
    name: policySet.name
    properties: {
      displayName: policySet.properties.displayName
      description: policySet.properties.?description ?? ''
      policyType: 'Custom'
      metadata: policySet.properties.?metadata ?? {}
      parameters: policySet.properties.?parameters ?? {}
      policyDefinitions: policySet.properties.policyDefinitions
      policyDefinitionGroups: policySet.properties.?policyDefinitionGroups ?? []
    }
  }
  dependsOn: [
    policyDefinitionsResource // Initiatives reference definitions
  ]
]

// Policy Assignments using AVM module
module assignments 'br/public:avm/ptn/authorization/policy-assignment:0.2.0' = [
  for (assignment, index) in policyAssignments: {
    name: 'deploy-pa-${index}-${uniqueString(deployment().name, location)}'
    scope: managementGroup(assignment.?managementGroupId ?? rootManagementGroupId)
    params: {
      name: assignment.name
      displayName: assignment.?displayName ?? assignment.name
      description: assignment.?description ?? ''
      policyDefinitionId: assignment.policyDefinitionId
      parameters: assignment.?parameters ?? {}
      identity: assignment.?identity ?? 'SystemAssigned'
      location: location
      enforcementMode: assignment.?enforcementMode ?? 'Default'
      nonComplianceMessages: assignment.?nonComplianceMessages ?? []
      notScopes: assignment.?notScopes ?? []
      enableTelemetry: enableTelemetry
    }
  }
  dependsOn: [
    policyDefinitionsResource
    policySetDefinitionsResource // Assignments may reference custom definitions
  ]
]

// Subscription Placement using AVM module
module subPlacements 'br/public:avm/ptn/mgmt-groups/subscription-placement:0.1.0' = [
  for (placement, index) in subscriptionPlacements: {
    name: 'deploy-sp-${index}-${uniqueString(deployment().name, location)}'
    params: {
      subscriptionId: placement.subscriptionId
      targetManagementGroupId: placement.managementGroupId
    }
  }
]

// ============================================================================
// Outputs
// ============================================================================

@description('The IDs of created management groups.')
output managementGroupIds array = [for (mg, index) in mgStructure: mgLevel1[index].id]

@description('The number of ALZ policy definitions deployed.')
output alzPolicyDefinitionCount int = length(alzPolicyDefinitions)

@description('The number of ALZ policy initiatives deployed.')
output alzPolicyInitiativeCount int = length(alzPolicySetDefinitions)

@description('The IDs of policy definitions.')
output policyDefinitionIds array = [for (policy, index) in allPolicyDefinitions: policyDefinitionsResource[index].id]

@description('The IDs of policy set definitions.')
output policySetDefinitionIds array = [for (policySet, index) in allPolicySetDefinitions: policySetDefinitionsResource[index].id]

@description('The IDs of policy assignments.')
output policyAssignmentIds array = [for (assignment, index) in policyAssignments: assignments[index].outputs.resourceId]
