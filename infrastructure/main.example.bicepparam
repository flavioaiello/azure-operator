// ============================================================================
// Azure Operator Infrastructure - Example Parameters
// ============================================================================
// Copy this file to main.bicepparam and fill in your values
// ============================================================================

using './main.bicep'

// Location for operator infrastructure
param location = 'westeurope'

// Name prefix for all resources
param namePrefix = 'alz-operator'

// Tags
param tags = {
  Environment: 'Production'
  ManagedBy: 'azure-operator'
  Purpose: 'Azure Landing Zone Operators'
}

// Container Registry (must exist and contain operator images)
param containerRegistryName = 'cralzoperators'
param containerRegistryResourceGroup = 'rg-shared-services'

// Image tag
param imageTag = 'latest'

// Subscription IDs for each operator
// - management: Where Log Analytics, Automation Account are deployed
// - connectivity: Where hub VNets, Firewalls are deployed
// - security: Where Key Vaults are deployed (can be same as management)
param subscriptionIds = {
  management: '00000000-0000-0000-0000-000000000001'
  connectivity: '00000000-0000-0000-0000-000000000002'
  security: '00000000-0000-0000-0000-000000000001' // Often same as management
}

// Root management group ID (your ALZ root, not tenant root)
param rootManagementGroupId = 'alz'

// Git repository with Bicep specs (this repository)
param gitRepoUrl = 'https://github.com/your-org/azure-operator.git'
param gitBranch = 'main'

// Reconciliation settings
param reconcileIntervalSeconds = 300 // 5 minutes
param dryRun = false // Set to true for testing
