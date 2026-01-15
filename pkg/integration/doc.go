// Package integration provides integration tests for the Azure Operator.
//
// These tests require Azure credentials and actual Azure resources.
// They are excluded from normal test runs via build tags.
//
// To run integration tests:
//
//	export AZURE_SUBSCRIPTION_ID=your-subscription-id
//	go test -tags=integration -v ./pkg/integration/...
//
// Required environment variables:
//   - AZURE_SUBSCRIPTION_ID: Target subscription for tests
//   - AZURE_LOCATION: Azure region (default: westeurope)
//
// Authentication:
//   - Uses DefaultAzureCredential for local development
//   - Uses ManagedIdentityCredential in production
package integration
