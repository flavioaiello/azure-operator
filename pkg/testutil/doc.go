// Package testutil provides Azure API mocks for integration testing.
//
// This package enables testing operator functionality without Azure connectivity
// by providing in-memory mock implementations of Azure SDK clients.
//
// Features:
//   - MockCredential: Simulates ManagedIdentityCredential with fake tokens
//   - MockResourceState: In-memory resource state management
//   - MockResourceClient: Simulates ResourceManagementClient operations
//   - MockGraphClient: Simulates Resource Graph queries
//   - MockContext: Coordinates all mocks for integration tests
package testutil
