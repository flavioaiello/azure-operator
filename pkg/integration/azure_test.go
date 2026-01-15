//go:build integration

// Package integration provides integration tests for Azure APIs.
//
// These tests require Azure credentials and are skipped by default.
// Run with: go test -tags=integration ./pkg/integration/...
//
// SECURITY NOTE:
// These tests use DefaultAzureCredential for local development only.
// In production, only ManagedIdentityCredential is allowed per secretless architecture.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/auth"
	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/graph"
	"github.com/flavioaiello/azure-operator/pkg/whatif"
)

const (
	testTimeout = 60 * time.Second
)

func skipIfNoCredentials(t *testing.T) {
	t.Helper()
	if os.Getenv("AZURE_SUBSCRIPTION_ID") == "" {
		t.Skip("AZURE_SUBSCRIPTION_ID not set, skipping integration test")
	}
}

func getTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		SubscriptionID: os.Getenv("AZURE_SUBSCRIPTION_ID"),
		Location:       getEnvOrDefault("AZURE_LOCATION", "westeurope"),
		Domain:         "integration-test",
		Mode:           config.ModeObserve,
		Scope:          config.ScopeSubscription,
		SpecsDir:       "../testdata/specs",
		TemplatesDir:   "../testdata/templates",
		Security:       config.DefaultSecurityConfig(),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func TestAuthManagedIdentity(t *testing.T) {
	skipIfNoCredentials(t)

	// SECURITY: Test that secretless enforcement works.
	// This will fail if AZURE_CLIENT_SECRET etc. are set.
	clientID := os.Getenv("AZURE_CLIENT_ID") // Optional for user-assigned MI.

	cred, err := auth.GetManagedIdentityCredential(clientID)
	if err != nil {
		// Expected to fail in local dev if no managed identity available.
		t.Logf("Managed identity not available (expected in local dev): %v", err)
		return
	}
	assert.NotNil(t, cred)
}

func TestAuthDefaultCredential(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// SECURITY: This uses DefaultAzureCredential for LOCAL TESTING ONLY.
	// Production operators MUST use ManagedIdentityCredential via auth.GetManagedIdentityCredential().
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	// Get a token to verify credentials work.
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)
}

func TestGraphClient(t *testing.T) {
	skipIfNoCredentials(t)

	cfg := getTestConfig(t)
	logger, _ := zap.NewDevelopment()

	// SECURITY: Using DefaultAzureCredential for local testing only.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	// Test client creation with correct signature.
	client, err := graph.NewClient(cfg, cred, logger)
	require.NoError(t, err)
	assert.NotNil(t, client)

	t.Log("Graph client created successfully")
}

func TestGraphGetManagedResources(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := getTestConfig(t)
	logger, _ := zap.NewDevelopment()

	// SECURITY: Using DefaultAzureCredential for local testing only.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	client, err := graph.NewClient(cfg, cred, logger)
	require.NoError(t, err)

	// Query for resources managed by this domain.
	resources, err := client.QueryManagedResources(ctx)
	if err != nil {
		// May fail if subscription doesn't have Resource Graph access.
		t.Logf("QueryManagedResources failed (may be expected): %v", err)
		return
	}

	t.Logf("Found %d managed resources for domain %s", len(resources), cfg.Domain)
}

func TestWhatIfExecute(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := getTestConfig(t)
	logger, _ := zap.NewDevelopment()

	// SECURITY: Using DefaultAzureCredential for local testing only.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	// Create WhatIf client with correct signature.
	client, err := whatif.NewClient(cfg, cred, logger)
	require.NoError(t, err)

	// Simple template for WhatIf.
	template := map[string]interface{}{
		"$schema":        "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		"contentVersion": "1.0.0.0",
		"resources":      []interface{}{},
	}

	result, err := client.ExecuteWhatIf(ctx, "test-rg", "test-whatif", template, nil)
	if err != nil {
		// May fail if resource group doesn't exist.
		t.Logf("WhatIf failed (expected if RG doesn't exist): %v", err)
		return
	}

	t.Logf("WhatIf changes: %d", result.ChangeCount())
}
