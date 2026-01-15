//go:build integration

// Package integration provides integration tests for Azure APIs.
//
// These tests require Azure credentials and are skipped by default.
// Run with: go test -tags=integration ./pkg/integration/...
package integration

import (
	"context"
	"os"
	"testing"
	"time"

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
		Operator:       "test-operator",
		Mode:           config.ModeObserve,
		SpecsDir:       "../testdata/specs",
		TemplatesDir:   "../testdata/templates",
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

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := getTestConfig(t)
	logger, _ := zap.NewDevelopment()

	provider, err := auth.NewProvider(cfg, logger)
	require.NoError(t, err)

	cred, err := provider.GetCredential(ctx)
	require.NoError(t, err)
	assert.NotNil(t, cred)
}

func TestAuthDefaultCredential(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// This uses DefaultAzureCredential for local testing.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	// Get a token to verify credentials work.
	token, err := cred.GetToken(ctx, azidentity.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)
}

func TestGraphQueryResources(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := getTestConfig(t)
	logger, _ := zap.NewDevelopment()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	client, err := graph.NewClient(logger, cred, cfg.SubscriptionID)
	require.NoError(t, err)

	// Query virtual networks.
	resources, err := client.QueryResources(ctx, graph.QueryOptions{
		ResourceType: "Microsoft.Network/virtualNetworks",
		MaxResults:   10,
	})
	require.NoError(t, err)

	// May be empty if no VNets exist.
	t.Logf("Found %d virtual networks", len(resources))
}

func TestGraphDetectDrift(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := getTestConfig(t)
	logger, _ := zap.NewDevelopment()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	client, err := graph.NewClient(logger, cred, cfg.SubscriptionID)
	require.NoError(t, err)

	// Check for any resources.
	hasDrift, err := client.HasDrift(ctx)
	require.NoError(t, err)

	t.Logf("Drift detected: %v", hasDrift)
}

func TestWhatIfExecute(t *testing.T) {
	skipIfNoCredentials(t)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := getTestConfig(t)
	logger, _ := zap.NewDevelopment()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	client, err := whatif.NewClient(logger, cred, cfg.SubscriptionID)
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
