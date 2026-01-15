package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants to avoid literal duplication.
const testSubscriptionID = "00000000-0000-0000-0000-000000000001"

func TestLoadFromEnvValidConfig(t *testing.T) {
	// Setup environment.
	setEnv := func() {
		os.Setenv("DOMAIN", "management")
		os.Setenv("AZURE_SUBSCRIPTION_ID", testSubscriptionID)
		os.Setenv("AZURE_LOCATION", "westeurope")
	}
	clearEnv := func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
		os.Unsetenv("DEPLOYMENT_SCOPE")
		os.Unsetenv("RECONCILIATION_MODE")
		os.Unsetenv("RECONCILE_INTERVAL_SECONDS")
	}

	setEnv()
	defer clearEnv()

	cfg, err := LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "management", cfg.Domain)
	assert.Equal(t, testSubscriptionID, cfg.SubscriptionID)
	assert.Equal(t, "westeurope", cfg.Location)
	assert.Equal(t, ScopeSubscription, cfg.Scope)
	assert.Equal(t, ModeObserve, cfg.Mode)
	assert.Equal(t, DefaultReconcileInterval, cfg.ReconcileInterval)
}

func TestLoadFromEnvMissingDomain(t *testing.T) {
	os.Setenv("AZURE_SUBSCRIPTION_ID", testSubscriptionID)
	os.Setenv("AZURE_LOCATION", "westeurope")
	defer func() {
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
	}()

	_, err := LoadFromEnv()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingDomain)
}

func TestLoadFromEnvInvalidDomain(t *testing.T) {
	os.Setenv("DOMAIN", "INVALID_DOMAIN")
	os.Setenv("AZURE_SUBSCRIPTION_ID", testSubscriptionID)
	os.Setenv("AZURE_LOCATION", "westeurope")
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
	}()

	_, err := LoadFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DOMAIN must match pattern")
}

func TestLoadFromEnvInvalidSubscriptionID(t *testing.T) {
	os.Setenv("DOMAIN", "management")
	os.Setenv("AZURE_SUBSCRIPTION_ID", "not-a-guid")
	os.Setenv("AZURE_LOCATION", "westeurope")
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
	}()

	_, err := LoadFromEnv()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSubscriptionID)
}

func TestLoadFromEnvManagementGroupScope(t *testing.T) {
	os.Setenv("DOMAIN", "policy")
	os.Setenv("AZURE_SUBSCRIPTION_ID", testSubscriptionID)
	os.Setenv("AZURE_LOCATION", "westeurope")
	os.Setenv("DEPLOYMENT_SCOPE", "managementGroup")
	os.Setenv("MANAGEMENT_GROUP_ID", "mg-platform")
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
		os.Unsetenv("DEPLOYMENT_SCOPE")
		os.Unsetenv("MANAGEMENT_GROUP_ID")
	}()

	cfg, err := LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, ScopeManagementGroup, cfg.Scope)
	assert.Equal(t, "mg-platform", cfg.ManagementGroupID)
}

func TestLoadFromEnvManagementGroupScopeMissingID(t *testing.T) {
	os.Setenv("DOMAIN", "policy")
	os.Setenv("AZURE_SUBSCRIPTION_ID", testSubscriptionID)
	os.Setenv("AZURE_LOCATION", "westeurope")
	os.Setenv("DEPLOYMENT_SCOPE", "managementGroup")
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
		os.Unsetenv("DEPLOYMENT_SCOPE")
	}()

	_, err := LoadFromEnv()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingMgmtGroupID)
}

func TestLoadFromEnvCustomReconcileInterval(t *testing.T) {
	os.Setenv("DOMAIN", "management")
	os.Setenv("AZURE_SUBSCRIPTION_ID", testSubscriptionID)
	os.Setenv("AZURE_LOCATION", "westeurope")
	os.Setenv("RECONCILE_INTERVAL_SECONDS", "600")
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
		os.Unsetenv("RECONCILE_INTERVAL_SECONDS")
	}()

	cfg, err := LoadFromEnv()
	require.NoError(t, err)
	assert.Equal(t, 600*time.Second, cfg.ReconcileInterval)
}

func TestLoadFromEnvReconcileIntervalOutOfRange(t *testing.T) {
	os.Setenv("DOMAIN", "management")
	os.Setenv("AZURE_SUBSCRIPTION_ID", testSubscriptionID)
	os.Setenv("AZURE_LOCATION", "westeurope")
	os.Setenv("RECONCILE_INTERVAL_SECONDS", "30") // Below minimum
	defer func() {
		os.Unsetenv("DOMAIN")
		os.Unsetenv("AZURE_SUBSCRIPTION_ID")
		os.Unsetenv("AZURE_LOCATION")
		os.Unsetenv("RECONCILE_INTERVAL_SECONDS")
	}()

	_, err := LoadFromEnv()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidReconcileInt)
}

func TestValidDomainPattern(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"management", true},
		{"connectivity", true},
		{"hub-network", true},
		{"log-analytics", true},
		{"firewall-secondary", true},
		{"a", false},                 // Too short
		{"ab", true},                 // Minimum length
		{"UPPERCASE", false},         // Must be lowercase
		{"with_underscore", false},   // No underscores
		{"with.dot", false},          // No dots
		{"-starts-with-dash", false}, // Must start with letter
		{"ends-with-dash-", false},   // Must end with alphanumeric
		{"123numeric", false},        // Must start with letter
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.valid, ValidDomainPattern.MatchString(tt.domain))
		})
	}
}

func TestValidSubscriptionIDPattern(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{testSubscriptionID, true},
		{"abcdef00-abcd-abcd-abcd-abcdef123456", true},
		{"not-a-guid", false},
		{"12345678-1234-1234-1234-12345678901", false},   // Too short
		{"12345678-1234-1234-1234-1234567890123", false}, // Too long
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			assert.Equal(t, tt.valid, ValidSubscriptionIDPattern.MatchString(tt.id))
		})
	}
}

func TestValidLocationPattern(t *testing.T) {
	tests := []struct {
		location string
		valid    bool
	}{
		{"westeurope", true},
		{"eastus", true},
		{"eastus2", true},
		{"northcentralus", true},
		{"a", false},           // Too short
		{"West Europe", false}, // No spaces
		{"WESTEUROPE", false},  // Must be lowercase
	}

	for _, tt := range tests {
		t.Run(tt.location, func(t *testing.T) {
			assert.Equal(t, tt.valid, ValidLocationPattern.MatchString(tt.location))
		})
	}
}

func TestParseScope(t *testing.T) {
	tests := []struct {
		input    string
		expected DeploymentScope
		wantErr  bool
	}{
		{"subscription", ScopeSubscription, false},
		{"Subscription", ScopeSubscription, false},
		{"SUBSCRIPTION", ScopeSubscription, false},
		{"managementGroup", ScopeManagementGroup, false},
		{"ManagementGroup", ScopeManagementGroup, false},
		{"resourceGroup", ScopeResourceGroup, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			scope, err := parseScope(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, scope)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		input    string
		expected ReconciliationMode
		wantErr  bool
	}{
		{"observe", ModeObserve, false},
		{"Observe", ModeObserve, false},
		{"OBSERVE", ModeObserve, false},
		{"enforce", ModeEnforce, false},
		{"protect", ModeProtect, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			mode, err := parseMode(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, mode)
			}
		})
	}
}
