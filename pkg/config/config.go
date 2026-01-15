// Package config provides configuration management with validation.
//
// Security constraints are enforced at configuration load time to ensure
// the operator runs in a secure mode by default.
//
// SECURITY: All inputs are validated at the boundary (fail-fast).
// This includes format validation to prevent injection attacks.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DeploymentScope represents Azure deployment scope.
type DeploymentScope string

const (
	// ScopeSubscription targets a subscription.
	ScopeSubscription DeploymentScope = "subscription"
	// ScopeManagementGroup targets a management group.
	ScopeManagementGroup DeploymentScope = "managementGroup"
	// ScopeResourceGroup targets a resource group.
	ScopeResourceGroup DeploymentScope = "resourceGroup"
)

// ReconciliationMode defines how drift is handled.
type ReconciliationMode string

const (
	// ModeObserve reports drift only, never applies changes.
	ModeObserve ReconciliationMode = "observe"
	// ModeEnforce automatically remediates drift.
	ModeEnforce ReconciliationMode = "enforce"
	// ModeProtect blocks external changes, requires manual intervention.
	ModeProtect ReconciliationMode = "protect"
)

// Configuration constants with documented bounds.
// SECURITY: Named constants for all limits - no magic numbers.
const (
	DefaultReconcileInterval   = 300 * time.Second
	MinReconcileInterval       = 60 * time.Second
	MaxReconcileInterval       = 3600 * time.Second
	DefaultWhatIfTimeout       = 300 * time.Second
	DefaultDeploymentTimeout   = 1800 * time.Second
	MaxDeploymentRetries       = 3
	RetryBackoffBase           = 5 * time.Second
	MaxSpecFileSizeBytes       = 1024 * 1024      // 1MB
	MaxTemplateFileSizeBytes   = 10 * 1024 * 1024 // 10MB
	MaxDeploymentNameLength    = 64
	MaxResourceGroupNameLength = 90
	MaxConcurrentDeployments   = 1
	MaxWhatIfChanges           = 1000
	MaxGraphQueryResults       = 1000
	MaxGraphQueryTimeout       = 30 * time.Second
	DefaultGraphCheckEnabled   = true
)

// Input validation patterns.
var (
	// ValidDomainPattern matches valid domain names.
	ValidDomainPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}[a-z0-9]$`)
	// ValidSubscriptionIDPattern matches valid Azure subscription IDs.
	ValidSubscriptionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// ValidLocationPattern matches valid Azure locations.
	ValidLocationPattern = regexp.MustCompile(`^[a-z]{2,}[a-z0-9]*$`)
)

// Configuration errors.
var (
	ErrMissingDomain         = errors.New("DOMAIN is required")
	ErrInvalidDomain         = errors.New("DOMAIN must match pattern ^[a-z][a-z0-9-]{0,62}[a-z0-9]$")
	ErrMissingSubscriptionID = errors.New("AZURE_SUBSCRIPTION_ID is required")
	ErrInvalidSubscriptionID = errors.New("AZURE_SUBSCRIPTION_ID must be a valid GUID")
	ErrMissingLocation       = errors.New("AZURE_LOCATION is required")
	ErrInvalidLocation       = errors.New("AZURE_LOCATION must be a valid Azure region")
	ErrMissingMgmtGroupID    = errors.New("MANAGEMENT_GROUP_ID is required when scope is managementGroup")
	ErrMissingResourceGroup  = errors.New("RESOURCE_GROUP_NAME is required when scope is resourceGroup")
	ErrResourceGroupTooLong  = errors.New("RESOURCE_GROUP_NAME exceeds maximum length")
	ErrInvalidReconcileInt   = errors.New("RECONCILE_INTERVAL out of valid range")
	ErrInvalidMode           = errors.New("RECONCILIATION_MODE must be observe, enforce, or protect")
	ErrInvalidScope          = errors.New("DEPLOYMENT_SCOPE must be subscription, managementGroup, or resourceGroup")
)

// wrapErrWithValue wraps an error with an invalid value for context.
func wrapErrWithValue(err error, value string) error {
	return fmt.Errorf("%w: %s", err, value)
}

// SecurityConfig holds security-related settings.
type SecurityConfig struct {
	// MaxResourcesPerDeployment limits resources per deployment to prevent runaway changes.
	MaxResourcesPerDeployment int
	// EnableAuditLogging enables structured audit logging.
	EnableAuditLogging bool
}

// DefaultSecurityConfig returns the default security configuration.
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		MaxResourcesPerDeployment: 100,
		EnableAuditLogging:        true,
	}
}

// Config holds operator configuration loaded from environment variables.
type Config struct {
	// Domain is the operator domain (e.g., "management", "connectivity").
	Domain string
	// SubscriptionID is the Azure subscription ID.
	SubscriptionID string
	// Location is the Azure region.
	Location string

	// SpecsDir is the directory containing YAML spec files.
	SpecsDir string
	// TemplatesDir is the directory containing ARM templates.
	TemplatesDir string

	// Scope is the Azure deployment scope.
	Scope DeploymentScope
	// ManagementGroupID is required when Scope is ScopeManagementGroup.
	ManagementGroupID string
	// ResourceGroupName is required when Scope is ScopeResourceGroup.
	ResourceGroupName string

	// Mode is the reconciliation mode.
	Mode ReconciliationMode

	// ReconcileInterval is the time between reconciliation cycles.
	ReconcileInterval time.Duration
	// WhatIfTimeout is the timeout for WhatIf operations.
	WhatIfTimeout time.Duration
	// DeploymentTimeout is the timeout for deployment operations.
	DeploymentTimeout time.Duration

	// EnableGraphCheck enables Resource Graph fast-path check.
	EnableGraphCheck bool

	// Security holds security-related configuration.
	Security SecurityConfig
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		Domain:            os.Getenv("DOMAIN"),
		SubscriptionID:    os.Getenv("AZURE_SUBSCRIPTION_ID"),
		Location:          os.Getenv("AZURE_LOCATION"),
		SpecsDir:          getEnvOrDefault("SPECS_DIR", "/specs"),
		TemplatesDir:      getEnvOrDefault("TEMPLATES_DIR", "/templates"),
		ManagementGroupID: os.Getenv("MANAGEMENT_GROUP_ID"),
		ResourceGroupName: os.Getenv("RESOURCE_GROUP_NAME"),
		EnableGraphCheck:  getEnvBool("ENABLE_GRAPH_CHECK", DefaultGraphCheckEnabled),
		Security:          DefaultSecurityConfig(),
	}

	// Parse scope.
	scopeStr := getEnvOrDefault("DEPLOYMENT_SCOPE", string(ScopeSubscription))
	scope, err := parseScope(scopeStr)
	if err != nil {
		return nil, err
	}
	cfg.Scope = scope

	// Parse mode.
	modeStr := getEnvOrDefault("RECONCILIATION_MODE", string(ModeObserve))
	mode, err := parseMode(modeStr)
	if err != nil {
		return nil, err
	}
	cfg.Mode = mode

	// Parse intervals.
	cfg.ReconcileInterval = getEnvDuration("RECONCILE_INTERVAL_SECONDS", DefaultReconcileInterval)
	cfg.WhatIfTimeout = getEnvDuration("WHATIF_TIMEOUT_SECONDS", DefaultWhatIfTimeout)
	cfg.DeploymentTimeout = getEnvDuration("DEPLOYMENT_TIMEOUT_SECONDS", DefaultDeploymentTimeout)

	// Parse security config.
	cfg.Security.MaxResourcesPerDeployment = getEnvInt(
		"MAX_RESOURCES_PER_DEPLOYMENT",
		DefaultSecurityConfig().MaxResourcesPerDeployment,
	)
	cfg.Security.EnableAuditLogging = getEnvBool("ENABLE_AUDIT_LOGGING", true)

	// Validate configuration.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	var errs []error

	// Required field validation.
	if c.Domain == "" {
		errs = append(errs, ErrMissingDomain)
	} else if !ValidDomainPattern.MatchString(c.Domain) {
		errs = append(errs, wrapErrWithValue(ErrInvalidDomain, c.Domain))
	}

	if c.SubscriptionID == "" {
		errs = append(errs, ErrMissingSubscriptionID)
	} else if !ValidSubscriptionIDPattern.MatchString(strings.ToLower(c.SubscriptionID)) {
		errs = append(errs, wrapErrWithValue(ErrInvalidSubscriptionID, c.SubscriptionID))
	}

	if c.Location == "" {
		errs = append(errs, ErrMissingLocation)
	} else if !ValidLocationPattern.MatchString(strings.ToLower(c.Location)) {
		errs = append(errs, wrapErrWithValue(ErrInvalidLocation, c.Location))
	}

	// Scope-specific validation.
	if c.Scope == ScopeManagementGroup && c.ManagementGroupID == "" {
		errs = append(errs, ErrMissingMgmtGroupID)
	}

	if c.Scope == ScopeResourceGroup && c.ResourceGroupName == "" {
		errs = append(errs, ErrMissingResourceGroup)
	}

	if c.ResourceGroupName != "" && len(c.ResourceGroupName) > MaxResourceGroupNameLength {
		errs = append(errs, fmt.Errorf("%w: %d chars", ErrResourceGroupTooLong, len(c.ResourceGroupName)))
	}

	// Timing validation.
	if c.ReconcileInterval < MinReconcileInterval || c.ReconcileInterval > MaxReconcileInterval {
		errs = append(errs, fmt.Errorf("%w: must be between %v and %v",
			ErrInvalidReconcileInt, MinReconcileInterval, MaxReconcileInterval))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// parseScope parses a deployment scope string.
func parseScope(s string) (DeploymentScope, error) {
	switch strings.ToLower(s) {
	case "subscription":
		return ScopeSubscription, nil
	case "managementgroup":
		return ScopeManagementGroup, nil
	case "resourcegroup":
		return ScopeResourceGroup, nil
	default:
		return "", wrapErrWithValue(ErrInvalidScope, s)
	}
}

// parseMode parses a reconciliation mode string.
func parseMode(s string) (ReconciliationMode, error) {
	switch strings.ToLower(s) {
	case string(ModeObserve):
		return ModeObserve, nil
	case string(ModeEnforce):
		return ModeEnforce, nil
	case string(ModeProtect):
		return ModeProtect, nil
	default:
		return "", wrapErrWithValue(ErrInvalidMode, s)
	}
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// getEnvBool parses a boolean environment variable.
func getEnvBool(key string, defaultValue bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return defaultValue
	}
	return b
}

// getEnvInt parses an integer environment variable.
func getEnvInt(key string, defaultValue int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return defaultValue
	}
	return i
}

// getEnvDuration parses a duration from seconds environment variable.
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	seconds, err := strconv.Atoi(v)
	if err != nil {
		return defaultValue
	}
	return time.Duration(seconds) * time.Second
}
