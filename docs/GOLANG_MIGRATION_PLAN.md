# Azure Operator: Python to Golang Migration Plan

> **Document Version:** 1.5  
> **Date:** January 15, 2026  
> **Status:** COMPLETE - 303 tests passing - All packages migrated

---

## Migration Progress Summary

| Phase | Status | Tests | Packages |
|-------|--------|-------|----------|
| Phase 0: Skeleton | ✅ Complete | - | go.mod, golangci.yml |
| Phase 1: Core | ✅ Complete | 67 | config, auth, loader, reconciler |
| Phase 2: Connectivity | ✅ Complete | 41 | specs, graph, whatif |
| Phase 3: Safety | ✅ Complete | 76 | approval, guardrails, deploy |
| Phase 4: Bootstrap | ✅ Complete | 69 | bootstrap, stacks, dependency, pause |
| Phase 5: Migration | ✅ Complete | 28 | integration, migrate, validate |
| Phase 5b: Mock | ✅ Complete | 22 | testutil (Azure API mocks) |

**Current Metrics:**
- 18 Go packages implemented
- 303 tests passing
- 2 binaries compiling (operator, azo)
- ~15MB static binary size

**CLI Commands:**
- `azo migrate status` - Migration status
- `azo migrate promote` - Advance operator stage
- `azo migrate rollback` - Rollback operator stage
- `azo migrate compare` - Compare Python/Go results
- `azo validate specs` - Validate spec files
- `azo validate templates` - Validate templates
- `azo validate compare` - Compare spec directories

---

## Executive Summary

This document outlines a comprehensive plan to migrate the Azure Landing Zone Operator from Python to Go. The migration targets improved runtime performance, reduced container image size, enhanced concurrency handling, and alignment with the Kubernetes operator ecosystem.

**Current State:**
- Python 3.11/3.12 application (~1,500 LoC core modules)
- Pydantic v2 for validation, Azure SDK for Python
- ~50MB container image (distroless)
- Async reconciliation loop

**Target State:**
- Go 1.22+ application
- Native Azure SDK for Go
- ~10-15MB container image (scratch/distroless)
- Goroutine-based concurrency

---

## I. Migration Rationale

### Benefits of Go

| Aspect | Python (Current) | Go (Target) |
|--------|------------------|-------------|
| **Binary Size** | ~50MB (interpreter + deps) | ~10-15MB (static binary) |
| **Startup Time** | 500-1000ms | 50-100ms |
| **Memory Usage** | 100-200MB per operator | 20-50MB per operator |
| **Concurrency** | asyncio (single-threaded) | Goroutines (true parallelism) |
| **Type Safety** | Runtime (Pydantic) | Compile-time |
| **Operator Ecosystem** | Custom patterns | controller-runtime, kubebuilder alignment |
| **Cloud Native** | Good SDK support | Excellent SDK + ecosystem |

### Risks

1. **Learning Curve:** Team must be proficient in Go idioms
2. **Azure SDK Parity:** Go SDK may have feature gaps vs Python
3. **Pydantic Loss:** Go lacks equivalent runtime validation library
4. **Test Rewrite:** All 453 tests require reimplementation

---

## II. Architecture Mapping

### Module-to-Package Mapping

| Python Module | Go Package | Description |
|---------------|------------|-------------|
| `controller/config.py` | `pkg/config` | Configuration loading, validation |
| `controller/models.py` | `pkg/specs` | Spec models with struct tags |
| `controller/security.py` | `pkg/auth` | Managed Identity, secretless enforcement |
| `controller/reconciler.py` | `pkg/reconciler` | Core reconciliation loop |
| `controller/spec_loader.py` | `pkg/loader` | YAML parsing, validation |
| `controller/resource_graph.py` | `pkg/graph` | Resource Graph queries |
| `controller/bootstrap.py` | `pkg/bootstrap` | Identity provisioning cascade |
| `controller/guardrails.py` | `pkg/guardrails` | Safety limits, kill switch |
| `controller/approval.py` | `pkg/approval` | Risk scoring, approval gates |
| `controller/cli.py` | `cmd/azo` | CLI application |
| `controller/main.py` | `cmd/operator` | Main operator entry point |
| `controller/dependency.py` | `pkg/dependency` | Dependency ordering |
| `controller/diff_normalizer.py` | `pkg/diff` | WhatIf diff normalization |
| `controller/pause.py` | `pkg/pause` | Pause/resume functionality |
| `controller/provenance.py` | `pkg/provenance` | Change attribution logging |
| `controller/deployment_stacks.py` | `pkg/stacks` | Deployment stacks support |
| `controller/resource_modes.py` | `pkg/modes` | Resource mode overrides |
| `controller/ignore_rules.py` | `pkg/ignore` | Ignore rules evaluation |

### Proposed Go Project Structure

```
azure-operator/
├── cmd/
│   ├── operator/           # Main operator binary
│   │   └── main.go
│   └── azo/                # CLI tool
│       └── main.go
├── pkg/
│   ├── config/             # Configuration management
│   │   ├── config.go
│   │   ├── config_test.go
│   │   └── validation.go
│   ├── specs/              # Spec models (Pydantic → Go structs)
│   │   ├── base.go
│   │   ├── management.go
│   │   ├── connectivity.go
│   │   ├── security.go
│   │   ├── identity.go
│   │   ├── bootstrap.go
│   │   └── validation.go
│   ├── auth/               # Security & authentication
│   │   ├── credential.go
│   │   ├── secretless.go
│   │   └── audit.go
│   ├── reconciler/         # Core reconciliation engine
│   │   ├── reconciler.go
│   │   ├── result.go
│   │   ├── circuit_breaker.go
│   │   └── reconciler_test.go
│   ├── loader/             # Spec loading
│   │   ├── loader.go
│   │   ├── templates.go
│   │   └── loader_test.go
│   ├── graph/              # Resource Graph client
│   │   ├── client.go
│   │   ├── queries.go
│   │   ├── changes.go
│   │   └── orphans.go
│   ├── bootstrap/          # Bootstrap cascade
│   │   ├── reconciler.go
│   │   ├── identity.go
│   │   └── rbac.go
│   ├── guardrails/         # Safety guardrails
│   │   ├── enforcer.go
│   │   ├── scope.go
│   │   ├── ratelimit.go
│   │   └── killswitch.go
│   ├── approval/           # Approval workflows
│   │   ├── gate.go
│   │   ├── risk.go
│   │   └── webhook.go
│   ├── dependency/         # Dependency resolution
│   │   ├── checker.go
│   │   └── graph.go
│   ├── diff/               # Diff normalization
│   │   ├── normalizer.go
│   │   └── whatif.go
│   ├── pause/              # Pause management
│   │   ├── manager.go
│   │   └── state.go
│   ├── provenance/         # Change provenance
│   │   ├── logger.go
│   │   └── summary.go
│   ├── stacks/             # Deployment stacks
│   │   └── stacks.go
│   ├── modes/              # Resource modes
│   │   ├── modes.go
│   │   └── evaluator.go
│   ├── ignore/             # Ignore rules
│   │   └── rules.go
│   └── testutil/           # Test utilities
│       ├── mocks/
│       │   ├── azure.go
│       │   └── graph.go
│       └── fixtures/
├── internal/
│   └── version/            # Build version info
│       └── version.go
├── api/
│   └── v1alpha1/           # CRD types (future K8s operator)
├── bicep/                  # Unchanged
├── archetypes/             # Unchanged
├── infrastructure/         # Unchanged
├── templates/              # Unchanged
├── build/
│   └── Dockerfile          # Updated for Go
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## III. Dependency Mapping

### Azure SDK Equivalents

| Python Package | Go Package | Notes |
|----------------|------------|-------|
| `azure-identity` | `github.com/Azure/azure-sdk-for-go/sdk/azidentity` | Full parity |
| `azure-mgmt-resource` | `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources` | Full parity |
| `azure-mgmt-resourcegraph` | `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph` | Full parity |
| `azure-core` | `github.com/Azure/azure-sdk-for-go/sdk/azcore` | Full parity |
| `pydantic` | `go-playground/validator/v10` + struct tags | See validation section |
| `PyYAML` | `gopkg.in/yaml.v3` | Full parity |
| `click` | `github.com/spf13/cobra` | Industry standard |

### Additional Go Dependencies

```go
// go.mod
module github.com/flavioaiello/azure-operator

go 1.22

require (
    github.com/Azure/azure-sdk-for-go/sdk/azcore v1.9.0
    github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.5.0
    github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.2.0
    github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph v0.8.0
    github.com/go-playground/validator/v10 v10.17.0
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.0
    go.uber.org/zap v1.26.0
    gopkg.in/yaml.v3 v3.0.1
)
```

---

## IV. Migration Phases

### Phase 0: Preparation (2 weeks)

**Objectives:**
- Set up Go project skeleton
- Establish CI/CD for Go
- Document coding standards

**Tasks:**
1. Initialize `go.mod` with dependencies
2. Create project structure directories
3. Set up `golangci-lint` configuration
4. Configure GitHub Actions for Go
5. Create Makefile targets for Go
6. Document Go coding standards aligned with AGENTS.md

**Deliverables:**
- [ ] Go project skeleton
- [ ] CI pipeline (lint, test, build)
- [ ] Coding standards document

---

### Phase 1: Core Infrastructure (3 weeks)

**Objectives:**
- Implement config, auth, and base spec models
- Establish validation patterns

**Tasks:**

#### 1.1 Configuration (`pkg/config`)
```go
// pkg/config/config.go
package config

import (
    "fmt"
    "regexp"
    "time"
)

// DeploymentScope represents Azure deployment scope
type DeploymentScope string

const (
    ScopeSubscription     DeploymentScope = "subscription"
    ScopeManagementGroup  DeploymentScope = "managementGroup"
    ScopeResourceGroup    DeploymentScope = "resourceGroup"
)

// ReconciliationMode defines how drift is handled
type ReconciliationMode string

const (
    ModeObserve ReconciliationMode = "observe"
    ModeEnforce ReconciliationMode = "enforce"
    ModeProtect ReconciliationMode = "protect"
)

// Validated constants - SECURITY: Named constants for all limits
const (
    DefaultReconcileInterval     = 300 * time.Second
    MinReconcileInterval         = 60 * time.Second
    MaxReconcileInterval         = 3600 * time.Second
    DefaultWhatIfTimeout         = 300 * time.Second
    DefaultDeploymentTimeout     = 1800 * time.Second
    MaxDeploymentRetries         = 3
    RetryBackoffBase             = 5 * time.Second
    MaxSpecFileSizeBytes         = 1024 * 1024      // 1MB
    MaxTemplateFileSizeBytes     = 10 * 1024 * 1024 // 10MB
    MaxDeploymentNameLength      = 64
    MaxResourceGroupNameLength   = 90
    MaxConcurrentDeployments     = 1
    MaxWhatIfChanges             = 1000
    MaxGraphQueryResults         = 1000
    MaxGraphQueryTimeout         = 30 * time.Second
)

// Input validation patterns
var (
    ValidDomainPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}[a-z0-9]$`)
    ValidSubscriptionIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
    ValidLocationPattern       = regexp.MustCompile(`^[a-z]{2,}[a-z0-9]*$`)
)

// Config holds operator configuration
type Config struct {
    Domain                    string             `validate:"required,domain"`
    SubscriptionID            string             `validate:"required,uuid"`
    Location                  string             `validate:"required,location"`
    SpecsDir                  string             `validate:"required,dir"`
    TemplatesDir              string             `validate:"required,dir"`
    Scope                     DeploymentScope    `validate:"required,oneof=subscription managementGroup resourceGroup"`
    ManagementGroupID         string             `validate:"required_if=Scope managementGroup"`
    ResourceGroupName         string             `validate:"required_if=Scope resourceGroup,max=90"`
    Mode                      ReconciliationMode `validate:"required,oneof=observe enforce protect"`
    ReconcileInterval         time.Duration      `validate:"required,min=60s,max=3600s"`
    WhatIfTimeout             time.Duration      `validate:"required"`
    DeploymentTimeout         time.Duration      `validate:"required"`
    EnableGraphCheck          bool
    Security                  SecurityConfig
}

// SecurityConfig holds security-related settings
type SecurityConfig struct {
    MaxResourcesPerDeployment int  `validate:"required,min=1,max=1000"`
    EnableAuditLogging        bool
}

// Validate performs configuration validation
func (c *Config) Validate() error {
    // Use go-playground/validator
    // Plus custom validation for patterns
}
```

#### 1.2 Authentication (`pkg/auth`)
```go
// pkg/auth/secretless.go
package auth

import (
    "context"
    "errors"
    "os"
    
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "go.uber.org/zap"
)

// ForbiddenCredentialEnvVars lists environment variables that indicate credential leakage
var ForbiddenCredentialEnvVars = []string{
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_USERNAME",
    "AZURE_PASSWORD",
}

// ErrSecretlessViolation indicates secretless architecture is violated
var ErrSecretlessViolation = errors.New("secretless architecture violation: credential environment variable detected")

// EnforceSecretlessArchitecture checks that no credential secrets are present
func EnforceSecretlessArchitecture() error {
    for _, envVar := range ForbiddenCredentialEnvVars {
        if os.Getenv(envVar) != "" {
            zap.L().Error("Secretless architecture violation",
                zap.String("env_var", envVar),
                zap.String("action", "startup_blocked"),
            )
            return fmt.Errorf("%w: %s", ErrSecretlessViolation, envVar)
        }
    }
    zap.L().Info("Secretless architecture verified",
        zap.String("credential_type", "ManagedIdentity"),
    )
    return nil
}

// GetManagedIdentityCredential returns a ManagedIdentityCredential after verification
func GetManagedIdentityCredential(clientID string) (*azidentity.ManagedIdentityCredential, error) {
    if err := EnforceSecretlessArchitecture(); err != nil {
        return nil, err
    }
    
    opts := &azidentity.ManagedIdentityCredentialOptions{}
    if clientID != "" {
        opts.ID = azidentity.ClientID(clientID)
    }
    
    return azidentity.NewManagedIdentityCredential(opts)
}
```

#### 1.3 Base Spec Models (`pkg/specs`)
```go
// pkg/specs/base.go
package specs

import (
    "github.com/go-playground/validator/v10"
)

// BaseSpec contains common fields for all specs
type BaseSpec struct {
    Location          string            `yaml:"location" validate:"omitempty,location"`
    ResourceGroupName string            `yaml:"resourceGroupName" validate:"omitempty,max=90"`
    Tags              map[string]string `yaml:"tags"`
    DependsOn         []string          `yaml:"dependsOn"`
    ModeConfig        *ModeConfig       `yaml:"modeConfig,omitempty"`
}

// ModeConfig allows per-resource mode overrides
type ModeConfig struct {
    DefaultMode string          `yaml:"defaultMode" validate:"omitempty,oneof=observe enforce protect"`
    Overrides   []ModeOverride  `yaml:"overrides"`
}

// ModeOverride specifies mode for specific resource types
type ModeOverride struct {
    ResourceTypes []string `yaml:"resourceTypes" validate:"required,min=1"`
    Mode          string   `yaml:"mode" validate:"required,oneof=observe enforce protect"`
}

// Validate validates the base spec
func (s *BaseSpec) Validate(v *validator.Validate) error {
    return v.Struct(s)
}
```

**Deliverables:**
- [ ] `pkg/config` with full validation
- [ ] `pkg/auth` with secretless enforcement
- [ ] `pkg/specs` base models
- [ ] Unit tests with 90%+ coverage

---

### Phase 2: Spec Models Migration (2 weeks)

**Objectives:**
- Port all Pydantic models to Go structs
- Implement `ToARMParameters()` methods

**Tasks:**

#### 2.1 Management Spec
```go
// pkg/specs/management.go
package specs

// LogAnalyticsConfig represents Log Analytics workspace config
type LogAnalyticsConfig struct {
    Name          string `yaml:"name" validate:"required,min=1,max=63"`
    RetentionDays int    `yaml:"retentionDays" validate:"required,min=30,max=730"`
    SKU           string `yaml:"sku" validate:"required,oneof=PerGB2018 CapacityReservation Free Standalone"`
}

// AutomationConfig represents Automation account config
type AutomationConfig struct {
    Name string `yaml:"name" validate:"required,min=1,max=50"`
}

// ManagementSpec represents the management domain specification
type ManagementSpec struct {
    BaseSpec            `yaml:",inline"`
    LogAnalytics        LogAnalyticsConfig       `yaml:"logAnalytics" validate:"required"`
    Automation          *AutomationConfig        `yaml:"automation,omitempty"`
    DataCollectionRules []DataCollectionRuleConfig `yaml:"dataCollectionRules"`
    ManagedIdentities   []ManagedIdentityConfig  `yaml:"managedIdentities"`
}

// ToARMParameters converts spec to ARM template parameters
func (s *ManagementSpec) ToARMParameters() map[string]interface{} {
    params := make(map[string]interface{})
    
    if s.Location != "" {
        params["location"] = map[string]interface{}{"value": s.Location}
    }
    if s.ResourceGroupName != "" {
        params["resourceGroupName"] = map[string]interface{}{"value": s.ResourceGroupName}
    }
    
    params["logAnalyticsName"] = map[string]interface{}{"value": s.LogAnalytics.Name}
    params["logAnalyticsRetentionDays"] = map[string]interface{}{"value": s.LogAnalytics.RetentionDays}
    params["logAnalyticsSku"] = map[string]interface{}{"value": s.LogAnalytics.SKU}
    
    // ... rest of parameters
    
    return params
}
```

#### 2.2 Port Remaining Spec Types
- `ConnectivitySpec` (firewall, bastion, VPN, DNS, hub-network)
- `SecuritySpec` (defender, keyvault, sentinel)  
- `IdentitySpec` (management groups, role assignments)
- `BootstrapSpec` (operator identities)

**Deliverables:**
- [ ] All spec types ported with validation
- [ ] `ToARMParameters()` for all types
- [ ] YAML round-trip tests
- [ ] Validation error tests

---

### Phase 3: Loader & Graph Client (2 weeks)

**Objectives:**
- Implement spec loading with size checks
- Implement Resource Graph client

**Tasks:**

#### 3.1 Spec Loader (`pkg/loader`)
```go
// pkg/loader/loader.go
package loader

import (
    "fmt"
    "io"
    "os"
    "path/filepath"
    
    "gopkg.in/yaml.v3"
    
    "github.com/flavioaiello/azure-operator/pkg/config"
    "github.com/flavioaiello/azure-operator/pkg/specs"
)

// ErrSpecFileTooLarge indicates the spec file exceeds size limit
var ErrSpecFileTooLarge = errors.New("spec file exceeds maximum size")

// LoadSpec loads and validates a domain spec from YAML
func LoadSpec(specsDir, domain string) (specs.Spec, error) {
    specPath := filepath.Join(specsDir, domain+".yaml")
    
    // SECURITY: Check file size before reading
    info, err := os.Stat(specPath)
    if err != nil {
        return nil, fmt.Errorf("failed to stat spec file: %w", err)
    }
    
    if info.Size() > config.MaxSpecFileSizeBytes {
        return nil, fmt.Errorf("%w: %s (%d bytes)", 
            ErrSpecFileTooLarge, specPath, info.Size())
    }
    
    file, err := os.Open(specPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open spec file: %w", err)
    }
    defer file.Close()
    
    // Read with limit
    limitedReader := io.LimitReader(file, config.MaxSpecFileSizeBytes+1)
    data, err := io.ReadAll(limitedReader)
    if err != nil {
        return nil, fmt.Errorf("failed to read spec file: %w", err)
    }
    
    // Parse YAML
    var raw map[string]interface{}
    if err := yaml.Unmarshal(data, &raw); err != nil {
        return nil, fmt.Errorf("invalid YAML: %w", err)
    }
    
    // Get spec class and unmarshal
    spec, err := specs.UnmarshalSpec(domain, data)
    if err != nil {
        return nil, err
    }
    
    return spec, nil
}
```

#### 3.2 Resource Graph Client (`pkg/graph`)
```go
// pkg/graph/client.go
package graph

import (
    "context"
    "time"
    
    "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// Client wraps the Resource Graph API
type Client struct {
    client  *armresourcegraph.Client
    config  *config.Config
    timeout time.Duration
}

// NewClient creates a new Resource Graph client
func NewClient(cred azcore.TokenCredential, cfg *config.Config) (*Client, error) {
    client, err := armresourcegraph.NewClient(cred, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create graph client: %w", err)
    }
    
    return &Client{
        client:  client,
        config:  cfg,
        timeout: config.MaxGraphQueryTimeout,
    }, nil
}

// QueryRecentChanges returns changes in the last interval
func (c *Client) QueryRecentChanges(ctx context.Context, since time.Time) ([]ResourceChange, error) {
    ctx, cancel := context.WithTimeout(ctx, c.timeout)
    defer cancel()
    
    // Build query for ResourceChanges table
    query := fmt.Sprintf(`
        resourcechanges
        | where subscriptionId == '%s'
        | where changeTime >= datetime(%s)
        | project resourceId, changeType, changeTime, changedBy, clientType
        | limit %d
    `, c.config.SubscriptionID, since.Format(time.RFC3339), config.MaxGraphQueryResults)
    
    // Execute query
    // ...
}
```

**Deliverables:**
- [ ] `pkg/loader` with size validation
- [ ] `pkg/graph` with bounded queries
- [ ] Integration tests with mocks

---

### Phase 4: Reconciler Core (4 weeks)

**Objectives:**
- Port the reconciliation loop
- Implement circuit breaker
- Implement WhatIf integration

**Tasks:**

#### 4.1 Reconciler Structure
```go
// pkg/reconciler/reconciler.go
package reconciler

import (
    "context"
    "sync"
    "time"
    
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

const (
    MaxConsecutiveFailures    = 5
    CircuitBreakerResetPeriod = 5 * time.Minute
)

// Reconciler implements the control loop
type Reconciler struct {
    config           *config.Config
    resourceClient   *armresources.Client
    deploymentsClient *armresources.DeploymentsClient
    graphClient      *graph.Client
    loader           *loader.Loader
    guardrails       *guardrails.Enforcer
    approval         *approval.Gate
    
    // Circuit breaker state
    consecutiveFailures int
    circuitOpenUntil    time.Time
    mu                  sync.Mutex
}

// ReconcileResult represents the outcome of a reconciliation cycle
type ReconcileResult struct {
    Domain           string
    Mode             config.ReconciliationMode
    StartTime        time.Time
    EndTime          time.Time
    DriftFound       bool
    ChangesApplied   int
    ChangesBlocked   int
    ApprovalRequired bool
    ApprovalRequestID string
    RiskAssessment   *approval.RiskAssessment
    Error            error
}

// Run starts the reconciliation loop
func (r *Reconciler) Run(ctx context.Context) error {
    ticker := time.NewTicker(r.config.ReconcileInterval)
    defer ticker.Stop()
    
    // Initial reconciliation
    if err := r.reconcileOnce(ctx); err != nil {
        r.handleFailure(err)
    }
    
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            if r.isCircuitOpen() {
                zap.L().Warn("Circuit breaker open, skipping reconciliation")
                continue
            }
            if err := r.reconcileOnce(ctx); err != nil {
                r.handleFailure(err)
            } else {
                r.resetCircuitBreaker()
            }
        }
    }
}

func (r *Reconciler) reconcileOnce(ctx context.Context) error {
    result := &ReconcileResult{
        Domain:    r.config.Domain,
        Mode:      r.config.Mode,
        StartTime: time.Now().UTC(),
    }
    defer func() {
        result.EndTime = time.Now().UTC()
        r.logResult(result)
    }()
    
    // 1. Check guardrails
    if err := r.guardrails.Check(ctx); err != nil {
        result.Error = err
        return err
    }
    
    // 2. Load spec
    spec, err := r.loader.LoadSpec(r.config.SpecsDir, r.config.Domain)
    if err != nil {
        result.Error = err
        return err
    }
    
    // 3. Fast-path: Resource Graph check
    if r.config.EnableGraphCheck {
        changes, err := r.graphClient.QueryRecentChanges(ctx, time.Now().Add(-r.config.ReconcileInterval))
        if err == nil && len(changes) == 0 {
            // No recent changes, skip WhatIf
            return nil
        }
    }
    
    // 4. WhatIf for precise diff
    whatifResult, err := r.runWhatIf(ctx, spec)
    if err != nil {
        result.Error = err
        return err
    }
    
    // 5. Process changes based on mode
    // ...
}
```

#### 4.2 WhatIf Integration
```go
// pkg/reconciler/whatif.go
package reconciler

func (r *Reconciler) runWhatIf(ctx context.Context, spec specs.Spec) (*armresources.WhatIfOperationResult, error) {
    ctx, cancel := context.WithTimeout(ctx, r.config.WhatIfTimeout)
    defer cancel()
    
    params := spec.ToARMParameters()
    template, err := r.loader.LoadTemplate(r.config.TemplatesDir, r.config.Domain)
    if err != nil {
        return nil, err
    }
    
    props := &armresources.DeploymentWhatIfProperties{
        Mode:       to.Ptr(armresources.DeploymentModeIncremental),
        Template:   template,
        Parameters: params,
    }
    
    var poller *runtime.Poller[armresources.DeploymentsClientWhatIfResponse]
    var pollErr error
    
    switch r.config.Scope {
    case config.ScopeSubscription:
        poller, pollErr = r.deploymentsClient.BeginWhatIfAtSubscriptionScope(
            ctx, r.generateDeploymentName(), 
            armresources.DeploymentWhatIf{Properties: props}, nil)
    case config.ScopeManagementGroup:
        poller, pollErr = r.deploymentsClient.BeginWhatIfAtManagementGroupScope(
            ctx, r.config.ManagementGroupID, r.generateDeploymentName(),
            armresources.ScopedDeploymentWhatIf{Properties: props}, nil)
    }
    
    if pollErr != nil {
        return nil, pollErr
    }
    
    result, err := poller.PollUntilDone(ctx, nil)
    if err != nil {
        return nil, err
    }
    
    // SECURITY: Bound the number of changes processed
    if result.Properties != nil && len(result.Properties.Changes) > config.MaxWhatIfChanges {
        return nil, fmt.Errorf("WhatIf returned %d changes, exceeds limit of %d",
            len(result.Properties.Changes), config.MaxWhatIfChanges)
    }
    
    return &result.WhatIfOperationResult, nil
}
```

**Deliverables:**
- [ ] Core reconciler with circuit breaker
- [ ] WhatIf integration
- [ ] ARM deployment execution
- [ ] Mode handling (observe/enforce/protect)
- [ ] Comprehensive tests

---

### Phase 5: Supporting Modules (3 weeks)

**Objectives:**
- Port guardrails, approval, pause, provenance
- Port bootstrap reconciler

**Tasks:**

#### 5.1 Guardrails (`pkg/guardrails`)
- Scope validation
- Rate limiting
- Kill switch
- Concurrency control

#### 5.2 Approval (`pkg/approval`)
- Risk scoring
- Webhook integration
- Approval state management

#### 5.3 Bootstrap (`pkg/bootstrap`)
- Identity provisioning
- RBAC assignment
- Cascade coordination

#### 5.4 Other Modules
- `pkg/pause` - Pause/resume
- `pkg/provenance` - Change attribution
- `pkg/dependency` - Dependency ordering
- `pkg/diff` - WhatIf normalization
- `pkg/modes` - Resource mode overrides
- `pkg/ignore` - Ignore rules

**Deliverables:**
- [ ] All supporting packages ported
- [ ] Integration tests
- [ ] Feature parity with Python

---

### Phase 6: CLI & Entry Points (2 weeks)

**Objectives:**
- Implement `azo` CLI with Cobra
- Implement main operator entry point

**Tasks:**

#### 6.1 CLI (`cmd/azo`)
```go
// cmd/azo/main.go
package main

import (
    "github.com/spf13/cobra"
)

func main() {
    rootCmd := &cobra.Command{
        Use:   "azo",
        Short: "Azure Operator CLI",
    }
    
    rootCmd.AddCommand(
        newDevCmd(),
        newBuildCmd(),
        newDeployCmd(),
        newRunCmd(),
        newCleanCmd(),
    )
    
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}

func newRunCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "run [domain]",
        Short: "Run operator locally",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            domain := args[0]
            // Initialize and run reconciler
        },
    }
    return cmd
}
```

#### 6.2 Operator Entry Point (`cmd/operator`)
```go
// cmd/operator/main.go
package main

func main() {
    // Setup logging
    logger := zap.NewProduction()
    defer logger.Sync()
    
    // Load config from environment
    cfg, err := config.LoadFromEnv()
    if err != nil {
        logger.Fatal("Failed to load config", zap.Error(err))
    }
    
    // Enforce secretless architecture
    if err := auth.EnforceSecretlessArchitecture(); err != nil {
        logger.Fatal("Security violation", zap.Error(err))
    }
    
    // Get managed identity credential
    cred, err := auth.GetManagedIdentityCredential("")
    if err != nil {
        logger.Fatal("Failed to get credential", zap.Error(err))
    }
    
    // Create and run reconciler
    reconciler, err := reconciler.New(cfg, cred)
    if err != nil {
        logger.Fatal("Failed to create reconciler", zap.Error(err))
    }
    
    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
    defer cancel()
    
    if err := reconciler.Run(ctx); err != nil && err != context.Canceled {
        logger.Fatal("Reconciler failed", zap.Error(err))
    }
}
```

**Deliverables:**
- [ ] `azo` CLI with all commands
- [ ] Operator main with graceful shutdown
- [ ] Signal handling

---

### Phase 7: Testing & Mocks (2 weeks)

**Objectives:**
- Port test fixtures
- Implement Azure SDK mocks
- Achieve 90%+ coverage

**Tasks:**

#### 7.1 Mock Infrastructure
```go
// pkg/testutil/mocks/azure.go
package mocks

import (
    "context"
    
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// MockDeploymentsClient mocks the Azure Deployments API
type MockDeploymentsClient struct {
    WhatIfFunc      func(ctx context.Context, ...) error
    BeginCreateFunc func(ctx context.Context, ...) error
    // ...
}
```

#### 7.2 Test Coverage Targets

| Package | Target Coverage |
|---------|----------------|
| `pkg/config` | 95% |
| `pkg/auth` | 95% |
| `pkg/specs` | 90% |
| `pkg/loader` | 90% |
| `pkg/reconciler` | 85% |
| `pkg/guardrails` | 90% |
| `pkg/approval` | 85% |
| `pkg/graph` | 80% |

**Deliverables:**
- [ ] Mock framework
- [ ] All unit tests ported
- [ ] Integration tests
- [ ] Coverage reports

---

### Phase 8: Container & Deployment (1 week)

**Objectives:**
- Update Dockerfile for Go
- Validate ACI deployment

**Tasks:**

#### 8.1 Go Dockerfile
```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /operator ./cmd/operator

# Runtime stage - scratch for minimal attack surface
FROM scratch

LABEL org.opencontainers.image.title="Azure Landing Zone Operator"
LABEL org.opencontainers.image.source="https://github.com/flavioaiello/azure-operator"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /operator /operator

USER 65532:65532

ENTRYPOINT ["/operator"]
```

**Expected Image Size:** ~10-15MB

**Deliverables:**
- [ ] Multi-stage Dockerfile
- [ ] Image build automation
- [ ] ACI deployment validation

---

### Phase 9: Validation & Cutover (2 weeks)

**Objectives:**
- Parallel running with Python
- Feature parity validation
- Production cutover

**Tasks:**
1. Deploy Go operator alongside Python (observe mode)
2. Compare reconciliation results
3. Validate WhatIf output parity
4. Stress test with multiple domains
5. Performance benchmarking
6. Gradual cutover per domain

**Acceptance Criteria:**
- [ ] All 453 test scenarios pass
- [ ] WhatIf output matches Python implementation
- [ ] No regressions in drift detection
- [ ] Memory usage ≤50MB per operator
- [ ] Startup time ≤100ms

---

## V. Validation Strategy

### Pydantic → Go Validation Mapping

| Pydantic Feature | Go Equivalent |
|------------------|---------------|
| `Field(min_length=1)` | `validate:"min=1"` |
| `Field(max_length=63)` | `validate:"max=63"` |
| `Field(ge=30, le=730)` | `validate:"min=30,max=730"` |
| `@field_validator` | Custom validator functions |
| `model_config = {"extra": "ignore"}` | YAML unmarshal with strict mode |
| Field aliases | YAML struct tags |

### Custom Validators
```go
// pkg/specs/validation.go
package specs

import (
    "regexp"
    
    "github.com/go-playground/validator/v10"
)

func RegisterCustomValidators(v *validator.Validate) {
    v.RegisterValidation("domain", validateDomain)
    v.RegisterValidation("location", validateLocation)
    v.RegisterValidation("sku", validateSKU)
}

func validateDomain(fl validator.FieldLevel) bool {
    return config.ValidDomainPattern.MatchString(fl.Field().String())
}
```

---

## VI. Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Azure Go SDK gaps | Audit SDK parity before phase 1; fallback to REST if needed |
| Test coverage regression | Mandate 85% coverage gate in CI |
| Performance regression | Benchmark critical paths; compare to Python baseline |
| Validation gaps | Port Pydantic tests first; validate edge cases |
| Team Go proficiency | Pair programming; code review focus on idioms |
| Deployment issues | Blue-green deployment; quick rollback path |

---

## VII. Timeline Summary

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 0: Preparation | 2 weeks | 2 weeks |
| Phase 1: Core Infrastructure | 3 weeks | 5 weeks |
| Phase 2: Spec Models | 2 weeks | 7 weeks |
| Phase 3: Loader & Graph | 2 weeks | 9 weeks |
| Phase 4: Reconciler Core | 4 weeks | 13 weeks |
| Phase 5: Supporting Modules | 3 weeks | 16 weeks |
| Phase 6: CLI & Entry Points | 2 weeks | 18 weeks |
| Phase 7: Testing & Mocks | 2 weeks | 20 weeks |
| Phase 8: Container & Deployment | 1 week | 21 weeks |
| Phase 9: Validation & Cutover | 2 weeks | **23 weeks** |

**Total Duration:** ~6 months

---

## VIII. Success Metrics

| Metric | Target |
|--------|--------|
| Container image size | ≤15MB |
| Startup time | ≤100ms |
| Memory per operator | ≤50MB |
| Test coverage | ≥85% |
| Reconcile loop overhead | ≤10ms |
| Feature parity | 100% |
| Zero security regressions | Mandatory |

---

## IX. Post-Migration Considerations

### Future Enhancements (Go-native)

1. **controller-runtime Integration**
   - Align with Kubernetes operator SDK
   - Potential for K8s CRD-based specs

2. **Workqueue Patterns**
   - Replace interval-based reconciliation
   - Event-driven triggers

3. **Metrics & Observability**
   - Prometheus metrics natively
   - OpenTelemetry tracing

4. **Multi-Architecture Builds**
   - ARM64 for Azure ARM-based VMs
   - Reduced ACI costs

---

## X. Appendix

### A. Module Complexity Ranking

| Module | LoC (Python) | Complexity | Migration Effort |
|--------|--------------|------------|------------------|
| `models.py` | 1531 | High | 4 days |
| `reconciler.py` | 1278 | Very High | 8 days |
| `guardrails.py` | 842 | Medium | 3 days |
| `cli.py` | 683 | Medium | 3 days |
| `approval.py` | 611 | Medium | 3 days |
| `bootstrap.py` | 597 | High | 4 days |
| `resource_graph.py` | 569 | Medium | 3 days |
| `config.py` | 326 | Low | 2 days |
| `spec_loader.py` | 239 | Low | 1 day |
| `security.py` | 160 | Low | 1 day |
| Other modules | ~800 | Low-Medium | 5 days |

### B. Azure SDK Version Requirements

```
github.com/Azure/azure-sdk-for-go/sdk/azcore >= 1.9.0
github.com/Azure/azure-sdk-for-go/sdk/azidentity >= 1.5.0
github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources >= 1.2.0
github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph >= 0.8.0
```

### C. Key Go Idioms to Apply

1. **Error Handling:** Use `errors.Is()` and `errors.As()` for error matching
2. **Context Propagation:** Pass `context.Context` through all call chains
3. **Interfaces:** Define interfaces where you use them, not where you implement them
4. **Concurrency:** Use channels for communication, mutexes for state protection
5. **Struct Embedding:** Prefer composition over inheritance
6. **Table-Driven Tests:** Use `testing.T` with subtests

---

## XI. Decision Log

| Decision | Rationale | Date |
|----------|-----------|------|
| Use `go-playground/validator` | Most mature Go validation library | 2026-01-15 |
| Use `cobra` for CLI | Industry standard, used by kubectl | 2026-01-15 |
| Use `zap` for logging | High performance, structured logging | 2026-01-15 |
| Scratch base image | Minimal attack surface, smallest size | 2026-01-15 |
| 6-month timeline | Conservative estimate with buffer | 2026-01-15 |

---

**Document Maintainer:** Platform Team  
**Next Review:** End of Phase 1
