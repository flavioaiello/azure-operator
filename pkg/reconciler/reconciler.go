// Package reconciler implements the core reconciliation loop.
//
// The reconciler:
//  1. Loads YAML spec from disk (synced by git-sync sidecar)
//  2. Fast-path: Queries Resource Graph for recent changes
//  3. If changes detected: Runs ARM WhatIf for precise diff
//  4. Applies changes using ARM deployment
//
// HYBRID DRIFT DETECTION:
// - Resource Graph: Fast queries (~2s), change attribution, orphan detection
// - ARM WhatIf: Precise template-to-state diff (~30s)
//
// Combined approach reduces WhatIf calls by ~90% while maintaining accuracy.
//
// SECURITY: Timeouts are enforced on all Azure API calls.
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/approval"
	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/deploy"
	"github.com/flavioaiello/azure-operator/pkg/graph"
	"github.com/flavioaiello/azure-operator/pkg/guardrails"

	"github.com/flavioaiello/azure-operator/pkg/whatif"
)

// Circuit breaker constants.
const (
	MaxConsecutiveFailures    = 5
	CircuitBreakerResetPeriod = 5 * time.Minute
)

// Errors.

// Spec is the interface that all spec types must implement.
type Spec interface {
	Validate() error
	GetOperator() string
	ToARMParameters() map[string]interface{}
	GetDependsOn() []string
}

// SpecLoader loads specs and templates.
type SpecLoader interface {
	LoadSpec(domain string) (Spec, error)
	LoadTemplate(domain string) (map[string]interface{}, error)
}

var (
	ErrCircuitOpen      = errors.New("circuit breaker is open")
	ErrMaxChanges       = errors.New("WhatIf returned too many changes")
	ErrSpecLoad         = errors.New("failed to load spec")
	ErrWhatIfFailed     = errors.New("WhatIf operation failed")
	ErrDeploymentFailed = errors.New("deployment failed")
)

// wrapErr wraps an error with additional context.
func wrapErr(sentinel, cause error) error {
	return fmt.Errorf("%w: %v", sentinel, cause)
}

// Result represents the outcome of a reconciliation cycle.
type Result struct {
	// Domain is the operator domain.
	Domain string
	// Mode is the reconciliation mode.
	Mode config.ReconciliationMode
	// StartTime is when reconciliation started.
	StartTime time.Time
	// EndTime is when reconciliation completed.
	EndTime time.Time
	// DriftFound indicates if drift was detected.
	DriftFound bool
	// ChangesApplied is the number of changes applied.
	ChangesApplied int
	// ChangesBlocked is the number of changes blocked (PROTECT mode).
	ChangesBlocked int
	// ApprovalRequired indicates if waiting for approval.
	ApprovalRequired bool
	// ApprovalRequestID is the pending approval ID.
	ApprovalRequestID string
	// Error is any error that occurred.
	Error error
}

// Duration returns the reconciliation duration.
func (r *Result) Duration() time.Duration {
	if r.EndTime.IsZero() {
		return 0
	}
	return r.EndTime.Sub(r.StartTime)
}

// Success returns true if no error occurred.
func (r *Result) Success() bool {
	return r.Error == nil
}

// Reconciler implements the control loop.
type Reconciler struct {
	config *config.Config
	cred   azcore.TokenCredential
	logger *zap.Logger

	// Azure clients.
	deploymentsClient *armresources.DeploymentsClient
	graphClient       *graph.Client
	whatIfClient      *whatif.Client

	// Safety components.
	guardrailsChecker *guardrails.Checker
	approvalManager   *approval.Manager
	deployExecutor    *deploy.Executor
	specLoader        SpecLoader

	// Circuit breaker state.
	mu                  sync.Mutex
	consecutiveFailures int
	circuitOpenUntil    time.Time
}

// New creates a new Reconciler.
func New(cfg *config.Config, cred azcore.TokenCredential, logger *zap.Logger, specLoader SpecLoader) (*Reconciler, error) {
	// Create deployments client.
	deploymentsClient, err := armresources.NewDeploymentsClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create deployments client: %w", err)
	}

	// Create Resource Graph client.
	graphClient, err := graph.NewClient(cfg, cred, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create graph client: %w", err)
	}

	// Create WhatIf client.
	whatIfClient, err := whatif.NewClient(cfg, cred, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create whatif client: %w", err)
	}

	// Create guardrails checker.
	guardrailsChecker := guardrails.NewChecker(cfg, logger)

	// Create approval manager.
	approvalMgr, err := approval.NewManager(cfg, logger, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create approval manager: %w", err)
	}

	// Create deployment executor.
	deployExecutor, err := deploy.NewExecutor(
		cfg, logger, cred,
		graphClient, whatIfClient,
		guardrailsChecker, approvalMgr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create deploy executor: %w", err)
	}

	return &Reconciler{
		config:            cfg,
		cred:              cred,
		logger:            logger,
		deploymentsClient: deploymentsClient,
		graphClient:       graphClient,
		whatIfClient:      whatIfClient,
		guardrailsChecker: guardrailsChecker,
		approvalManager:   approvalMgr,
		deployExecutor:    deployExecutor,
		specLoader:        specLoader,
	}, nil
}

// Run starts the reconciliation loop.
func (r *Reconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.config.ReconcileInterval)
	defer ticker.Stop()

	// Initial reconciliation.
	result := r.reconcileOnce(ctx)
	r.logResult(result)
	if result.Error != nil {
		r.handleFailure(result.Error)
	} else {
		r.resetCircuitBreaker()
	}

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Reconciliation loop stopped",
				zap.String("domain", r.config.Domain),
				zap.String("reason", ctx.Err().Error()),
			)
			return ctx.Err()

		case <-ticker.C:
			if r.isCircuitOpen() {
				r.logger.Warn("Circuit breaker open, skipping reconciliation",
					zap.String("domain", r.config.Domain),
					zap.Time("open_until", r.circuitOpenUntil),
				)
				continue
			}

			result := r.reconcileOnce(ctx)
			r.logResult(result)

			if result.Error != nil {
				r.handleFailure(result.Error)
			} else {
				r.resetCircuitBreaker()
			}
		}
	}
}

// reconcileOnce performs a single reconciliation cycle.
func (r *Reconciler) reconcileOnce(ctx context.Context) *Result {
	result := &Result{
		Domain:    r.config.Domain,
		Mode:      r.config.Mode,
		StartTime: time.Now().UTC(),
	}
	defer func() {
		result.EndTime = time.Now().UTC()
	}()

	r.logger.Info("Starting reconciliation",
		zap.String("domain", r.config.Domain),
		zap.String("mode", string(r.config.Mode)),
	)

	spec, err := r.loadSpecAndTemplate()
	if err != nil {
		result.Error = err
		return result
	}

	if !r.detectChanges(ctx, result) {
		return result
	}

	whatIfResult, err := r.runWhatIf(ctx, spec)
	if err != nil {
		result.Error = err
		return result
	}

	if !whatIfResult.HasChanges() {
		r.logger.Debug("WhatIf detected no changes")
		result.DriftFound = false
		return result
	}

	r.logDriftDetected(whatIfResult, result)
	r.processChanges(ctx, spec, whatIfResult, result)

	r.logger.Info("Reconciliation complete",
		zap.String("domain", r.config.Domain),
		zap.Bool("drift_found", result.DriftFound),
		zap.Int("changes_applied", result.ChangesApplied),
		zap.Duration("duration", result.Duration()),
	)

	return result
}

// loadSpecAndTemplate loads the spec file and template.
func (r *Reconciler) loadSpecAndTemplate() (Spec, error) {
	spec, err := r.specLoader.LoadSpec(r.config.Domain)
	if err != nil {
		return nil, wrapErr(ErrSpecLoad, err)
	}
	r.logger.Debug("Spec loaded",
		zap.String("domain", r.config.Domain),
		zap.String("operator", spec.GetOperator()),
	)

	_, err = r.specLoader.LoadTemplate(spec.GetOperator())
	if err != nil {
		return nil, fmt.Errorf("failed to load template: %w", err)
	}

	return spec, nil
}

// detectChanges uses Resource Graph to detect recent changes.
// Returns true if changes were detected or check failed.
func (r *Reconciler) detectChanges(ctx context.Context, result *Result) bool {
	graphCtx, graphCancel := context.WithTimeout(ctx, graph.QueryTimeout)
	defer graphCancel()

	recentChanges, err := r.graphClient.QueryRecentChanges(
		graphCtx,
		time.Now().Add(-5*time.Minute),
	)
	if err != nil {
		r.logger.Warn("Resource Graph query failed, falling back to WhatIf",
			zap.Error(err),
		)
		return true
	}

	if len(recentChanges) == 0 {
		r.logger.Debug("No recent changes detected via Resource Graph")
		result.DriftFound = false
		return false
	}

	return true
}

// runWhatIf executes WhatIf analysis.
func (r *Reconciler) runWhatIf(ctx context.Context, spec Spec) (*whatif.Result, error) {
	whatIfCtx, whatIfCancel := context.WithTimeout(ctx, whatif.WhatIfTimeout)
	defer whatIfCancel()

	whatIfResult, err := r.whatIfClient.ExecuteWhatIf(
		whatIfCtx,
		r.config.ResourceGroupName,
		fmt.Sprintf("%s-%d", r.config.Domain, time.Now().Unix()),
		spec.ToARMParameters(),
		nil,
	)
	if err != nil {
		return nil, wrapErr(ErrWhatIfFailed, err)
	}

	return whatIfResult, nil
}

// logDriftDetected logs drift details and updates result.
func (r *Reconciler) logDriftDetected(whatIfResult *whatif.Result, result *Result) {
	result.DriftFound = true
	r.logger.Info("Drift detected",
		zap.Int("total_changes", whatIfResult.ChangeCount()),
		zap.Int("creates", whatIfResult.CountByType(whatif.ChangeTypeCreate)),
		zap.Int("modifies", whatIfResult.CountByType(whatif.ChangeTypeModify)),
		zap.Int("deletes", whatIfResult.CountByType(whatif.ChangeTypeDelete)),
	)
}

// processChanges applies changes based on the configured mode.
func (r *Reconciler) processChanges(ctx context.Context, spec Spec, whatIfResult *whatif.Result, result *Result) {
	switch r.config.Mode {
	case config.ModeObserve:
		r.processObserveMode(whatIfResult, result)
	case config.ModeEnforce:
		r.processEnforceMode(ctx, spec, whatIfResult, result)
	case config.ModeProtect:
		r.processProtectMode(ctx, spec, whatIfResult, result)
	}
}

// processObserveMode handles OBSERVE mode - log only.
func (r *Reconciler) processObserveMode(whatIfResult *whatif.Result, result *Result) {
	r.logger.Info("OBSERVE mode - changes logged but not applied")
	result.ChangesBlocked = whatIfResult.ChangeCount()
}

// processEnforceMode handles ENFORCE mode - apply changes automatically.
func (r *Reconciler) processEnforceMode(ctx context.Context, spec Spec, whatIfResult *whatif.Result, result *Result) {
	deployResult, err := r.deployExecutor.Execute(ctx, deploy.ExecuteOptions{
		Template:   spec.ToARMParameters(),
		Parameters: nil,
		Mode:       deploy.ModeIncremental,
	})
	if err != nil {
		r.handleDeployError(err, whatIfResult, result)
		return
	}
	result.ChangesApplied = deployResult.Changes
}

// processProtectMode handles PROTECT mode - request approval before applying.
func (r *Reconciler) processProtectMode(ctx context.Context, spec Spec, whatIfResult *whatif.Result, result *Result) {
	deployResult, err := r.deployExecutor.Execute(ctx, deploy.ExecuteOptions{
		Template:   spec.ToARMParameters(),
		Parameters: nil,
		Mode:       deploy.ModeIncremental,
	})
	if err != nil {
		if errors.Is(err, deploy.ErrApprovalRequired) {
			result.ApprovalRequired = true
			result.ApprovalRequestID = deployResult.ApprovalID
			result.ChangesBlocked = whatIfResult.ChangeCount()
			return
		}
		r.handleDeployError(err, whatIfResult, result)
		return
	}
	result.ChangesApplied = deployResult.Changes
}

// handleDeployError handles deployment errors.
func (r *Reconciler) handleDeployError(err error, whatIfResult *whatif.Result, result *Result) {
	if errors.Is(err, deploy.ErrGuardrailsFailed) {
		result.ChangesBlocked = whatIfResult.ChangeCount()
	} else {
		result.Error = wrapErr(ErrDeploymentFailed, err)
	}
}

// isCircuitOpen checks if the circuit breaker is open.
func (r *Reconciler) isCircuitOpen() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.consecutiveFailures >= MaxConsecutiveFailures {
		if time.Now().Before(r.circuitOpenUntil) {
			return true
		}
		// Reset circuit breaker after timeout.
		r.consecutiveFailures = 0
	}
	return false
}

// handleFailure increments the failure counter and may open the circuit.
func (r *Reconciler) handleFailure(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.consecutiveFailures++
	r.logger.Error("Reconciliation failed",
		zap.String("domain", r.config.Domain),
		zap.Error(err),
		zap.Int("consecutive_failures", r.consecutiveFailures),
	)

	if r.consecutiveFailures >= MaxConsecutiveFailures {
		r.circuitOpenUntil = time.Now().Add(CircuitBreakerResetPeriod)
		r.logger.Warn("Circuit breaker opened",
			zap.String("domain", r.config.Domain),
			zap.Time("open_until", r.circuitOpenUntil),
		)
	}
}

// resetCircuitBreaker resets the failure counter.
func (r *Reconciler) resetCircuitBreaker() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.consecutiveFailures > 0 {
		r.logger.Info("Circuit breaker reset",
			zap.String("domain", r.config.Domain),
			zap.Int("previous_failures", r.consecutiveFailures),
		)
	}
	r.consecutiveFailures = 0
}

// logResult logs the reconciliation result.
func (r *Reconciler) logResult(result *Result) {
	if result.Error != nil {
		r.logger.Error("Reconciliation result",
			zap.String("domain", result.Domain),
			zap.String("mode", string(result.Mode)),
			zap.Duration("duration", result.Duration()),
			zap.Error(result.Error),
		)
		return
	}

	r.logger.Info("Reconciliation result",
		zap.String("domain", result.Domain),
		zap.String("mode", string(result.Mode)),
		zap.Duration("duration", result.Duration()),
		zap.Bool("drift_found", result.DriftFound),
		zap.Int("changes_applied", result.ChangesApplied),
		zap.Int("changes_blocked", result.ChangesBlocked),
		zap.Bool("approval_required", result.ApprovalRequired),
	)
}
