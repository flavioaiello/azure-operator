// Package deploy provides deployment execution for ARM templates.
package deploy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/approval"
	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/graph"
	"github.com/flavioaiello/azure-operator/pkg/guardrails"
	"github.com/flavioaiello/azure-operator/pkg/whatif"
)

// Constants for deployment execution.
const (
	DefaultDeploymentTimeout  = 30 * time.Minute
	DeploymentNameRandomBytes = 4
	MaxDeploymentNameLength   = 64
	PollingInterval           = 5 * time.Second
)

// DeploymentMode determines deployment behavior.
type DeploymentMode string

const (
	ModeIncremental DeploymentMode = "Incremental"
	ModeComplete    DeploymentMode = "Complete"
)

// Errors.
var (
	ErrDeploymentFailed  = errors.New("deployment failed")
	ErrDeploymentTimeout = errors.New("deployment timed out")
	ErrGuardrailsFailed  = errors.New("guardrails check failed")
	ErrApprovalRequired  = errors.New("approval required")
	ErrApprovalPending   = errors.New("approval pending")
	ErrNoChangesDetected = errors.New("no changes detected")
	ErrInvalidScope      = errors.New("invalid deployment scope")
)

// DeploymentResult contains the outcome of a deployment.
type DeploymentResult struct {
	DeploymentName string        `json:"deploymentName"`
	Status         string        `json:"status"`
	CorrelationID  string        `json:"correlationId,omitempty"`
	Duration       time.Duration `json:"duration"`
	Changes        int           `json:"changes"`
	Error          string        `json:"error,omitempty"`
	ApprovalID     string        `json:"approvalId,omitempty"`
}

// Succeeded returns true if deployment succeeded.
func (r *DeploymentResult) Succeeded() bool {
	return r.Status == "Succeeded"
}

// Executor executes deployments with safety checks.
type Executor struct {
	config            *config.Config
	logger            *zap.Logger
	credential        azcore.TokenCredential
	graphClient       *graph.Client
	whatIfClient      *whatif.Client
	guardrails        *guardrails.Checker
	approvalManager   *approval.Manager
	deploymentsClient *armresources.DeploymentsClient
}

// NewExecutor creates a new deployment executor.
func NewExecutor(
	cfg *config.Config,
	logger *zap.Logger,
	credential azcore.TokenCredential,
	graphClient *graph.Client,
	whatIfClient *whatif.Client,
	guardrailsChecker *guardrails.Checker,
	approvalMgr *approval.Manager,
) (*Executor, error) {
	var deploymentsClient *armresources.DeploymentsClient
	var err error

	if cfg.Scope == config.ScopeSubscription {
		deploymentsClient, err = armresources.NewDeploymentsClient(cfg.SubscriptionID, credential, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create deployments client: %w", err)
		}
	}

	return &Executor{
		config:            cfg,
		logger:            logger,
		credential:        credential,
		graphClient:       graphClient,
		whatIfClient:      whatIfClient,
		guardrails:        guardrailsChecker,
		approvalManager:   approvalMgr,
		deploymentsClient: deploymentsClient,
	}, nil
}

// ExecuteOptions configures deployment execution.
type ExecuteOptions struct {
	ResourceGroup string
	Template      map[string]interface{}
	Parameters    map[string]interface{}
	Mode          DeploymentMode
	Timeout       time.Duration
	SkipWhatIf    bool
	ApprovalID    string
}

// Execute runs a deployment with all safety checks.
func (e *Executor) Execute(ctx context.Context, opts ExecuteOptions) (*DeploymentResult, error) {
	startTime := time.Now()
	deploymentName := generateDeploymentName(e.config.Domain)

	e.logger.Info("Starting deployment",
		zap.String("name", deploymentName),
		zap.String("domain", e.config.Domain),
		zap.String("mode", string(opts.Mode)),
	)

	result := &DeploymentResult{
		DeploymentName: deploymentName,
		Status:         "Pending",
	}

	whatIfResult, err := e.runWhatIfPhase(ctx, opts, deploymentName, result, startTime)
	if err != nil || result.Status != "Pending" {
		return result, err
	}

	if err := e.runGuardrailsPhase(ctx, whatIfResult, result, startTime); err != nil {
		return result, err
	}

	if err := e.runApprovalPhase(ctx, opts, deploymentName, whatIfResult, result, startTime); err != nil {
		return result, err
	}

	if e.config.Mode == config.ModeObserve {
		result.Status = "DryRun"
		result.Duration = time.Since(startTime)
		e.logger.Info("Observe mode - skipping deployment")
		return result, nil
	}

	return e.runDeploymentPhase(ctx, opts, deploymentName, result, startTime)
}

// runWhatIfPhase executes WhatIf analysis if enabled.
func (e *Executor) runWhatIfPhase(
	ctx context.Context,
	opts ExecuteOptions,
	deploymentName string,
	result *DeploymentResult,
	startTime time.Time,
) (*whatif.Result, error) {
	if opts.SkipWhatIf || e.whatIfClient == nil {
		return nil, nil
	}

	whatIfResult, err := e.whatIfClient.ExecuteWhatIf(
		ctx,
		opts.ResourceGroup,
		deploymentName,
		opts.Template,
		opts.Parameters,
	)
	if err != nil {
		e.logger.Error("WhatIf failed", zap.Error(err))
		result.Status = "Failed"
		result.Error = fmt.Sprintf("WhatIf failed: %v", err)
		result.Duration = time.Since(startTime)
		return nil, err
	}

	if !whatIfResult.HasChanges() {
		e.logger.Info("No changes detected")
		result.Status = "NoChanges"
		result.Duration = time.Since(startTime)
		return whatIfResult, nil
	}

	result.Changes = len(whatIfResult.Changes)
	return whatIfResult, nil
}

// runGuardrailsPhase checks guardrails if enabled.
func (e *Executor) runGuardrailsPhase(
	ctx context.Context,
	whatIfResult *whatif.Result,
	result *DeploymentResult,
	startTime time.Time,
) error {
	if e.guardrails == nil || whatIfResult == nil {
		return nil
	}

	guardrailResult := e.guardrails.Check(ctx, whatIfResult)
	if !guardrailResult.Passed {
		e.logger.Warn("Guardrails check failed",
			zap.Int("violations", len(guardrailResult.Violations)),
		)
		result.Status = "Blocked"
		result.Error = formatViolations(guardrailResult.Violations)
		result.Duration = time.Since(startTime)
		return ErrGuardrailsFailed
	}
	return nil
}

// runApprovalPhase handles approval workflow in protect mode.
func (e *Executor) runApprovalPhase(
	ctx context.Context,
	opts ExecuteOptions,
	deploymentName string,
	whatIfResult *whatif.Result,
	result *DeploymentResult,
	startTime time.Time,
) error {
	if e.config.Mode != config.ModeProtect || e.approvalManager == nil {
		return nil
	}

	if opts.ApprovalID == "" {
		return e.createApprovalRequest(ctx, deploymentName, opts.ResourceGroup, whatIfResult, result, startTime)
	}

	return e.validateApproval(ctx, opts.ApprovalID, result, startTime)
}

// createApprovalRequest creates a new approval request.
func (e *Executor) createApprovalRequest(
	ctx context.Context,
	deploymentName, resourceGroup string,
	whatIfResult *whatif.Result,
	result *DeploymentResult,
	startTime time.Time,
) error {
	approvalReq, err := e.approvalManager.CreateRequest(
		ctx,
		deploymentName,
		resourceGroup,
		whatIfResult,
	)
	if err != nil {
		e.logger.Error("Failed to create approval", zap.Error(err))
		result.Status = "Failed"
		result.Error = fmt.Sprintf("Failed to create approval: %v", err)
		result.Duration = time.Since(startTime)
		return err
	}

	result.Status = "AwaitingApproval"
	result.ApprovalID = approvalReq.ID
	result.Duration = time.Since(startTime)
	return ErrApprovalRequired
}

// validateApproval checks if an approval is valid and approved.
func (e *Executor) validateApproval(
	ctx context.Context,
	approvalID string,
	result *DeploymentResult,
	startTime time.Time,
) error {
	approvalReq, err := e.approvalManager.GetRequest(ctx, approvalID)
	if err != nil {
		result.Status = "Failed"
		result.Error = fmt.Sprintf("Invalid approval: %v", err)
		result.Duration = time.Since(startTime)
		return err
	}

	if approvalReq.Status != approval.StatusApproved {
		result.Status = "Blocked"
		result.ApprovalID = approvalID
		result.Error = fmt.Sprintf("Approval status: %s", approvalReq.Status)
		result.Duration = time.Since(startTime)
		return ErrApprovalPending
	}
	return nil
}

// runDeploymentPhase executes the actual ARM deployment.
func (e *Executor) runDeploymentPhase(
	ctx context.Context,
	opts ExecuteOptions,
	deploymentName string,
	result *DeploymentResult,
	startTime time.Time,
) (*DeploymentResult, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultDeploymentTimeout
	}

	deployCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	deployResult, err := e.executeARMDeployment(deployCtx, opts, deploymentName)
	if err != nil {
		result.Status = "Failed"
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, err
	}

	if e.guardrails != nil {
		e.guardrails.RecordDeployment()
	}

	result.Status = "Succeeded"
	result.CorrelationID = deployResult.CorrelationID
	result.Duration = time.Since(startTime)

	e.logger.Info("Deployment succeeded",
		zap.String("name", deploymentName),
		zap.Duration("duration", result.Duration),
		zap.Int("changes", result.Changes),
	)

	return result, nil
}

type armDeploymentResult struct {
	CorrelationID string
}

func (e *Executor) executeARMDeployment(
	ctx context.Context,
	opts ExecuteOptions,
	deploymentName string,
) (*armDeploymentResult, error) {
	if e.deploymentsClient == nil {
		return nil, ErrInvalidScope
	}

	deployment := armresources.Deployment{
		Properties: &armresources.DeploymentProperties{
			Template:   opts.Template,
			Parameters: opts.Parameters,
			Mode:       to.Ptr(armresources.DeploymentMode(opts.Mode)),
		},
	}

	if opts.ResourceGroup != "" {
		_, err := e.deploymentsClient.BeginCreateOrUpdate(
			ctx,
			opts.ResourceGroup,
			deploymentName,
			deployment,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to start deployment: %w", err)
		}
		return e.pollResourceGroupDeployment(ctx, opts.ResourceGroup, deploymentName)
	}

	_, err := e.deploymentsClient.BeginCreateOrUpdateAtSubscriptionScope(
		ctx,
		deploymentName,
		deployment,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start subscription deployment: %w", err)
	}
	return e.pollSubscriptionDeployment(ctx, deploymentName)
}

func (e *Executor) pollResourceGroupDeployment(
	ctx context.Context,
	resourceGroup string,
	deploymentName string,
) (*armDeploymentResult, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ErrDeploymentTimeout
		case <-time.After(PollingInterval):
			resp, err := e.deploymentsClient.Get(ctx, resourceGroup, deploymentName, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get deployment status: %w", err)
			}

			state := *resp.Properties.ProvisioningState
			switch state {
			case armresources.ProvisioningStateSucceeded:
				return &armDeploymentResult{
					CorrelationID: safeString(resp.Properties.CorrelationID),
				}, nil
			case armresources.ProvisioningStateFailed, armresources.ProvisioningStateCanceled:
				return nil, fmt.Errorf("%w: %s", ErrDeploymentFailed, state)
			}
		}
	}
}

func (e *Executor) pollSubscriptionDeployment(
	ctx context.Context,
	deploymentName string,
) (*armDeploymentResult, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ErrDeploymentTimeout
		case <-time.After(PollingInterval):
			resp, err := e.deploymentsClient.GetAtSubscriptionScope(ctx, deploymentName, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get deployment status: %w", err)
			}

			state := *resp.Properties.ProvisioningState
			switch state {
			case armresources.ProvisioningStateSucceeded:
				return &armDeploymentResult{
					CorrelationID: safeString(resp.Properties.CorrelationID),
				}, nil
			case armresources.ProvisioningStateFailed, armresources.ProvisioningStateCanceled:
				return nil, fmt.Errorf("%w: %s", ErrDeploymentFailed, state)
			}
		}
	}
}

func generateDeploymentName(domain string) string {
	timestamp := time.Now().UTC().Format("20060102-150405")

	randomBytes := make([]byte, DeploymentNameRandomBytes)
	_, _ = rand.Read(randomBytes)
	randomSuffix := hex.EncodeToString(randomBytes)

	name := fmt.Sprintf("%s-%s-%s", domain, timestamp, randomSuffix)

	if len(name) > MaxDeploymentNameLength {
		name = name[:MaxDeploymentNameLength]
	}

	return name
}

func formatViolations(violations []guardrails.Violation) string {
	if len(violations) == 0 {
		return ""
	}

	msg := fmt.Sprintf("%d guardrail violation(s):", len(violations))
	for i, v := range violations {
		msg += fmt.Sprintf(" [%d] %s", i+1, v.Message)
	}
	return msg
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
