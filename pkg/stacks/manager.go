// Package stacks provides deployment stacks support for atomic deployments.
//
// Deployment stacks enable:
//  1. Atomic deployments with rollback
//  2. Resource deletion protection (deny settings)
//  3. Managed resource group lifecycle
package stacks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armdeploymentstacks"
	"go.uber.org/zap"
)

// Constants for deployment stacks.
const (
	// DefaultStackTimeout is the default timeout for stack operations.
	DefaultStackTimeout = 60 * time.Minute
	// MaxStackNameLength is the maximum length for stack names.
	MaxStackNameLength = 90
	// StackPollingInterval is the interval for polling stack status.
	StackPollingInterval = 10 * time.Second
)

// DenySettingsMode controls resource protection.
type DenySettingsMode string

const (
	DenySettingsModeNone            DenySettingsMode = "None"
	DenySettingsModeDenyDelete      DenySettingsMode = "DenyDelete"
	DenySettingsModeDenyWriteDelete DenySettingsMode = "DenyWriteAndDelete"
)

// DeleteResourcesMode controls orphan resource handling.
type DeleteResourcesMode string

const (
	DeleteResourcesModeDetach DeleteResourcesMode = "Detach"
	DeleteResourcesModeDelete DeleteResourcesMode = "Delete"
)

// StackStatus represents the current state of a stack.
type StackStatus string

const (
	StackStatusSucceeded StackStatus = "Succeeded"
	StackStatusFailed    StackStatus = "Failed"
	StackStatusDeploying StackStatus = "Deploying"
	StackStatusDeleting  StackStatus = "Deleting"
	StackStatusCanceled  StackStatus = "Canceled"
	StackStatusUnknown   StackStatus = "Unknown"
)

// Errors.
var (
	ErrStackNotFound         = errors.New("deployment stack not found")
	ErrStackDeploymentFailed = errors.New("stack deployment failed")
	ErrStackDeletionFailed   = errors.New("stack deletion failed")
	ErrStackNameTooLong      = errors.New("stack name exceeds maximum length")
	ErrInvalidDenySettings   = errors.New("invalid deny settings mode")
)

// Error message formats.
const errMsgStacksClient = "failed to create stacks client: %w"

// wrapErr wraps a sentinel error with a cause for additional context.
func wrapErr(sentinel, cause error) error {
	return fmt.Errorf("%w: %v", sentinel, cause)
}

// StackConfig defines configuration for a deployment stack.
type StackConfig struct {
	Name              string
	Description       string
	Scope             string
	ResourceGroup     string
	SubscriptionID    string
	ManagementGroupID string
	Template          map[string]interface{}
	Parameters        map[string]*armdeploymentstacks.DeploymentParameter
	DenySettings      DenySettingsMode
	DeleteMode        DeleteResourcesMode
	Tags              map[string]string
}

// StackResult represents the result of a stack operation.
type StackResult struct {
	ID                string
	Name              string
	Status            StackStatus
	ProvisioningState string
	Resources         []ManagedResource
	Error             string
	Duration          time.Duration
}

// ManagedResource represents a resource managed by a stack.
type ManagedResource struct {
	ID         string
	Name       string
	Type       string
	Status     string
	DenyStatus string
}

// Manager handles deployment stack operations.
type Manager struct {
	logger         *zap.Logger
	credential     azcore.TokenCredential
	subscriptionID string
	timeout        time.Duration
}

// NewManager creates a new stack manager.
func NewManager(
	logger *zap.Logger,
	cred azcore.TokenCredential,
	subscriptionID string,
) *Manager {
	return &Manager{
		logger:         logger,
		credential:     cred,
		subscriptionID: subscriptionID,
		timeout:        DefaultStackTimeout,
	}
}

// WithTimeout sets a custom timeout.
func (m *Manager) WithTimeout(timeout time.Duration) *Manager {
	m.timeout = timeout
	return m
}

// DeployToResourceGroup deploys a stack at resource group scope.
func (m *Manager) DeployToResourceGroup(
	ctx context.Context,
	config StackConfig,
) (*StackResult, error) {
	if len(config.Name) > MaxStackNameLength {
		return nil, ErrStackNameTooLong
	}

	client, err := armdeploymentstacks.NewClient(m.subscriptionID, m.credential, nil)
	if err != nil {
		return nil, fmt.Errorf(errMsgStacksClient, err)
	}

	m.logger.Info("Deploying stack to resource group",
		zap.String("name", config.Name),
		zap.String("resourceGroup", config.ResourceGroup),
	)

	startTime := time.Now()

	stack := armdeploymentstacks.DeploymentStack{
		Properties: &armdeploymentstacks.DeploymentStackProperties{
			Description:      &config.Description,
			DenySettings:     buildDenySettings(config.DenySettings),
			ActionOnUnmanage: buildActionOnUnmanage(config.DeleteMode),
		},
		Tags: toStringPtrMap(config.Tags),
	}

	// Set template if provided.
	if config.Template != nil {
		stack.Properties.Template = config.Template
	}

	// Set parameters if provided.
	if config.Parameters != nil {
		stack.Properties.Parameters = config.Parameters
	}

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	poller, err := client.BeginCreateOrUpdateAtResourceGroup(
		ctx,
		config.ResourceGroup,
		config.Name,
		stack,
		nil,
	)
	if err != nil {
		return nil, wrapErr(ErrStackDeploymentFailed, err)
	}

	resp, err := m.pollStack(ctx, poller)
	if err != nil {
		return nil, err
	}

	result := m.buildResult(resp, startTime)
	m.logger.Info("Stack deployment completed",
		zap.String("name", config.Name),
		zap.String("status", string(result.Status)),
		zap.Duration("duration", result.Duration),
	)

	return result, nil
}

// DeployToSubscription deploys a stack at subscription scope.
func (m *Manager) DeployToSubscription(
	ctx context.Context,
	config StackConfig,
) (*StackResult, error) {
	if len(config.Name) > MaxStackNameLength {
		return nil, ErrStackNameTooLong
	}

	client, err := armdeploymentstacks.NewClient(m.subscriptionID, m.credential, nil)
	if err != nil {
		return nil, fmt.Errorf(errMsgStacksClient, err)
	}

	m.logger.Info("Deploying stack to subscription",
		zap.String("name", config.Name),
		zap.String("subscriptionId", m.subscriptionID),
	)

	startTime := time.Now()

	stack := armdeploymentstacks.DeploymentStack{
		Location: toPtr("westeurope"),
		Properties: &armdeploymentstacks.DeploymentStackProperties{
			Description:      &config.Description,
			DenySettings:     buildDenySettings(config.DenySettings),
			ActionOnUnmanage: buildActionOnUnmanage(config.DeleteMode),
		},
		Tags: toStringPtrMap(config.Tags),
	}

	if config.Template != nil {
		stack.Properties.Template = config.Template
	}
	if config.Parameters != nil {
		stack.Properties.Parameters = config.Parameters
	}

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	poller, err := client.BeginCreateOrUpdateAtSubscription(
		ctx,
		config.Name,
		stack,
		nil,
	)
	if err != nil {
		return nil, wrapErr(ErrStackDeploymentFailed, err)
	}

	resp, err := m.pollSubscriptionStack(ctx, poller)
	if err != nil {
		return nil, err
	}

	result := m.buildResult(resp, startTime)
	return result, nil
}

// GetStack retrieves a stack by name.
func (m *Manager) GetStack(
	ctx context.Context,
	resourceGroup string,
	name string,
) (*StackResult, error) {
	client, err := armdeploymentstacks.NewClient(m.subscriptionID, m.credential, nil)
	if err != nil {
		return nil, fmt.Errorf(errMsgStacksClient, err)
	}

	resp, err := client.GetAtResourceGroup(ctx, resourceGroup, name, nil)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrStackNotFound
		}
		return nil, err
	}

	return m.buildResult(resp.DeploymentStack, time.Now()), nil
}

// DeleteStack removes a stack.
func (m *Manager) DeleteStack(
	ctx context.Context,
	resourceGroup string,
	name string,
	deleteResources bool,
) error {
	client, err := armdeploymentstacks.NewClient(m.subscriptionID, m.credential, nil)
	if err != nil {
		return fmt.Errorf(errMsgStacksClient, err)
	}

	m.logger.Info("Deleting deployment stack",
		zap.String("name", name),
		zap.String("resourceGroup", resourceGroup),
		zap.Bool("deleteResources", deleteResources),
	)

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	var unmanageAction *armdeploymentstacks.UnmanageActionResourceMode
	if deleteResources {
		unmanageAction = toPtr(armdeploymentstacks.UnmanageActionResourceModeDelete)
	} else {
		unmanageAction = toPtr(armdeploymentstacks.UnmanageActionResourceModeDetach)
	}

	opts := &armdeploymentstacks.ClientBeginDeleteAtResourceGroupOptions{
		UnmanageActionResources: unmanageAction,
	}

	poller, err := client.BeginDeleteAtResourceGroup(ctx, resourceGroup, name, opts)
	if err != nil {
		if isNotFoundError(err) {
			return nil // Already deleted.
		}
		return wrapErr(ErrStackDeletionFailed, err)
	}

	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: StackPollingInterval,
	})
	if err != nil {
		return wrapErr(ErrStackDeletionFailed, err)
	}

	m.logger.Info("Stack deleted successfully",
		zap.String("name", name),
	)

	return nil
}

// ListStacks lists all stacks in a resource group.
func (m *Manager) ListStacks(
	ctx context.Context,
	resourceGroup string,
) ([]StackResult, error) {
	client, err := armdeploymentstacks.NewClient(m.subscriptionID, m.credential, nil)
	if err != nil {
		return nil, fmt.Errorf(errMsgStacksClient, err)
	}

	pager := client.NewListAtResourceGroupPager(resourceGroup, nil)
	var results []StackResult

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, stack := range page.Value {
			results = append(results, *m.buildResult(*stack, time.Now()))
		}
	}

	return results, nil
}

// pollStack waits for a stack operation to complete.
func (m *Manager) pollStack(
	ctx context.Context,
	poller *runtime.Poller[armdeploymentstacks.ClientCreateOrUpdateAtResourceGroupResponse],
) (armdeploymentstacks.DeploymentStack, error) {
	resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: StackPollingInterval,
	})
	if err != nil {
		return armdeploymentstacks.DeploymentStack{}, wrapErr(ErrStackDeploymentFailed, err)
	}
	return resp.DeploymentStack, nil
}

// pollSubscriptionStack waits for a subscription-scoped stack operation.
func (m *Manager) pollSubscriptionStack(
	ctx context.Context,
	poller *runtime.Poller[armdeploymentstacks.ClientCreateOrUpdateAtSubscriptionResponse],
) (armdeploymentstacks.DeploymentStack, error) {
	resp, err := poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: StackPollingInterval,
	})
	if err != nil {
		return armdeploymentstacks.DeploymentStack{}, wrapErr(ErrStackDeploymentFailed, err)
	}
	return resp.DeploymentStack, nil
}

// buildResult converts a DeploymentStack to StackResult.
func (m *Manager) buildResult(stack armdeploymentstacks.DeploymentStack, startTime time.Time) *StackResult {
	result := &StackResult{
		Duration: time.Since(startTime),
	}

	result.ID = ptrToString(stack.ID)
	result.Name = ptrToString(stack.Name)

	if stack.Properties != nil {
		m.populatePropertiesResult(stack.Properties, result)
	}

	return result
}

// populatePropertiesResult extracts properties from the stack.
func (m *Manager) populatePropertiesResult(props *armdeploymentstacks.DeploymentStackProperties, result *StackResult) {
	if props.ProvisioningState != nil {
		result.ProvisioningState = string(*props.ProvisioningState)
		result.Status = mapProvisioningState(*props.ProvisioningState)
	}

	result.Resources = m.extractManagedResources(props.Resources)

	if props.Error != nil && props.Error.Message != nil {
		result.Error = *props.Error.Message
	}
}

// extractManagedResources converts SDK resources to ManagedResource slice.
func (m *Manager) extractManagedResources(resources []*armdeploymentstacks.ManagedResourceReference) []ManagedResource {
	if resources == nil {
		return nil
	}

	result := make([]ManagedResource, 0, len(resources))
	for _, res := range resources {
		result = append(result, ManagedResource{
			ID:         ptrToString(res.ID),
			Status:     ptrToResourceStatus(res.Status),
			DenyStatus: ptrToDenyStatus(res.DenyStatus),
		})
	}
	return result
}

// ptrToString safely dereferences a string pointer.
func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ptrToResourceStatus safely dereferences a ResourceStatusMode pointer.
func ptrToResourceStatus(s *armdeploymentstacks.ResourceStatusMode) string {
	if s == nil {
		return ""
	}
	return string(*s)
}

// ptrToDenyStatus safely dereferences a DenyStatusMode pointer.
func ptrToDenyStatus(s *armdeploymentstacks.DenyStatusMode) string {
	if s == nil {
		return ""
	}
	return string(*s)
}

func mapProvisioningState(state armdeploymentstacks.DeploymentStackProvisioningState) StackStatus {
	switch state {
	case armdeploymentstacks.DeploymentStackProvisioningStateSucceeded:
		return StackStatusSucceeded
	case armdeploymentstacks.DeploymentStackProvisioningStateFailed:
		return StackStatusFailed
	case armdeploymentstacks.DeploymentStackProvisioningStateDeploying:
		return StackStatusDeploying
	case armdeploymentstacks.DeploymentStackProvisioningStateDeleting:
		return StackStatusDeleting
	case armdeploymentstacks.DeploymentStackProvisioningStateCanceled:
		return StackStatusCanceled
	default:
		return StackStatusUnknown
	}
}

func buildDenySettings(mode DenySettingsMode) *armdeploymentstacks.DenySettings {
	var denyMode armdeploymentstacks.DenySettingsMode
	switch mode {
	case DenySettingsModeDenyDelete:
		denyMode = armdeploymentstacks.DenySettingsModeDenyDelete
	case DenySettingsModeDenyWriteDelete:
		denyMode = armdeploymentstacks.DenySettingsModeDenyWriteAndDelete
	default:
		denyMode = armdeploymentstacks.DenySettingsModeNone
	}
	return &armdeploymentstacks.DenySettings{
		Mode: &denyMode,
	}
}

func buildActionOnUnmanage(mode DeleteResourcesMode) *armdeploymentstacks.ActionOnUnmanage {
	var resourceMode armdeploymentstacks.DeploymentStacksDeleteDetachEnum
	switch mode {
	case DeleteResourcesModeDelete:
		resourceMode = armdeploymentstacks.DeploymentStacksDeleteDetachEnumDelete
	default:
		resourceMode = armdeploymentstacks.DeploymentStacksDeleteDetachEnumDetach
	}
	return &armdeploymentstacks.ActionOnUnmanage{
		Resources: &resourceMode,
	}
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsSubstr(errStr, "ResourceNotFound") || containsSubstr(errStr, "not found") || containsSubstr(errStr, "NotFound")
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toStringPtrMap(m map[string]string) map[string]*string {
	if m == nil {
		return nil
	}
	result := make(map[string]*string)
	for k, v := range m {
		v := v
		result[k] = &v
	}
	return result
}

func toPtr[T any](v T) *T {
	return &v
}
