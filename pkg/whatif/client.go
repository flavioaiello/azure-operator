// Package whatif provides ARM WhatIf integration for precise drift detection.
package whatif

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
)

// Constants for WhatIf operations.
const (
	WhatIfTimeout    = 5 * time.Minute
	MaxWhatIfChanges = 500
	PollingInterval  = 5 * time.Second
)

// ChangeType represents the type of change.
type ChangeType string

const (
	ChangeTypeCreate      ChangeType = "Create"
	ChangeTypeDelete      ChangeType = "Delete"
	ChangeTypeModify      ChangeType = "Modify"
	ChangeTypeNoChange    ChangeType = "NoChange"
	ChangeTypeIgnore      ChangeType = "Ignore"
	ChangeTypeDeploy      ChangeType = "Deploy"
	ChangeTypeUnsupported ChangeType = "Unsupported"
)

// Errors.
var (
	ErrWhatIfFailed    = errors.New("WhatIf operation failed")
	ErrWhatIfTimeout   = errors.New("WhatIf operation timed out")
	ErrTooManyChanges  = errors.New("WhatIf returned too many changes")
	ErrInvalidTemplate = errors.New("invalid ARM template")
)

// Change represents a single WhatIf change.
type Change struct {
	ResourceID        string
	ChangeType        ChangeType
	Before            map[string]interface{}
	After             map[string]interface{}
	PropertyChanges   []PropertyChange
	UnsupportedReason string
}

// PropertyChange represents a property-level change.
type PropertyChange struct {
	Path       string
	Before     interface{}
	After      interface{}
	ChangeType ChangeType
}

// Result represents the WhatIf result.
type Result struct {
	Changes  []Change
	Status   string
	Error    string
	Duration time.Duration
}

// HasChanges returns true if there are any actionable changes.
func (r *Result) HasChanges() bool {
	for _, c := range r.Changes {
		switch c.ChangeType {
		case ChangeTypeCreate, ChangeTypeDelete, ChangeTypeModify:
			return true
		}
	}
	return false
}

// ChangeCount returns the total number of changes.
func (r *Result) ChangeCount() int {
	return len(r.Changes)
}

// CountByType returns the count for a specific change type.
func (r *Result) CountByType(ct ChangeType) int {
	count := 0
	for _, c := range r.Changes {
		if c.ChangeType == ct {
			count++
		}
	}
	return count
}

// Client provides WhatIf operations.
type Client struct {
	config *config.Config
	cred   azcore.TokenCredential
	logger *zap.Logger
}

// NewClient creates a new WhatIf client.
func NewClient(cfg *config.Config, cred azcore.TokenCredential, logger *zap.Logger) (*Client, error) {
	if cred == nil {
		return nil, errors.New("credential is required")
	}

	return &Client{
		config: cfg,
		cred:   cred,
		logger: logger,
	}, nil
}

// ExecuteWhatIf runs a WhatIf operation for a deployment.
func (c *Client) ExecuteWhatIf(
	ctx context.Context,
	resourceGroupName string,
	deploymentName string,
	template map[string]interface{},
	parameters map[string]interface{},
) (*Result, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, WhatIfTimeout)
	defer cancel()

	deploymentsClient, err := armresources.NewDeploymentsClient(c.config.SubscriptionID, c.cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create deployments client: %w", err)
	}

	properties := armresources.DeploymentWhatIfProperties{
		Mode:       toPtr(armresources.DeploymentModeIncremental),
		Template:   template,
		Parameters: parameters,
	}

	whatIfRequest := armresources.DeploymentWhatIf{
		Properties: &properties,
	}

	c.logger.Info("Starting WhatIf operation",
		zap.String("domain", c.config.Domain),
		zap.String("resourceGroup", resourceGroupName),
		zap.String("deployment", deploymentName),
	)

	poller, err := deploymentsClient.BeginWhatIf(ctx, resourceGroupName, deploymentName, whatIfRequest, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWhatIfFailed, err)
	}

	resp, err := c.pollWhatIf(ctx, poller)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrWhatIfTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrWhatIfFailed, err)
	}

	result := c.parseWhatIfResponse(resp)
	result.Duration = time.Since(start)

	c.logger.Info("WhatIf operation completed",
		zap.String("domain", c.config.Domain),
		zap.Duration("duration", result.Duration),
		zap.Int("changes", len(result.Changes)),
		zap.Bool("has_changes", result.HasChanges()),
	)

	return result, nil
}

// pollWhatIf polls the WhatIf operation until completion.
func (c *Client) pollWhatIf(
	ctx context.Context,
	poller *runtime.Poller[armresources.DeploymentsClientWhatIfResponse],
) (armresources.DeploymentsClientWhatIfResponse, error) {
	return poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: PollingInterval,
	})
}

// parseWhatIfResponse parses the WhatIf response into our Result type.
func (c *Client) parseWhatIfResponse(resp armresources.DeploymentsClientWhatIfResponse) *Result {
	result := &Result{
		Changes: make([]Change, 0),
		Status:  "Succeeded",
	}

	whatIfResult := resp.WhatIfOperationResult
	if whatIfResult.Properties == nil {
		return result
	}

	if whatIfResult.Error != nil && whatIfResult.Error.Message != nil {
		result.Error = *whatIfResult.Error.Message
		result.Status = "Failed"
		return result
	}

	if whatIfResult.Properties.Changes == nil {
		return result
	}

	changes := whatIfResult.Properties.Changes
	if len(changes) > MaxWhatIfChanges {
		c.logger.Warn("WhatIf returned too many changes, truncating",
			zap.Int("total", len(changes)),
			zap.Int("limit", MaxWhatIfChanges),
		)
		changes = changes[:MaxWhatIfChanges]
	}

	for _, change := range changes {
		result.Changes = append(result.Changes, c.parseChange(change))
	}

	return result
}

// parseChange converts an ARM WhatIfChange to our Change type.
func (c *Client) parseChange(armChange *armresources.WhatIfChange) Change {
	change := Change{}

	if armChange.ResourceID != nil {
		change.ResourceID = *armChange.ResourceID
	}

	if armChange.ChangeType != nil {
		change.ChangeType = mapChangeType(*armChange.ChangeType)
	}

	if armChange.Before != nil {
		if m, ok := armChange.Before.(map[string]interface{}); ok {
			change.Before = m
		}
	}

	if armChange.After != nil {
		if m, ok := armChange.After.(map[string]interface{}); ok {
			change.After = m
		}
	}

	if armChange.UnsupportedReason != nil {
		change.UnsupportedReason = *armChange.UnsupportedReason
	}

	if armChange.Delta != nil {
		for _, delta := range armChange.Delta {
			change.PropertyChanges = append(change.PropertyChanges, c.parsePropertyChange(delta))
		}
	}

	return change
}

// parsePropertyChange converts an ARM property change.
func (c *Client) parsePropertyChange(delta *armresources.WhatIfPropertyChange) PropertyChange {
	prop := PropertyChange{}

	if delta.Path != nil {
		prop.Path = *delta.Path
	}
	prop.Before = delta.Before
	prop.After = delta.After

	if delta.PropertyChangeType != nil {
		prop.ChangeType = mapPropertyChangeType(*delta.PropertyChangeType)
	}

	return prop
}

// mapChangeType maps ARM ChangeType to our ChangeType.
func mapChangeType(armType armresources.ChangeType) ChangeType {
	switch armType {
	case armresources.ChangeTypeCreate:
		return ChangeTypeCreate
	case armresources.ChangeTypeDelete:
		return ChangeTypeDelete
	case armresources.ChangeTypeModify:
		return ChangeTypeModify
	case armresources.ChangeTypeNoChange:
		return ChangeTypeNoChange
	case armresources.ChangeTypeIgnore:
		return ChangeTypeIgnore
	case armresources.ChangeTypeDeploy:
		return ChangeTypeDeploy
	case armresources.ChangeTypeUnsupported:
		return ChangeTypeUnsupported
	default:
		return ChangeTypeNoChange
	}
}

// mapPropertyChangeType maps ARM property change type.
func mapPropertyChangeType(armType armresources.PropertyChangeType) ChangeType {
	switch armType {
	case armresources.PropertyChangeTypeCreate:
		return ChangeTypeCreate
	case armresources.PropertyChangeTypeDelete:
		return ChangeTypeDelete
	case armresources.PropertyChangeTypeModify:
		return ChangeTypeModify
	case armresources.PropertyChangeTypeNoEffect:
		return ChangeTypeNoChange
	case armresources.PropertyChangeTypeArray:
		return ChangeTypeModify
	default:
		return ChangeTypeNoChange
	}
}

// toPtr returns a pointer to the value.
func toPtr[T any](v T) *T {
	return &v
}
