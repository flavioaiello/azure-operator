package testutil

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Path segment for provider in resource IDs.
const pathProvidersSegment = "/providers/"

// MockResourceClient provides a mock implementation of Azure ResourceManagementClient.
// Thread-safe.
type MockResourceClient struct {
	mu sync.Mutex

	state              *MockResourceState
	shouldFailDeploy   bool
	shouldFailWhatIf   bool
	failMessage        string
	deploymentDelay    time.Duration
	whatIfDelay        time.Duration
	deploymentCallback func(*MockDeployment)
}

// NewMockResourceClient creates a new mock resource client.
func NewMockResourceClient(state *MockResourceState) *MockResourceClient {
	if state == nil {
		state = NewMockResourceState()
	}
	return &MockResourceClient{
		state:       state,
		failMessage: "mock deployment failed",
	}
}

// State returns the underlying resource state.
func (m *MockResourceClient) State() *MockResourceState {
	return m.state
}

// SetDeploymentFailure configures deployments to fail.
func (m *MockResourceClient) SetDeploymentFailure(shouldFail bool, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFailDeploy = shouldFail
	if message != "" {
		m.failMessage = message
	}
}

// SetWhatIfFailure configures WhatIf to fail.
func (m *MockResourceClient) SetWhatIfFailure(shouldFail bool, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFailWhatIf = shouldFail
	if message != "" {
		m.failMessage = message
	}
}

// SetDeploymentDelay sets simulated deployment duration.
func (m *MockResourceClient) SetDeploymentDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deploymentDelay = d
}

// SetDeploymentCallback sets a callback invoked on each deployment.
func (m *MockResourceClient) SetDeploymentCallback(cb func(*MockDeployment)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deploymentCallback = cb
}

// DeployInput represents deployment input parameters.
type DeployInput struct {
	Name              string
	SubscriptionID    string
	ResourceGroup     *string
	ManagementGroupID *string
	Location          string
	Template          map[string]interface{}
	Parameters        map[string]interface{}
	Mode              string
}

// DeployOutput represents deployment result.
type DeployOutput struct {
	Deployment *MockDeployment
	Error      error
}

// Deploy simulates an ARM deployment.
func (m *MockResourceClient) Deploy(ctx context.Context, input DeployInput) (*MockDeployment, error) {
	m.mu.Lock()
	shouldFail := m.shouldFailDeploy
	failMessage := m.failMessage
	delay := m.deploymentDelay
	callback := m.deploymentCallback
	m.mu.Unlock()

	// Create deployment record
	deployment := &MockDeployment{
		Name:              input.Name,
		SubscriptionID:    input.SubscriptionID,
		ResourceGroup:     input.ResourceGroup,
		ManagementGroupID: input.ManagementGroupID,
		Location:          input.Location,
		Template:          input.Template,
		Parameters:        input.Parameters,
		Mode:              input.Mode,
		ProvisioningState: DeploymentStateAccepted,
		CorrelationID:     uuid.New().String(),
		Timestamp:         time.Now(),
		Outputs:           make(map[string]interface{}),
	}

	// Record deployment
	if err := m.state.CreateDeployment(deployment); err != nil {
		return nil, err
	}

	// Update to running
	_ = m.state.UpdateDeploymentState(deployment.Name, DeploymentStateRunning, nil, nil)

	// Simulate delay
	if delay > 0 {
		select {
		case <-ctx.Done():
			_ = m.state.UpdateDeploymentState(deployment.Name, DeploymentStateCanceled, nil, nil)
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}

	// Check for configured failure
	if shouldFail {
		err := &DeploymentError{
			Code:    "DeploymentFailed",
			Message: failMessage,
		}
		_ = m.state.UpdateDeploymentState(deployment.Name, DeploymentStateFailed, err, nil)
		deployment.ProvisioningState = DeploymentStateFailed
		deployment.Error = err
		return deployment, nil
	}

	// Apply resources from template to state
	m.applyTemplateResources(input)

	// Mark succeeded
	_ = m.state.UpdateDeploymentState(deployment.Name, DeploymentStateSucceeded, nil, nil)
	deployment.ProvisioningState = DeploymentStateSucceeded

	// Invoke callback if set
	if callback != nil {
		callback(deployment)
	}

	return deployment, nil
}

// applyTemplateResources creates resources from template in state.
func (m *MockResourceClient) applyTemplateResources(input DeployInput) {
	resources, ok := input.Template["resources"].([]interface{})
	if !ok {
		return
	}

	for _, res := range resources {
		resourceDef, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		resource := m.buildResourceFromDef(resourceDef, input)
		if resource != nil {
			_ = m.state.PutResource(resource)
		}
	}
}

// buildResourceFromDef creates a MockResource from a resource definition.
func (m *MockResourceClient) buildResourceFromDef(resourceDef map[string]interface{}, input DeployInput) *MockResource {
	resourceType, _ := resourceDef["type"].(string)
	resourceName, _ := resourceDef["name"].(string)
	location, _ := resourceDef["location"].(string)
	props, _ := resourceDef["properties"].(map[string]interface{})

	resourceID := m.buildResourceID(resourceType, resourceName, input)
	tags := extractTags(resourceDef)

	return &MockResource{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Name:         resourceName,
		Location:     location,
		Properties:   props,
		Tags:         tags,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		APIVersion:   "2024-01-01",
	}
}

// buildResourceID constructs the resource ID based on scope.
func (m *MockResourceClient) buildResourceID(resourceType, resourceName string, input DeployInput) string {
	if input.ManagementGroupID != nil {
		return "/providers/Microsoft.Management/managementGroups/" + *input.ManagementGroupID +
			pathProvidersSegment + resourceType + "/" + resourceName
	}
	if input.ResourceGroup != nil {
		return "/subscriptions/" + input.SubscriptionID +
			"/resourceGroups/" + *input.ResourceGroup +
			pathProvidersSegment + resourceType + "/" + resourceName
	}
	return "/subscriptions/" + input.SubscriptionID +
		pathProvidersSegment + resourceType + "/" + resourceName
}

// extractTags extracts tags from a resource definition.
func extractTags(resourceDef map[string]interface{}) map[string]string {
	tags := make(map[string]string)
	t, ok := resourceDef["tags"].(map[string]interface{})
	if !ok {
		return tags
	}
	for k, v := range t {
		if s, ok := v.(string); ok {
			tags[k] = s
		}
	}
	return tags
}

// WhatIf simulates a WhatIf operation.
func (m *MockResourceClient) WhatIf(ctx context.Context, input DeployInput) (*MockWhatIfResult, error) {
	m.mu.Lock()
	shouldFail := m.shouldFailWhatIf
	failMessage := m.failMessage
	delay := m.whatIfDelay
	m.mu.Unlock()

	// Simulate delay
	if delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}

	// Check for configured failure
	if shouldFail {
		return &MockWhatIfResult{
			Status: "Failed",
			Error: &DeploymentError{
				Code:    "WhatIfFailed",
				Message: failMessage,
			},
		}, nil
	}

	// Compute WhatIf result from state
	return m.state.ComputeWhatIf(
		input.Template,
		input.SubscriptionID,
		input.ResourceGroup,
		input.ManagementGroupID,
	), nil
}

// GetDeployment returns a deployment by name.
func (m *MockResourceClient) GetDeployment(name string) *MockDeployment {
	return m.state.GetDeployment(name)
}

// Clear resets all state.
func (m *MockResourceClient) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Clear()
	m.shouldFailDeploy = false
	m.shouldFailWhatIf = false
	m.deploymentDelay = 0
	m.whatIfDelay = 0
	m.deploymentCallback = nil
}
