package testutil

import (
	"errors"
	"sync"
	"time"
)

// Resource limits to prevent unbounded growth in tests.
const (
	MaxResources   = 10000
	MaxDeployments = 1000
)

// Resource ID path segments.
const (
	pathSubscriptions  = "/subscriptions/"
	pathResourceGroups = "/resourceGroups/"
	pathDeployments    = "/providers/Microsoft.Resources/deployments/"
	pathProviders      = "/providers/"
)

// DeploymentProvisioningState represents Azure deployment states.
type DeploymentProvisioningState string

const (
	DeploymentStateAccepted  DeploymentProvisioningState = "Accepted"
	DeploymentStateRunning   DeploymentProvisioningState = "Running"
	DeploymentStateSucceeded DeploymentProvisioningState = "Succeeded"
	DeploymentStateFailed    DeploymentProvisioningState = "Failed"
	DeploymentStateCanceled  DeploymentProvisioningState = "Canceled"
)

// WhatIfChangeType represents Azure WhatIf change types.
type WhatIfChangeType string

const (
	WhatIfChangeCreate   WhatIfChangeType = "Create"
	WhatIfChangeDelete   WhatIfChangeType = "Delete"
	WhatIfChangeModify   WhatIfChangeType = "Modify"
	WhatIfChangeNoChange WhatIfChangeType = "NoChange"
	WhatIfChangeIgnore   WhatIfChangeType = "Ignore"
	WhatIfChangeDeploy   WhatIfChangeType = "Deploy"
)

// Errors.
var (
	ErrResourceLimitExceeded   = errors.New("resource limit exceeded")
	ErrDeploymentLimitExceeded = errors.New("deployment limit exceeded")
	ErrResourceNotFound        = errors.New("resource not found")
	ErrDeploymentNotFound      = errors.New("deployment not found")
)

// MockResource represents a mock Azure resource in state.
type MockResource struct {
	ResourceID   string
	ResourceType string
	Name         string
	Location     string
	Properties   map[string]interface{}
	Tags         map[string]string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	APIVersion   string
}

// NewMockResource creates a new mock resource with defaults.
func NewMockResource(resourceID, resourceType, name, location string) *MockResource {
	now := time.Now()
	return &MockResource{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Name:         name,
		Location:     location,
		Properties:   make(map[string]interface{}),
		Tags:         make(map[string]string),
		CreatedAt:    now,
		UpdatedAt:    now,
		APIVersion:   "2024-01-01",
	}
}

// Clone creates a deep copy of the resource.
func (r *MockResource) Clone() *MockResource {
	clone := &MockResource{
		ResourceID:   r.ResourceID,
		ResourceType: r.ResourceType,
		Name:         r.Name,
		Location:     r.Location,
		Properties:   make(map[string]interface{}),
		Tags:         make(map[string]string),
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    time.Now(),
		APIVersion:   r.APIVersion,
	}
	for k, v := range r.Properties {
		clone.Properties[k] = v
	}
	for k, v := range r.Tags {
		clone.Tags[k] = v
	}
	return clone
}

// MockDeployment represents a mock ARM deployment.
type MockDeployment struct {
	Name              string
	SubscriptionID    string
	ResourceGroup     *string
	ManagementGroupID *string
	Location          string
	Template          map[string]interface{}
	Parameters        map[string]interface{}
	Mode              string
	ProvisioningState DeploymentProvisioningState
	CorrelationID     string
	Timestamp         time.Time
	Error             *DeploymentError
	Outputs           map[string]interface{}
}

// DeploymentError represents a deployment error.
type DeploymentError struct {
	Code    string
	Message string
	Details []DeploymentError
}

// ID returns the deployment resource ID.
func (d *MockDeployment) ID() string {
	if d.ResourceGroup != nil {
		return pathSubscriptions + d.SubscriptionID +
			pathResourceGroups + *d.ResourceGroup +
			pathDeployments + d.Name
	}
	if d.ManagementGroupID != nil {
		return "/providers/Microsoft.Management/managementGroups/" + *d.ManagementGroupID +
			pathDeployments + d.Name
	}
	return pathSubscriptions + d.SubscriptionID +
		pathDeployments + d.Name
}

// MockWhatIfChange represents a single change in WhatIf result.
type MockWhatIfChange struct {
	ResourceID string
	ChangeType WhatIfChangeType
	Before     map[string]interface{}
	After      map[string]interface{}
	Delta      []PropertyChange
}

// PropertyChange represents a property-level change.
type PropertyChange struct {
	Path   string
	Before interface{}
	After  interface{}
}

// MockWhatIfResult represents the result of a WhatIf operation.
type MockWhatIfResult struct {
	Status  string
	Changes []MockWhatIfChange
	Error   *DeploymentError
}

// HasChanges returns true if there are non-trivial changes.
func (r *MockWhatIfResult) HasChanges() bool {
	for _, c := range r.Changes {
		if c.ChangeType != WhatIfChangeNoChange && c.ChangeType != WhatIfChangeIgnore {
			return true
		}
	}
	return false
}

// MockResourceState provides in-memory Azure resource state management.
// Thread-safe.
type MockResourceState struct {
	mu sync.RWMutex

	resources         map[string]*MockResource
	deployments       map[string]*MockDeployment
	deploymentHistory []*MockDeployment
}

// NewMockResourceState creates a new empty resource state.
func NewMockResourceState() *MockResourceState {
	return &MockResourceState{
		resources:         make(map[string]*MockResource),
		deployments:       make(map[string]*MockDeployment),
		deploymentHistory: make([]*MockDeployment, 0),
	}
}

// ResourceCount returns the current resource count.
func (s *MockResourceState) ResourceCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.resources)
}

// DeploymentCount returns the current deployment count.
func (s *MockResourceState) DeploymentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.deployments)
}

// GetResource returns a resource by ID.
func (s *MockResourceState) GetResource(resourceID string) *MockResource {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.resources[resourceID]; ok {
		return r.Clone()
	}
	return nil
}

// ListResources returns resources matching the optional filters.
func (s *MockResourceState) ListResources(resourceType, resourceGroup *string) []*MockResource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*MockResource, 0)
	for _, r := range s.resources {
		if resourceType != nil && r.ResourceType != *resourceType {
			continue
		}
		if resourceGroup != nil {
			expected := pathResourceGroups + *resourceGroup + "/"
			if !contains(r.ResourceID, expected) {
				continue
			}
		}
		results = append(results, r.Clone())
	}
	return results
}

// PutResource creates or updates a resource.
func (s *MockResourceState) PutResource(resource *MockResource) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.resources[resource.ResourceID]; !exists {
		if len(s.resources) >= MaxResources {
			return ErrResourceLimitExceeded
		}
	}

	s.resources[resource.ResourceID] = resource.Clone()
	return nil
}

// DeleteResource removes a resource by ID.
func (s *MockResourceState) DeleteResource(resourceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.resources[resourceID]; exists {
		delete(s.resources, resourceID)
		return true
	}
	return false
}

// GetDeployment returns a deployment by name.
func (s *MockResourceState) GetDeployment(name string) *MockDeployment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deployments[name]
}

// CreateDeployment creates a new deployment.
func (s *MockResourceState) CreateDeployment(deployment *MockDeployment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.deployments) >= MaxDeployments {
		return ErrDeploymentLimitExceeded
	}

	s.deployments[deployment.Name] = deployment
	s.deploymentHistory = append(s.deploymentHistory, deployment)
	return nil
}

// UpdateDeploymentState updates deployment provisioning state.
func (s *MockResourceState) UpdateDeploymentState(
	name string,
	state DeploymentProvisioningState,
	err *DeploymentError,
	outputs map[string]interface{},
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	deployment, exists := s.deployments[name]
	if !exists {
		return ErrDeploymentNotFound
	}

	deployment.ProvisioningState = state
	if err != nil {
		deployment.Error = err
	}
	if outputs != nil {
		deployment.Outputs = outputs
	}
	return nil
}

// GetDeploymentHistory returns all deployments in execution order.
func (s *MockResourceState) GetDeploymentHistory() []*MockDeployment {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*MockDeployment, len(s.deploymentHistory))
	copy(result, s.deploymentHistory)
	return result
}

// ComputeWhatIf computes WhatIf result for a template deployment.
func (s *MockResourceState) ComputeWhatIf(
	template map[string]interface{},
	subscriptionID string,
	resourceGroup *string,
	managementGroupID *string,
) *MockWhatIfResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := &MockWhatIfResult{
		Status:  "Succeeded",
		Changes: make([]MockWhatIfChange, 0),
	}

	// Extract resources from template
	resources, ok := template["resources"].([]interface{})
	if !ok {
		return result
	}

	for _, res := range resources {
		resourceDef, ok := res.(map[string]interface{})
		if !ok {
			continue
		}

		resourceType, _ := resourceDef["type"].(string)
		resourceName, _ := resourceDef["name"].(string)
		location, _ := resourceDef["location"].(string)

		// Construct resource ID based on scope
		var resourceID string
		if managementGroupID != nil {
			resourceID = "/providers/Microsoft.Management/managementGroups/" + *managementGroupID +
				pathProviders + resourceType + "/" + resourceName
		} else if resourceGroup != nil {
			resourceID = pathSubscriptions + subscriptionID +
				pathResourceGroups + *resourceGroup +
				pathProviders + resourceType + "/" + resourceName
		} else {
			resourceID = pathSubscriptions + subscriptionID +
				pathProviders + resourceType + "/" + resourceName
		}

		// Check if resource exists
		existing := s.resources[resourceID]

		if existing == nil {
			// New resource - CREATE
			result.Changes = append(result.Changes, MockWhatIfChange{
				ResourceID: resourceID,
				ChangeType: WhatIfChangeCreate,
				Before:     nil,
				After: map[string]interface{}{
					"type":       resourceType,
					"name":       resourceName,
					"location":   location,
					"properties": resourceDef["properties"],
				},
			})
		} else {
			// Compare properties
			newProps, _ := resourceDef["properties"].(map[string]interface{})
			if !mapsEqual(newProps, existing.Properties) {
				result.Changes = append(result.Changes, MockWhatIfChange{
					ResourceID: resourceID,
					ChangeType: WhatIfChangeModify,
					Before: map[string]interface{}{
						"type":       existing.ResourceType,
						"name":       existing.Name,
						"location":   existing.Location,
						"properties": existing.Properties,
					},
					After: map[string]interface{}{
						"type":       resourceType,
						"name":       resourceName,
						"location":   location,
						"properties": newProps,
					},
				})
			} else {
				result.Changes = append(result.Changes, MockWhatIfChange{
					ResourceID: resourceID,
					ChangeType: WhatIfChangeNoChange,
				})
			}
		}
	}

	return result
}

// Clear resets all state.
func (s *MockResourceState) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resources = make(map[string]*MockResource)
	s.deployments = make(map[string]*MockDeployment)
	s.deploymentHistory = s.deploymentHistory[:0]
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// mapsEqual compares two maps for equality (shallow).
func mapsEqual(a, b map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
