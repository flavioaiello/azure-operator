package testutil

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Graph query errors.
var (
	ErrGraphQueryFailed = errors.New("graph query failed")
)

// MockGraphChange represents a mock change event for testing.
type MockGraphChange struct {
	ResourceID string
	ChangeType string
	ChangedBy  string
	ClientType string
	Timestamp  time.Time
	Changes    map[string]interface{}
}

// MockGraphResource represents a mock resource for testing.
type MockGraphResource struct {
	ResourceID     string
	Name           string
	Type           string
	Location       string
	ResourceGroup  string
	SubscriptionID string
	Tags           map[string]string
}

// MockGraphClient provides a mock Resource Graph client for testing.
// Thread-safe.
type MockGraphClient struct {
	mu sync.Mutex

	changes     []MockGraphChange
	resources   []MockGraphResource
	queryCount  int
	shouldFail  bool
	failMessage string
}

// NewMockGraphClient creates a new mock graph client.
func NewMockGraphClient() *MockGraphClient {
	return &MockGraphClient{
		changes:     make([]MockGraphChange, 0),
		resources:   make([]MockGraphResource, 0),
		failMessage: "mock failure",
	}
}

// AddChange adds a mock change event.
func (m *MockGraphClient) AddChange(change MockGraphChange) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changes = append(m.changes, change)
}

// AddResource adds a mock resource.
func (m *MockGraphClient) AddResource(resource MockGraphResource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resources = append(m.resources, resource)
}

// SetShouldFail configures the mock to fail on next query.
func (m *MockGraphClient) SetShouldFail(shouldFail bool, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = shouldFail
	if message != "" {
		m.failMessage = message
	}
}

// QueryCount returns the number of queries executed.
func (m *MockGraphClient) QueryCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.queryCount
}

// Clear resets all mock state.
func (m *MockGraphClient) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changes = m.changes[:0]
	m.resources = m.resources[:0]
	m.queryCount = 0
	m.shouldFail = false
}

// QueryResources executes a mock resource query.
func (m *MockGraphClient) QueryResources(ctx context.Context, _ string, subscriptions []string) ([]map[string]interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.queryCount++

	// Check cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Check if configured to fail
	if m.shouldFail {
		return nil, errors.New(m.failMessage)
	}

	// Filter resources by subscription if provided
	results := make([]map[string]interface{}, 0)
	for _, r := range m.resources {
		if len(subscriptions) > 0 && !containsString(subscriptions, r.SubscriptionID) {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":             r.ResourceID,
			"name":           r.Name,
			"type":           r.Type,
			"location":       r.Location,
			"resourceGroup":  r.ResourceGroup,
			"subscriptionId": r.SubscriptionID,
			"tags":           r.Tags,
		})
	}

	return results, nil
}

// QueryChanges executes a mock resource changes query.
func (m *MockGraphClient) QueryChanges(ctx context.Context, resourceIDs []string, startTime, endTime time.Time) ([]MockGraphChange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.queryCount++

	// Check cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Check if configured to fail
	if m.shouldFail {
		return nil, errors.New(m.failMessage)
	}

	// Filter changes
	results := make([]MockGraphChange, 0)
	for _, c := range m.changes {
		// Filter by resource ID if provided
		if len(resourceIDs) > 0 && !containsString(resourceIDs, c.ResourceID) {
			continue
		}
		// Filter by time range
		if c.Timestamp.Before(startTime) || c.Timestamp.After(endTime) {
			continue
		}
		results = append(results, c)
	}

	return results, nil
}

// containsString checks if slice contains string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
