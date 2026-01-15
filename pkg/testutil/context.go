package testutil

import (
	"sync"
)

// MockContext coordinates all Azure API mocks for integration tests.
// Thread-safe.
type MockContext struct {
	mu sync.Mutex

	credential     *MockCredential
	state          *MockResourceState
	resourceClient *MockResourceClient
	graphClient    *MockGraphClient

	// Configuration
	clientID *string
}

// MockContextOption configures a MockContext.
type MockContextOption func(*MockContext)

// WithClientID sets the managed identity client ID.
func WithClientID(clientID string) MockContextOption {
	return func(c *MockContext) {
		c.clientID = &clientID
	}
}

// WithInitialResources pre-populates resources in state.
func WithInitialResources(resources []*MockResource) MockContextOption {
	return func(c *MockContext) {
		for _, r := range resources {
			_ = c.state.PutResource(r)
		}
	}
}

// WithFailAuth configures authentication to fail.
func WithFailAuth(message string) MockContextOption {
	return func(c *MockContext) {
		c.credential.SetFailure(true, message)
	}
}

// WithFailDeployment configures deployments to fail.
func WithFailDeployment(message string) MockContextOption {
	return func(c *MockContext) {
		c.resourceClient.SetDeploymentFailure(true, message)
	}
}

// NewMockContext creates a new mock context with all mocks initialized.
func NewMockContext(opts ...MockContextOption) *MockContext {
	ctx := &MockContext{
		state: NewMockResourceState(),
	}

	// Apply options first to get clientID
	for _, opt := range opts {
		opt(ctx)
	}

	// Initialize mocks
	ctx.credential = NewMockCredential(ctx.clientID)
	ctx.resourceClient = NewMockResourceClient(ctx.state)
	ctx.graphClient = NewMockGraphClient()

	// Re-apply options that configure mocks
	for _, opt := range opts {
		opt(ctx)
	}

	return ctx
}

// Credential returns the mock credential.
func (c *MockContext) Credential() *MockCredential {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.credential
}

// State returns the mock resource state.
func (c *MockContext) State() *MockResourceState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// ResourceClient returns the mock resource client.
func (c *MockContext) ResourceClient() *MockResourceClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resourceClient
}

// GraphClient returns the mock graph client.
func (c *MockContext) GraphClient() *MockGraphClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.graphClient
}

// DeploymentCount returns the number of deployments executed.
func (c *MockContext) DeploymentCount() int {
	return c.state.DeploymentCount()
}

// ResourceCount returns the number of resources in state.
func (c *MockContext) ResourceCount() int {
	return c.state.ResourceCount()
}

// GetDeployments returns all deployments in execution order.
func (c *MockContext) GetDeployments() []*MockDeployment {
	return c.state.GetDeploymentHistory()
}

// Clear resets all mock state.
func (c *MockContext) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.credential.Reset()
	c.state.Clear()
	c.resourceClient.Clear()
	c.graphClient.Clear()
}

// Close releases all resources (no-op for mocks, but follows pattern).
func (c *MockContext) Close() {
	c.Clear()
}
