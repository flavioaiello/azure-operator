package testutil

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// Token validity duration.
const TokenValidityHours = 1

// Error messages.
const errMsgMockAuthFailed = "mock authentication failed"

// Errors.
var (
	ErrMockAuthFailed = errors.New(errMsgMockAuthFailed)
)

// MockAccessToken represents a fake Azure access token.
type MockAccessToken struct {
	Token     string
	ExpiresOn time.Time
}

// MockCredential provides a mock implementation of azcore.TokenCredential.
//
// Returns fake tokens without requiring Azure connectivity.
// Tracks authentication calls for test assertions.
// Thread-safe.
type MockCredential struct {
	mu sync.Mutex

	clientID       *string
	tokenCalls     []TokenCall
	tokenCounter   int
	shouldFail     bool
	failureMessage string
}

// TokenCall records a single GetToken invocation.
type TokenCall struct {
	Scopes    []string
	Timestamp time.Time
}

// NewMockCredential creates a new mock credential.
func NewMockCredential(clientID *string) *MockCredential {
	return &MockCredential{
		clientID:       clientID,
		tokenCalls:     make([]TokenCall, 0),
		failureMessage: errMsgMockAuthFailed,
	}
}

// ClientID returns the configured client ID.
func (m *MockCredential) ClientID() *string {
	return m.clientID
}

// GetTokenCallCount returns the number of GetToken calls.
func (m *MockCredential) GetTokenCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tokenCalls)
}

// GetTokenCalls returns all recorded token calls.
func (m *MockCredential) GetTokenCalls() []TokenCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]TokenCall, len(m.tokenCalls))
	copy(result, m.tokenCalls)
	return result
}

// SetFailure configures the credential to fail on next GetToken call.
func (m *MockCredential) SetFailure(shouldFail bool, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = shouldFail
	if message != "" {
		m.failureMessage = message
	}
}

// GetToken implements azcore.TokenCredential.
func (m *MockCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Record the call
	m.tokenCalls = append(m.tokenCalls, TokenCall{
		Scopes:    options.Scopes,
		Timestamp: time.Now(),
	})

	// Check for cancellation
	select {
	case <-ctx.Done():
		return azcore.AccessToken{}, ctx.Err()
	default:
	}

	// Check if configured to fail
	if m.shouldFail {
		return azcore.AccessToken{}, errors.New(m.failureMessage)
	}

	// Generate fake token
	m.tokenCounter++
	expiresOn := time.Now().Add(TokenValidityHours * time.Hour)

	return azcore.AccessToken{
		Token:     "mock-token-" + string(rune(m.tokenCounter)),
		ExpiresOn: expiresOn,
	}, nil
}

// Reset clears all recorded state.
func (m *MockCredential) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenCalls = m.tokenCalls[:0]
	m.tokenCounter = 0
	m.shouldFail = false
	m.failureMessage = "mock authentication failed"
}

// Verify interface compliance.
var _ azcore.TokenCredential = (*MockCredential)(nil)
