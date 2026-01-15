package reconciler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
)

func TestResultDuration(t *testing.T) {
	start := time.Now()
	end := start.Add(5 * time.Second)

	result := &Result{
		StartTime: start,
		EndTime:   end,
	}

	assert.Equal(t, 5*time.Second, result.Duration())
}

func TestResultDurationZeroEndTime(t *testing.T) {
	result := &Result{
		StartTime: time.Now(),
	}

	assert.Equal(t, time.Duration(0), result.Duration())
}

func TestResultSuccess(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		success bool
	}{
		{"no error", nil, true},
		{"with error", ErrSpecLoad, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{Error: tt.err}
			assert.Equal(t, tt.success, result.Success())
		})
	}
}

func TestReconcilerCircuitBreaker(t *testing.T) {
	logger := zap.NewNop()
	r := &Reconciler{
		config: &config.Config{
			Domain: "test",
		},
		logger: logger,
	}

	// Initially circuit should be closed.
	assert.False(t, r.isCircuitOpen())

	// Accumulate failures.
	for i := 0; i < MaxConsecutiveFailures-1; i++ {
		r.handleFailure(ErrSpecLoad)
		assert.False(t, r.isCircuitOpen(), "circuit should not open before max failures")
	}

	// One more failure should open the circuit.
	r.handleFailure(ErrSpecLoad)
	assert.True(t, r.isCircuitOpen(), "circuit should be open after max failures")

	// Reset should close the circuit.
	r.resetCircuitBreaker()
	assert.False(t, r.isCircuitOpen(), "circuit should be closed after reset")
}

func TestReconcilerCircuitBreakerTimeout(t *testing.T) {
	logger := zap.NewNop()
	r := &Reconciler{
		config: &config.Config{
			Domain: "test",
		},
		logger: logger,
	}

	// Open the circuit.
	for i := 0; i < MaxConsecutiveFailures; i++ {
		r.handleFailure(ErrSpecLoad)
	}
	assert.True(t, r.isCircuitOpen())

	// Simulate timeout by setting open_until to the past.
	r.mu.Lock()
	r.circuitOpenUntil = time.Now().Add(-1 * time.Second)
	r.mu.Unlock()

	// Circuit should now be closed (timeout expired).
	assert.False(t, r.isCircuitOpen())
}

func TestConstants(t *testing.T) {
	// Verify constants are reasonable.
	assert.Equal(t, 5, MaxConsecutiveFailures)
	assert.Equal(t, 5*time.Minute, CircuitBreakerResetPeriod)
}
