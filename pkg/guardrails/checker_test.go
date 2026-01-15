package guardrails

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/whatif"
)

// Test constants to avoid literal duplication.
const testDomain = "contoso.com"

func TestConstants(t *testing.T) {
	assert.Equal(t, 5, MaxDeletesPerDeployment)
	assert.Equal(t, 50, MaxAffectedResourcesPerDeployment)
	assert.Equal(t, 1*time.Hour, DeploymentRateLimitWindow)
	assert.Equal(t, 10, MaxDeploymentsPerWindow)
	assert.Equal(t, 30*time.Second, DefaultCooldownPeriod)
}

func TestViolationTypes(t *testing.T) {
	assert.Equal(t, ViolationType("too_many_deletes"), ViolationTooManyDeletes)
	assert.Equal(t, ViolationType("blast_radius_exceeded"), ViolationBlastRadius)
	assert.Equal(t, ViolationType("rate_limit_exceeded"), ViolationRateLimit)
	assert.Equal(t, ViolationType("protected_resource"), ViolationProtectedResource)
	assert.Equal(t, ViolationType("cooldown_active"), ViolationCooldown)
}

func TestCheckerCheckNoChanges(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	result := checker.Check(context.Background(), &whatif.Result{Changes: []whatif.Change{}})
	assert.True(t, result.Passed)
	assert.Empty(t, result.Violations)
}

func TestCheckerCheckNilResult(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	result := checker.Check(context.Background(), nil)
	assert.True(t, result.Passed)
}

func TestCheckerTooManyDeletes(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	changes := make([]whatif.Change, 0)
	for i := 0; i < MaxDeletesPerDeployment+2; i++ {
		changes = append(changes, whatif.Change{
			ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
			ChangeType: whatif.ChangeTypeDelete,
		})
	}

	result := checker.Check(context.Background(), &whatif.Result{Changes: changes})
	assert.False(t, result.Passed)

	found := false
	for _, v := range result.Violations {
		if v.Type == ViolationTooManyDeletes {
			found = true
			assert.Equal(t, MaxDeletesPerDeployment, v.Limit)
		}
	}
	assert.True(t, found)
}

func TestCheckerBlastRadiusExceeded(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	changes := make([]whatif.Change, 0)
	for i := 0; i < MaxAffectedResourcesPerDeployment+5; i++ {
		changes = append(changes, whatif.Change{
			ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
			ChangeType: whatif.ChangeTypeCreate,
		})
	}

	result := checker.Check(context.Background(), &whatif.Result{Changes: changes})
	assert.False(t, result.Passed)

	found := false
	for _, v := range result.Violations {
		if v.Type == ViolationBlastRadius {
			found = true
		}
	}
	assert.True(t, found)
}

func TestCheckerProtectedResourceDelete(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	changes := []whatif.Change{
		{
			ResourceID: "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/ra-456",
			ChangeType: whatif.ChangeTypeDelete,
		},
	}

	result := checker.Check(context.Background(), &whatif.Result{Changes: changes})
	assert.False(t, result.Passed)

	found := false
	for _, v := range result.Violations {
		if v.Type == ViolationProtectedResource {
			found = true
		}
	}
	assert.True(t, found)
}

func TestCheckerProtectedResourceModifyAllowed(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	changes := []whatif.Change{
		{
			ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-test",
			ChangeType: whatif.ChangeTypeModify,
		},
	}

	result := checker.Check(context.Background(), &whatif.Result{Changes: changes})
	assert.True(t, result.Passed)
}

func TestCheckerRateLimit(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	for i := 0; i < MaxDeploymentsPerWindow; i++ {
		checker.RecordDeployment()
	}

	result := checker.Check(context.Background(), &whatif.Result{Changes: []whatif.Change{
		{ResourceID: "/sub/rg/res", ChangeType: whatif.ChangeTypeCreate},
	}})
	assert.False(t, result.Passed)

	found := false
	for _, v := range result.Violations {
		if v.Type == ViolationRateLimit {
			found = true
		}
	}
	assert.True(t, found)
}

func TestCheckerResetRateLimit(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}
	checker := NewChecker(cfg, logger)

	for i := 0; i < 5; i++ {
		checker.RecordDeployment()
	}

	checker.ResetRateLimit()

	result := checker.Check(context.Background(), &whatif.Result{Changes: []whatif.Change{
		{ResourceID: "/sub/rg/res", ChangeType: whatif.ChangeTypeCreate},
	}})
	assert.True(t, result.Passed)
}

func TestDefaultProtectedPatterns(t *testing.T) {
	patterns := defaultProtectedPatterns()
	assert.GreaterOrEqual(t, len(patterns), 4)

	for _, p := range patterns {
		assert.NotNil(t, p.Pattern)
		assert.NotEmpty(t, p.Description)
	}
}
