package deploy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/flavioaiello/azure-operator/pkg/guardrails"
)

func TestConstants(t *testing.T) {
	assert.Equal(t, 30*time.Minute, DefaultDeploymentTimeout)
	assert.Equal(t, 4, DeploymentNameRandomBytes)
	assert.Equal(t, 64, MaxDeploymentNameLength)
	assert.Equal(t, 5*time.Second, PollingInterval)
}

func TestDeploymentModes(t *testing.T) {
	assert.Equal(t, DeploymentMode("Incremental"), ModeIncremental)
	assert.Equal(t, DeploymentMode("Complete"), ModeComplete)
}

func TestDeploymentResultSucceeded(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		succeeded bool
	}{
		{"succeeded", "Succeeded", true},
		{"failed", "Failed", false},
		{"pending", "Pending", false},
		{"dry run", "DryRun", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &DeploymentResult{Status: tt.status}
			assert.Equal(t, tt.succeeded, r.Succeeded())
		})
	}
}

func TestGenerateDeploymentName(t *testing.T) {
	name1 := generateDeploymentName("connectivity")
	name2 := generateDeploymentName("connectivity")

	assert.NotEqual(t, name1, name2)
	assert.Contains(t, name1, "connectivity")
	assert.LessOrEqual(t, len(name1), MaxDeploymentNameLength)
}

func TestGenerateDeploymentNameLongDomain(t *testing.T) {
	longDomain := "this-is-a-very-long-domain-name-that-exceeds-limits"
	name := generateDeploymentName(longDomain)

	assert.LessOrEqual(t, len(name), MaxDeploymentNameLength)
}

func TestFormatViolationsEmpty(t *testing.T) {
	result := formatViolations(nil)
	assert.Empty(t, result)

	result = formatViolations([]guardrails.Violation{})
	assert.Empty(t, result)
}

func TestFormatViolationsMultiple(t *testing.T) {
	violations := []guardrails.Violation{
		{Type: guardrails.ViolationTooManyDeletes, Message: "Too many deletes"},
		{Type: guardrails.ViolationBlastRadius, Message: "Blast radius exceeded"},
	}

	result := formatViolations(violations)
	assert.Contains(t, result, "2 guardrail violation(s)")
	assert.Contains(t, result, "Too many deletes")
	assert.Contains(t, result, "Blast radius exceeded")
}

func TestSafeString(t *testing.T) {
	assert.Equal(t, "", safeString(nil))

	s := "test"
	assert.Equal(t, "test", safeString(&s))
}

func TestErrors(t *testing.T) {
	assert.NotEqual(t, ErrDeploymentFailed, ErrDeploymentTimeout)
	assert.NotEqual(t, ErrGuardrailsFailed, ErrApprovalRequired)
	assert.NotEqual(t, ErrApprovalPending, ErrNoChangesDetected)
}
