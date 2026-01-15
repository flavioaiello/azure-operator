package provenance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test constants to avoid literal duplication.
const (
	testGitRepo        = "github.com/org/repo"
	testSpecPath       = "specs/test-spec.yaml"
	testSubscriptionID = "00000000-0000-0000-0000-000000000001"
)

func TestNewLogger(t *testing.T) {
	zapLogger, _ := zap.NewDevelopment() //nolint:errcheck // Test setup
	logger := NewLogger(zapLogger)

	assert.NotNil(t, logger)
	assert.NotNil(t, logger.log)
}

func TestCreateRecord(t *testing.T) {
	zapLogger, _ := zap.NewDevelopment() //nolint:errcheck // Test setup
	logger := NewLogger(zapLogger)

	// Set up test environment
	t.Setenv("GIT_COMMIT_SHA", "abc123")
	t.Setenv("GIT_BRANCH", "main")
	t.Setenv("GIT_REPO", testGitRepo)
	t.Setenv("USER", "testuser")

	record := logger.CreateRecord(testSubscriptionID, testSpecPath, ReconcileAction)

	assert.Equal(t, "abc123", record.GitSHA)
	assert.Equal(t, "main", record.GitBranch)
	assert.Equal(t, testGitRepo, record.GitRepo)
	assert.Equal(t, ReconcileAction, record.Action)
	assert.Equal(t, testSubscriptionID, record.Scope)
	assert.Equal(t, testSpecPath, record.SpecPath)
	assert.Contains(t, record.Operator, "testuser")
	assert.NotNil(t, record.Changes)
}

func TestRecordToJSON(t *testing.T) {
	record := Record{
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Action:    DeployAction,
		Scope:     testSubscriptionID,
		SpecPath:  testSpecPath,
		GitSHA:    "abc123",
		GitBranch: "main",
		GitRepo:   testGitRepo,
		Operator:  "testuser@testhost",
		Changes: &ChangeSummary{
			Created:  2,
			Modified: 1,
			Deleted:  0,
			NoChange: 5,
			Ignored:  1,
		},
	}

	jsonStr, err := record.ToJSON()
	require.NoError(t, err)

	assert.Contains(t, jsonStr, `"action":"deploy"`)
	assert.Contains(t, jsonStr, `"scope":"`+testSubscriptionID+`"`)
	assert.Contains(t, jsonStr, `"git_sha":"abc123"`)
}

func TestChangeSummaryTotalSignificant(t *testing.T) {
	summary := ChangeSummary{
		Created:  2,
		Modified: 3,
		Deleted:  1,
		NoChange: 10,
		Ignored:  5,
	}

	assert.Equal(t, 6, summary.TotalSignificant())
}

func TestChangeSummaryIsEmpty(t *testing.T) {
	empty := ChangeSummary{}
	assert.True(t, empty.IsEmpty())

	withChanges := ChangeSummary{Created: 1}
	assert.False(t, withChanges.IsEmpty())

	onlyNoChange := ChangeSummary{NoChange: 5}
	assert.False(t, onlyNoChange.IsEmpty())
}

func TestLogProvenance(t *testing.T) {
	t.Helper()
	zapLogger, _ := zap.NewDevelopment() //nolint:errcheck // Test setup
	logger := NewLogger(zapLogger)

	record := Record{
		Timestamp: time.Now(),
		Action:    WhatIfAction,
		Scope:     testSubscriptionID,
		SpecPath:  testSpecPath,
		GitSHA:    "abc123",
		Changes: &ChangeSummary{
			Created:  1,
			Modified: 2,
		},
	}

	// Should not panic
	logger.LogProvenance(record)
}

func TestLogChangeDetail(t *testing.T) {
	t.Helper()
	zapLogger, _ := zap.NewDevelopment() //nolint:errcheck // Test setup
	logger := NewLogger(zapLogger)

	record := Record{
		Timestamp: time.Now(),
		Action:    DeployAction,
		Scope:     testSubscriptionID,
		GitSHA:    "abc123",
	}

	// Should not panic
	logger.LogChangeDetail(record, "Microsoft.Network/virtualNetworks", "hub-vnet", "Create", nil, map[string]interface{}{
		"location": "eastus",
	})
}

func TestActionString(t *testing.T) {
	assert.Equal(t, "reconcile", string(ReconcileAction))
	assert.Equal(t, "whatif", string(WhatIfAction))
	assert.Equal(t, "deploy", string(DeployAction))
	assert.Equal(t, "rollback", string(RollbackAction))
}

func TestRecordEmptyChanges(t *testing.T) {
	record := Record{
		Timestamp: time.Now(),
		Action:    WhatIfAction,
		Scope:     testSubscriptionID,
	}

	jsonStr, err := record.ToJSON()
	require.NoError(t, err)

	// Changes is nil and omitempty, so it should NOT appear in JSON
	assert.NotContains(t, jsonStr, `"changes"`)
}
