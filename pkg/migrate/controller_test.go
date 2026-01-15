package migrate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewController(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeParallel)

	assert.NotNil(t, c)
	assert.Equal(t, ModeParallel, c.mode)
}

func TestSetAndGetOperatorMode(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeParallel)

	// Default mode.
	assert.Equal(t, ModeParallel, c.GetOperatorMode("connectivity"))

	// Override.
	c.SetOperatorMode("connectivity", ModeGoOnly)
	assert.Equal(t, ModeGoOnly, c.GetOperatorMode("connectivity"))

	// Other operators still use default.
	assert.Equal(t, ModeParallel, c.GetOperatorMode("security"))
}

func TestShouldRunPython(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeParallel)

	tests := []struct {
		mode   MigrationMode
		expect bool
	}{
		{ModeParallel, true},
		{ModeShadow, true},
		{ModeGoPrimary, false},
		{ModeGoOnly, false},
	}

	for _, tt := range tests {
		c.SetOperatorMode("test", tt.mode)
		assert.Equal(t, tt.expect, c.ShouldRunPython("test"), "mode=%s", tt.mode)
	}
}

func TestShouldRunGo(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeParallel)

	tests := []struct {
		mode   MigrationMode
		expect bool
	}{
		{ModeParallel, true},
		{ModeShadow, false},
		{ModeGoPrimary, true},
		{ModeGoOnly, true},
	}

	for _, tt := range tests {
		c.SetOperatorMode("test", tt.mode)
		assert.Equal(t, tt.expect, c.ShouldRunGo("test"), "mode=%s", tt.mode)
	}
}

func TestShouldGoDeploy(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeParallel)

	tests := []struct {
		mode   MigrationMode
		expect bool
	}{
		{ModeParallel, false},
		{ModeShadow, false},
		{ModeGoPrimary, true},
		{ModeGoOnly, true},
	}

	for _, tt := range tests {
		c.SetOperatorMode("test", tt.mode)
		assert.Equal(t, tt.expect, c.ShouldGoDeploy("test"), "mode=%s", tt.mode)
	}
}

func TestSaveAndLoadResult(t *testing.T) {
	dir := t.TempDir()
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, dir, ModeParallel)
	ctx := context.Background()

	result := &ReconcileResult{
		Implementation: ImplementationGo,
		Operator:       "connectivity",
		Domain:         "connectivity",
		Timestamp:      time.Now(),
		Duration:       5 * time.Second,
		SpecsProcessed: 10,
		DriftDetected:  true,
		ChangesApplied: 3,
	}

	// Save.
	err := c.SaveResult(ctx, result)
	require.NoError(t, err)

	// Verify file exists.
	path := filepath.Join(dir, "connectivity", "go", ResultFileName)
	_, err = os.Stat(path)
	assert.NoError(t, err)

	// Load.
	loaded, err := c.LoadResult(ctx, "connectivity", ImplementationGo)
	require.NoError(t, err)
	assert.Equal(t, result.SpecsProcessed, loaded.SpecsProcessed)
	assert.Equal(t, result.DriftDetected, loaded.DriftDetected)
}

func TestLoadResult_Missing(t *testing.T) {
	dir := t.TempDir()
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, dir, ModeParallel)
	ctx := context.Background()

	_, err := c.LoadResult(ctx, "missing", ImplementationGo)
	assert.ErrorIs(t, err, ErrMissingResult)
}

func TestCompareResults_Match(t *testing.T) {
	dir := t.TempDir()
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, dir, ModeParallel)
	ctx := context.Background()

	pythonResult := &ReconcileResult{
		Implementation: ImplementationPython,
		Operator:       "connectivity",
		Timestamp:      time.Now(),
		Duration:       5 * time.Second,
		SpecsProcessed: 10,
		DriftDetected:  true,
		ChangesApplied: 3,
	}

	goResult := &ReconcileResult{
		Implementation: ImplementationGo,
		Operator:       "connectivity",
		Timestamp:      time.Now(),
		Duration:       5 * time.Second,
		SpecsProcessed: 10,
		DriftDetected:  true,
		ChangesApplied: 3,
	}

	_ = c.SaveResult(ctx, pythonResult)
	_ = c.SaveResult(ctx, goResult)

	comparison, err := c.CompareResults(ctx, "connectivity")
	require.NoError(t, err)
	assert.True(t, comparison.Match)
	assert.Empty(t, comparison.Discrepancies)
}

func TestCompareResults_Mismatch(t *testing.T) {
	dir := t.TempDir()
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, dir, ModeParallel)
	ctx := context.Background()

	pythonResult := &ReconcileResult{
		Implementation: ImplementationPython,
		Operator:       "connectivity",
		Timestamp:      time.Now(),
		SpecsProcessed: 10,
		DriftDetected:  true,
		ChangesApplied: 3,
	}

	goResult := &ReconcileResult{
		Implementation: ImplementationGo,
		Operator:       "connectivity",
		Timestamp:      time.Now(),
		SpecsProcessed: 12,    // Different!
		DriftDetected:  false, // Different!
		ChangesApplied: 3,
	}

	_ = c.SaveResult(ctx, pythonResult)
	_ = c.SaveResult(ctx, goResult)

	comparison, err := c.CompareResults(ctx, "connectivity")
	require.NoError(t, err)
	assert.False(t, comparison.Match)
	assert.Len(t, comparison.Discrepancies, 2)
}

func TestPromoteOperator(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeShadow)

	// Start at shadow.
	c.SetOperatorMode("connectivity", ModeShadow)

	// Promote through stages.
	err := c.PromoteOperator("connectivity")
	require.NoError(t, err)
	assert.Equal(t, ModeParallel, c.GetOperatorMode("connectivity"))

	err = c.PromoteOperator("connectivity")
	require.NoError(t, err)
	assert.Equal(t, ModeGoPrimary, c.GetOperatorMode("connectivity"))

	err = c.PromoteOperator("connectivity")
	require.NoError(t, err)
	assert.Equal(t, ModeGoOnly, c.GetOperatorMode("connectivity"))

	// Can't promote beyond GoOnly.
	err = c.PromoteOperator("connectivity")
	assert.Error(t, err)
}

func TestRollbackOperator(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeGoOnly)

	c.SetOperatorMode("connectivity", ModeGoOnly)

	// Rollback through stages.
	err := c.RollbackOperator("connectivity")
	require.NoError(t, err)
	assert.Equal(t, ModeGoPrimary, c.GetOperatorMode("connectivity"))

	err = c.RollbackOperator("connectivity")
	require.NoError(t, err)
	assert.Equal(t, ModeParallel, c.GetOperatorMode("connectivity"))

	err = c.RollbackOperator("connectivity")
	require.NoError(t, err)
	assert.Equal(t, ModeShadow, c.GetOperatorMode("connectivity"))

	// Can't rollback beyond Shadow.
	err = c.RollbackOperator("connectivity")
	assert.Error(t, err)
}

func TestGetMigrationStatus(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	c := NewController(logger, "/tmp/results", ModeParallel)

	c.SetOperatorMode("connectivity", ModeGoOnly)
	c.SetOperatorMode("security", ModeShadow)

	status := c.GetMigrationStatus()
	assert.Equal(t, ModeParallel, status["default"])
	assert.Equal(t, ModeGoOnly, status["connectivity"])
	assert.Equal(t, ModeShadow, status["security"])
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 5*time.Minute, DefaultComparisonTimeout)
	assert.Equal(t, "reconcile-result.json", ResultFileName)
	assert.Equal(t, 1*time.Hour, MaxResultAge)
}

func TestMigrationModes(t *testing.T) {
	assert.Equal(t, MigrationMode("parallel"), ModeParallel)
	assert.Equal(t, MigrationMode("shadow"), ModeShadow)
	assert.Equal(t, MigrationMode("go-primary"), ModeGoPrimary)
	assert.Equal(t, MigrationMode("go-only"), ModeGoOnly)
}

func TestImplementations(t *testing.T) {
	assert.Equal(t, Implementation("python"), ImplementationPython)
	assert.Equal(t, Implementation("go"), ImplementationGo)
}

func TestErrors(t *testing.T) {
	assert.NotNil(t, ErrResultMismatch)
	assert.NotNil(t, ErrMissingResult)
	assert.NotNil(t, ErrResultExpired)
	assert.NotNil(t, ErrOperatorMismatch)
}
