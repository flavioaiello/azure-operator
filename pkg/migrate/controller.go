// Package migrate provides migration utilities for Python to Go transition.
//
// Features:
//  1. Parallel run mode - run Python and Go operators side-by-side
//  2. Result comparison - compare outputs for validation
//  3. Gradual migration - operator-by-operator switchover
package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Constants.
const (
	// DefaultComparisonTimeout is the timeout for result comparison.
	DefaultComparisonTimeout = 5 * time.Minute
	// ResultFileName is the name of result files.
	ResultFileName = "reconcile-result.json"
	// MaxResultAge is the maximum age for result files.
	MaxResultAge = 1 * time.Hour
)

// Errors.
var (
	ErrResultMismatch   = errors.New("result mismatch between implementations")
	ErrMissingResult    = errors.New("missing result file")
	ErrResultExpired    = errors.New("result file is too old")
	ErrOperatorMismatch = errors.New("operator configuration mismatch")
)

// Implementation identifies which implementation produced a result.
type Implementation string

const (
	ImplementationPython Implementation = "python"
	ImplementationGo     Implementation = "go"
)

// MigrationMode controls how operators run during migration.
type MigrationMode string

const (
	// ModeParallel runs both implementations, compares results.
	ModeParallel MigrationMode = "parallel"
	// ModeShadow runs Go in shadow mode (no deployments), compares to Python.
	ModeShadow MigrationMode = "shadow"
	// ModeGoPrimary runs Go as primary, Python as shadow.
	ModeGoPrimary MigrationMode = "go-primary"
	// ModeGoOnly runs Go only (migration complete).
	ModeGoOnly MigrationMode = "go-only"
)

// ReconcileResult represents the output of a reconciliation cycle.
type ReconcileResult struct {
	Implementation Implementation  `json:"implementation"`
	Operator       string          `json:"operator"`
	Domain         string          `json:"domain"`
	Timestamp      time.Time       `json:"timestamp"`
	Duration       time.Duration   `json:"duration"`
	SpecsProcessed int             `json:"specsProcessed"`
	DriftDetected  bool            `json:"driftDetected"`
	ChangesApplied int             `json:"changesApplied"`
	Errors         []string        `json:"errors,omitempty"`
	ResourceStates []ResourceState `json:"resourceStates,omitempty"`
}

// ResourceState represents the state of a single resource.
type ResourceState struct {
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
	Status       string `json:"status"`
	ChangeType   string `json:"changeType,omitempty"`
}

// ComparisonResult represents the outcome of comparing two implementations.
type ComparisonResult struct {
	Match         bool             `json:"match"`
	PythonResult  *ReconcileResult `json:"pythonResult,omitempty"`
	GoResult      *ReconcileResult `json:"goResult,omitempty"`
	Discrepancies []Discrepancy    `json:"discrepancies,omitempty"`
	Timestamp     time.Time        `json:"timestamp"`
}

// Discrepancy describes a difference between implementations.
type Discrepancy struct {
	Field       string `json:"field"`
	PythonValue string `json:"pythonValue"`
	GoValue     string `json:"goValue"`
	Severity    string `json:"severity"` // "error", "warning", "info"
}

// Controller manages migration between implementations.
type Controller struct {
	mu         sync.RWMutex
	logger     *zap.Logger
	mode       MigrationMode
	resultsDir string
	operators  map[string]MigrationMode // Per-operator overrides.
}

// NewController creates a new migration controller.
func NewController(logger *zap.Logger, resultsDir string, defaultMode MigrationMode) *Controller {
	return &Controller{
		logger:     logger,
		mode:       defaultMode,
		resultsDir: resultsDir,
		operators:  make(map[string]MigrationMode),
	}
}

// SetOperatorMode sets migration mode for a specific operator.
func (c *Controller) SetOperatorMode(operator string, mode MigrationMode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.operators[operator] = mode
}

// GetOperatorMode returns the migration mode for an operator.
func (c *Controller) GetOperatorMode(operator string) MigrationMode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if mode, ok := c.operators[operator]; ok {
		return mode
	}
	return c.mode
}

// ShouldRunPython returns true if Python should run.
func (c *Controller) ShouldRunPython(operator string) bool {
	mode := c.GetOperatorMode(operator)
	return mode == ModeParallel || mode == ModeShadow
}

// ShouldRunGo returns true if Go should run.
func (c *Controller) ShouldRunGo(operator string) bool {
	mode := c.GetOperatorMode(operator)
	return mode != ModeShadow // All modes except shadow run Go.
}

// ShouldGoDeploy returns true if Go should perform actual deployments.
func (c *Controller) ShouldGoDeploy(operator string) bool {
	mode := c.GetOperatorMode(operator)
	return mode == ModeGoPrimary || mode == ModeGoOnly
}

// SaveResult persists a reconciliation result.
func (c *Controller) SaveResult(ctx context.Context, result *ReconcileResult) error {
	dir := filepath.Join(c.resultsDir, result.Operator, string(result.Implementation))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	path := filepath.Join(dir, ResultFileName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}

	c.logger.Debug("Saved reconcile result",
		zap.String("operator", result.Operator),
		zap.String("implementation", string(result.Implementation)),
	)

	return nil
}

// LoadResult loads a reconciliation result.
func (c *Controller) LoadResult(ctx context.Context, operator string, impl Implementation) (*ReconcileResult, error) {
	path := filepath.Join(c.resultsDir, operator, string(impl), ResultFileName)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrMissingResult
		}
		return nil, err
	}

	// Check age.
	if time.Since(info.ModTime()) > MaxResultAge {
		return nil, ErrResultExpired
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result ReconcileResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result: %w", err)
	}

	return &result, nil
}

// CompareResults compares Python and Go results for an operator.
func (c *Controller) CompareResults(ctx context.Context, operator string) (*ComparisonResult, error) {
	pythonResult, pythonErr := c.LoadResult(ctx, operator, ImplementationPython)
	goResult, goErr := c.LoadResult(ctx, operator, ImplementationGo)

	comparison := &ComparisonResult{
		Timestamp:    time.Now(),
		PythonResult: pythonResult,
		GoResult:     goResult,
	}

	// Both missing is an error.
	if pythonErr != nil && goErr != nil {
		return comparison, fmt.Errorf("no results available: python=%v, go=%v", pythonErr, goErr)
	}

	// One missing is a discrepancy.
	if pythonErr != nil {
		comparison.Match = false
		comparison.Discrepancies = append(comparison.Discrepancies, Discrepancy{
			Field:    "result",
			GoValue:  "present",
			Severity: "error",
		})
		return comparison, nil
	}
	if goErr != nil {
		comparison.Match = false
		comparison.Discrepancies = append(comparison.Discrepancies, Discrepancy{
			Field:       "result",
			PythonValue: "present",
			Severity:    "error",
		})
		return comparison, nil
	}

	// Compare results.
	comparison.Discrepancies = c.findDiscrepancies(pythonResult, goResult)
	comparison.Match = len(comparison.Discrepancies) == 0

	return comparison, nil
}

// findDiscrepancies compares two results and returns differences.
func (c *Controller) findDiscrepancies(python, golang *ReconcileResult) []Discrepancy {
	var discrepancies []Discrepancy

	// Compare specs processed.
	if python.SpecsProcessed != golang.SpecsProcessed {
		discrepancies = append(discrepancies, Discrepancy{
			Field:       "specsProcessed",
			PythonValue: fmt.Sprintf("%d", python.SpecsProcessed),
			GoValue:     fmt.Sprintf("%d", golang.SpecsProcessed),
			Severity:    "error",
		})
	}

	// Compare drift detection.
	if python.DriftDetected != golang.DriftDetected {
		discrepancies = append(discrepancies, Discrepancy{
			Field:       "driftDetected",
			PythonValue: fmt.Sprintf("%t", python.DriftDetected),
			GoValue:     fmt.Sprintf("%t", golang.DriftDetected),
			Severity:    "error",
		})
	}

	// Compare changes applied.
	if python.ChangesApplied != golang.ChangesApplied {
		discrepancies = append(discrepancies, Discrepancy{
			Field:       "changesApplied",
			PythonValue: fmt.Sprintf("%d", python.ChangesApplied),
			GoValue:     fmt.Sprintf("%d", golang.ChangesApplied),
			Severity:    "error",
		})
	}

	// Compare error counts.
	if len(python.Errors) != len(golang.Errors) {
		discrepancies = append(discrepancies, Discrepancy{
			Field:       "errorCount",
			PythonValue: fmt.Sprintf("%d", len(python.Errors)),
			GoValue:     fmt.Sprintf("%d", len(golang.Errors)),
			Severity:    "warning",
		})
	}

	// Compare resource states count.
	if len(python.ResourceStates) != len(golang.ResourceStates) {
		discrepancies = append(discrepancies, Discrepancy{
			Field:       "resourceStateCount",
			PythonValue: fmt.Sprintf("%d", len(python.ResourceStates)),
			GoValue:     fmt.Sprintf("%d", len(golang.ResourceStates)),
			Severity:    "warning",
		})
	}

	// Compare duration (allow 20% variance).
	pythonDur := python.Duration.Seconds()
	goDur := golang.Duration.Seconds()
	if pythonDur > 0 {
		variance := (goDur - pythonDur) / pythonDur
		if variance > 0.2 || variance < -0.2 {
			discrepancies = append(discrepancies, Discrepancy{
				Field:       "duration",
				PythonValue: python.Duration.String(),
				GoValue:     golang.Duration.String(),
				Severity:    "info",
			})
		}
	}

	return discrepancies
}

// GetMigrationStatus returns the overall migration status.
func (c *Controller) GetMigrationStatus() map[string]MigrationMode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := make(map[string]MigrationMode)
	status["default"] = c.mode
	for op, mode := range c.operators {
		status[op] = mode
	}
	return status
}

// PromoteOperator advances an operator to the next migration stage.
func (c *Controller) PromoteOperator(operator string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	current, ok := c.operators[operator]
	if !ok {
		current = c.mode
	}

	var next MigrationMode
	switch current {
	case ModeShadow:
		next = ModeParallel
	case ModeParallel:
		next = ModeGoPrimary
	case ModeGoPrimary:
		next = ModeGoOnly
	case ModeGoOnly:
		return fmt.Errorf("operator %s is already fully migrated", operator)
	default:
		next = ModeShadow
	}

	c.operators[operator] = next
	c.logger.Info("Promoted operator migration stage",
		zap.String("operator", operator),
		zap.String("from", string(current)),
		zap.String("to", string(next)),
	)

	return nil
}

// RollbackOperator moves an operator back to the previous migration stage.
func (c *Controller) RollbackOperator(operator string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	current, ok := c.operators[operator]
	if !ok {
		current = c.mode
	}

	var prev MigrationMode
	switch current {
	case ModeGoOnly:
		prev = ModeGoPrimary
	case ModeGoPrimary:
		prev = ModeParallel
	case ModeParallel:
		prev = ModeShadow
	case ModeShadow:
		return fmt.Errorf("operator %s is already at initial stage", operator)
	default:
		prev = ModeShadow
	}

	c.operators[operator] = prev
	c.logger.Info("Rolled back operator migration stage",
		zap.String("operator", operator),
		zap.String("from", string(current)),
		zap.String("to", string(prev)),
	)

	return nil
}
