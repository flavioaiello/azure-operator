// Package pause provides pause/resume functionality for operators.
//
// Features:
//  1. Pause reconciliation for maintenance
//  2. Resume with backoff
//  3. Pause status tracking
package pause

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Constants.
const (
	// DefaultPauseTimeout is the maximum pause duration before auto-resume.
	DefaultPauseTimeout = 24 * time.Hour
	// PauseFileName is the name of the pause state file.
	PauseFileName = ".pause"
)

// Errors.
var (
	ErrAlreadyPaused = errors.New("operator is already paused")
	ErrNotPaused     = errors.New("operator is not paused")
	ErrPauseExpired  = errors.New("pause has expired")
)

// PauseReason indicates why an operator was paused.
type PauseReason string

const (
	PauseReasonMaintenance     PauseReason = "maintenance"
	PauseReasonIncident        PauseReason = "incident"
	PauseReasonManual          PauseReason = "manual"
	PauseReasonDrift           PauseReason = "drift-detected"
	PauseReasonApprovalWaiting PauseReason = "approval-waiting"
)

// PauseState represents the pause state of an operator.
type PauseState struct {
	Paused    bool        `json:"paused"`
	Reason    PauseReason `json:"reason"`
	Message   string      `json:"message,omitempty"`
	PausedAt  time.Time   `json:"pausedAt"`
	PausedBy  string      `json:"pausedBy,omitempty"`
	ExpiresAt time.Time   `json:"expiresAt,omitempty"`
	ResumedAt *time.Time  `json:"resumedAt,omitempty"`
}

// Manager handles pause/resume operations.
type Manager struct {
	mu       sync.RWMutex
	stateDir string
	states   map[string]*PauseState
	timeout  time.Duration
}

// NewManager creates a new pause manager.
func NewManager(stateDir string) *Manager {
	return &Manager{
		stateDir: stateDir,
		states:   make(map[string]*PauseState),
		timeout:  DefaultPauseTimeout,
	}
}

// WithTimeout sets a custom pause timeout.
func (m *Manager) WithTimeout(timeout time.Duration) *Manager {
	m.timeout = timeout
	return m
}

// Pause pauses an operator.
func (m *Manager) Pause(operatorName string, reason PauseReason, message string, pausedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state, exists := m.states[operatorName]; exists && state.Paused {
		return ErrAlreadyPaused
	}

	now := time.Now()
	state := &PauseState{
		Paused:    true,
		Reason:    reason,
		Message:   message,
		PausedAt:  now,
		PausedBy:  pausedBy,
		ExpiresAt: now.Add(m.timeout),
	}

	m.states[operatorName] = state

	// Persist state.
	if err := m.persistState(operatorName, state); err != nil {
		return fmt.Errorf("failed to persist pause state: %w", err)
	}

	return nil
}

// PauseWithExpiry pauses an operator with a custom expiry.
func (m *Manager) PauseWithExpiry(operatorName string, reason PauseReason, message string, pausedBy string, expiry time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state, exists := m.states[operatorName]; exists && state.Paused {
		return ErrAlreadyPaused
	}

	now := time.Now()
	state := &PauseState{
		Paused:    true,
		Reason:    reason,
		Message:   message,
		PausedAt:  now,
		PausedBy:  pausedBy,
		ExpiresAt: now.Add(expiry),
	}

	m.states[operatorName] = state

	if err := m.persistState(operatorName, state); err != nil {
		return fmt.Errorf("failed to persist pause state: %w", err)
	}

	return nil
}

// Resume resumes a paused operator.
func (m *Manager) Resume(operatorName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.states[operatorName]
	if !exists || !state.Paused {
		return ErrNotPaused
	}

	now := time.Now()
	state.Paused = false
	state.ResumedAt = &now

	if err := m.persistState(operatorName, state); err != nil {
		return fmt.Errorf("failed to persist resume state: %w", err)
	}

	return nil
}

// IsPaused checks if an operator is currently paused.
func (m *Manager) IsPaused(operatorName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, exists := m.states[operatorName]
	if !exists {
		return false
	}

	if !state.Paused {
		return false
	}

	// Check if pause has expired.
	if time.Now().After(state.ExpiresAt) {
		return false
	}

	return true
}

// GetState returns the current pause state.
func (m *Manager) GetState(operatorName string) (*PauseState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, exists := m.states[operatorName]
	if !exists {
		return nil, ErrNotPaused
	}

	return state, nil
}

// ListPaused returns all paused operators.
func (m *Manager) ListPaused() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var paused []string
	now := time.Now()

	for name, state := range m.states {
		if state.Paused && now.Before(state.ExpiresAt) {
			paused = append(paused, name)
		}
	}

	return paused
}

// CleanupExpired removes expired pause states.
func (m *Manager) CleanupExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	count := 0

	for name, state := range m.states {
		if state.Paused && now.After(state.ExpiresAt) {
			state.Paused = false
			resumedAt := now
			state.ResumedAt = &resumedAt
			count++

			_ = m.persistState(name, state) //nolint:errcheck // Best-effort persistence in cleanup loop
		}
	}

	return count
}

// LoadStates loads pause states from disk.
func (m *Manager) LoadStates(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entries, err := os.ReadDir(m.stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read state directory: %w", err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if entry.IsDir() {
			pauseFile := filepath.Join(m.stateDir, entry.Name(), PauseFileName)
			data, err := os.ReadFile(pauseFile)
			if err != nil {
				continue // No pause file.
			}

			state := &PauseState{}
			if err := json.Unmarshal(data, state); err != nil {
				continue // Invalid file.
			}

			m.states[entry.Name()] = state
		}
	}

	return nil
}

// persistState saves pause state to disk.
func (m *Manager) persistState(operatorName string, state *PauseState) error {
	dir := filepath.Join(m.stateDir, operatorName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	pauseFile := filepath.Join(dir, PauseFileName)
	return os.WriteFile(pauseFile, data, 0o644)
}

// ShouldReconcile returns true if the operator should reconcile.
func (m *Manager) ShouldReconcile(operatorName string) (bool, *PauseState) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, exists := m.states[operatorName]
	if !exists {
		return true, nil
	}

	if !state.Paused {
		return true, state
	}

	// Check expiry.
	if time.Now().After(state.ExpiresAt) {
		return true, state
	}

	return false, state
}
