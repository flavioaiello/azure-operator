package pause

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	m := NewManager("/tmp/pause-test")
	assert.NotNil(t, m)
	assert.Equal(t, DefaultPauseTimeout, m.timeout)
}

func TestWithTimeout(t *testing.T) {
	m := NewManager("/tmp/pause-test").WithTimeout(1 * time.Hour)
	assert.Equal(t, 1*time.Hour, m.timeout)
}

func TestPauseAndResume(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	// Pause.
	err := m.Pause("operator1", PauseReasonMaintenance, "Scheduled maintenance", "admin")
	require.NoError(t, err)

	// Check paused.
	assert.True(t, m.IsPaused("operator1"))

	// Get state.
	state, err := m.GetState("operator1")
	require.NoError(t, err)
	assert.True(t, state.Paused)
	assert.Equal(t, PauseReasonMaintenance, state.Reason)
	assert.Equal(t, "admin", state.PausedBy)

	// Resume.
	err = m.Resume("operator1")
	require.NoError(t, err)

	// Check not paused.
	assert.False(t, m.IsPaused("operator1"))
}

func TestPauseAlreadyPaused(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	_ = m.Pause("operator1", PauseReasonManual, "", "admin") //nolint:errcheck // Test setup
	err := m.Pause("operator1", PauseReasonManual, "", "admin")

	assert.ErrorIs(t, err, ErrAlreadyPaused)
}

func TestResumeNotPaused(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	err := m.Resume("operator1")
	assert.ErrorIs(t, err, ErrNotPaused)
}

func TestPauseWithExpiry(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	err := m.PauseWithExpiry("operator1", PauseReasonIncident, "Incident response", "oncall", 2*time.Hour)
	require.NoError(t, err)

	state, err := m.GetState("operator1")
	require.NoError(t, err)
	assert.True(t, state.ExpiresAt.After(time.Now().Add(1*time.Hour)))
}

func TestPauseExpiry(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	// Pause with very short expiry.
	err := m.PauseWithExpiry("operator1", PauseReasonManual, "", "admin", 1*time.Millisecond)
	require.NoError(t, err)

	// Wait for expiry.
	time.Sleep(10 * time.Millisecond)

	// Should no longer be paused.
	assert.False(t, m.IsPaused("operator1"))
}

func TestListPaused(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	_ = m.Pause("operator1", PauseReasonManual, "", "admin")      //nolint:errcheck // Test setup
	_ = m.Pause("operator2", PauseReasonMaintenance, "", "admin") //nolint:errcheck // Test setup

	paused := m.ListPaused()
	assert.Len(t, paused, 2)
	assert.Contains(t, paused, "operator1")
	assert.Contains(t, paused, "operator2")
}

func TestCleanupExpired(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	// Pause with short expiry.
	_ = m.PauseWithExpiry("operator1", PauseReasonManual, "", "admin", 1*time.Millisecond) //nolint:errcheck // Test setup
	_ = m.Pause("operator2", PauseReasonManual, "", "admin")                               //nolint:errcheck // Test setup

	time.Sleep(10 * time.Millisecond)

	count := m.CleanupExpired()
	assert.Equal(t, 1, count)

	// operator1 should be auto-resumed.
	state, _ := m.GetState("operator1")
	assert.False(t, state.Paused)
	assert.NotNil(t, state.ResumedAt)
}

func TestShouldReconcile(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	// Not paused.
	should, state := m.ShouldReconcile("operator1")
	assert.True(t, should)
	assert.Nil(t, state)

	// Pause it.
	_ = m.Pause("operator1", PauseReasonManual, "", "admin")

	should, state = m.ShouldReconcile("operator1")
	assert.False(t, should)
	assert.NotNil(t, state)

	// Resume.
	_ = m.Resume("operator1")

	should, state = m.ShouldReconcile("operator1")
	assert.True(t, should)
	assert.NotNil(t, state)
}

func TestLoadStates(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	// Create initial state.
	_ = m.Pause("operator1", PauseReasonManual, "test", "admin")

	// Create new manager and load.
	m2 := NewManager(dir)
	err := m2.LoadStates(context.Background())
	require.NoError(t, err)

	// State should be loaded.
	assert.True(t, m2.IsPaused("operator1"))
}

func TestPersistState(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)

	_ = m.Pause("operator1", PauseReasonMaintenance, "test", "admin")

	// Check file exists.
	pauseFile := filepath.Join(dir, "operator1", PauseFileName)
	_, err := os.Stat(pauseFile)
	assert.NoError(t, err)
}

func TestPauseReasons(t *testing.T) {
	assert.Equal(t, PauseReason("maintenance"), PauseReasonMaintenance)
	assert.Equal(t, PauseReason("incident"), PauseReasonIncident)
	assert.Equal(t, PauseReason("manual"), PauseReasonManual)
	assert.Equal(t, PauseReason("drift-detected"), PauseReasonDrift)
	assert.Equal(t, PauseReason("approval-waiting"), PauseReasonApprovalWaiting)
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 24*time.Hour, DefaultPauseTimeout)
	assert.Equal(t, ".pause", PauseFileName)
}

func TestErrors(t *testing.T) {
	assert.NotNil(t, ErrAlreadyPaused)
	assert.NotNil(t, ErrNotPaused)
	assert.NotNil(t, ErrPauseExpired)
}
