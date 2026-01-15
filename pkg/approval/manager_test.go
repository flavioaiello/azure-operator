package approval

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/whatif"
)

// Test constants to avoid literal duplication.
const (
	testDomain         = "test-domain"
	testApprovalDirPat = "approval-test-*"
	testResourceGroup  = "rg-test"
	testDeploymentID   = "deploy-001"
	testApproverEmail  = "admin@example.com"
)

func TestConstants(t *testing.T) {
	assert.Equal(t, 24*time.Hour, DefaultApprovalTimeout)
	assert.Equal(t, 10, MaxPendingApprovals)
	assert.Equal(t, 16, ApprovalIDLength)
}

func TestApprovalStatusValues(t *testing.T) {
	assert.Equal(t, ApprovalStatus("pending"), StatusPending)
	assert.Equal(t, ApprovalStatus("approved"), StatusApproved)
	assert.Equal(t, ApprovalStatus("rejected"), StatusRejected)
	assert.Equal(t, ApprovalStatus("expired"), StatusExpired)
}

func TestRequestIsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		expired   bool
	}{
		{"future", now.Add(1 * time.Hour), false},
		{"past", now.Add(-1 * time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Request{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expired, r.IsExpired())
		})
	}
}

func TestRequestIsPending(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		status    ApprovalStatus
		expiresAt time.Time
		pending   bool
	}{
		{"pending valid", StatusPending, now.Add(1 * time.Hour), true},
		{"pending expired", StatusPending, now.Add(-1 * time.Hour), false},
		{"approved", StatusApproved, now.Add(1 * time.Hour), false},
		{"rejected", StatusRejected, now.Add(1 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Request{Status: tt.status, ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.pending, r.IsPending())
		})
	}
}

func TestManagerCreateRequest(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}

	tmpDir, err := os.MkdirTemp("", testApprovalDirPat)
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr, err := NewManager(cfg, logger, tmpDir)
	require.NoError(t, err)

	ctx := context.Background()
	whatIfResult := &whatif.Result{
		Changes: []whatif.Change{
			{ResourceID: "/sub/rg/res1", ChangeType: whatif.ChangeTypeCreate},
			{ResourceID: "/sub/rg/res2", ChangeType: whatif.ChangeTypeModify},
		},
	}

	request, err := mgr.CreateRequest(ctx, testDeploymentID, testResourceGroup, whatIfResult)
	require.NoError(t, err)

	assert.NotEmpty(t, request.ID)
	assert.Equal(t, testDomain, request.Domain)
	assert.Equal(t, StatusPending, request.Status)
	assert.Equal(t, 2, request.ChangeSummary.TotalChanges)
	assert.Equal(t, 1, request.ChangeSummary.Creates)
	assert.Equal(t, 1, request.ChangeSummary.Modifies)
}

func TestManagerApprove(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}

	tmpDir, err := os.MkdirTemp("", testApprovalDirPat)
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr, err := NewManager(cfg, logger, tmpDir)
	require.NoError(t, err)

	ctx := context.Background()

	request, err := mgr.CreateRequest(ctx, testDeploymentID, testResourceGroup, nil)
	require.NoError(t, err)

	err = mgr.Approve(ctx, request.ID, testApproverEmail)
	require.NoError(t, err)

	retrieved, err := mgr.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusApproved, retrieved.Status)
	assert.Equal(t, testApproverEmail, retrieved.ApprovedBy)
}

func TestManagerReject(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}

	tmpDir, err := os.MkdirTemp("", testApprovalDirPat)
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr, err := NewManager(cfg, logger, tmpDir)
	require.NoError(t, err)

	ctx := context.Background()

	request, err := mgr.CreateRequest(ctx, testDeploymentID, testResourceGroup, nil)
	require.NoError(t, err)

	err = mgr.Reject(ctx, request.ID, testApproverEmail, "Not approved")
	require.NoError(t, err)

	retrieved, err := mgr.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRejected, retrieved.Status)
	assert.Equal(t, "Not approved", retrieved.RejectionReason)
}

func TestManagerApproveNotFound(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{Domain: testDomain}

	tmpDir, err := os.MkdirTemp("", testApprovalDirPat)
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	mgr, err := NewManager(cfg, logger, tmpDir)
	require.NoError(t, err)

	ctx := context.Background()
	err = mgr.Approve(ctx, "nonexistent", testApproverEmail)
	assert.ErrorIs(t, err, ErrApprovalNotFound)
}

func TestGenerateApprovalID(t *testing.T) {
	id1, err := generateApprovalID()
	require.NoError(t, err)
	assert.Len(t, id1, ApprovalIDLength*2)

	id2, err := generateApprovalID()
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2)
}

func TestBuildChangeSummary(t *testing.T) {
	result := &whatif.Result{
		Changes: []whatif.Change{
			{ResourceID: "/sub/rg/res1", ChangeType: whatif.ChangeTypeCreate},
			{ResourceID: "/sub/rg/res2", ChangeType: whatif.ChangeTypeCreate},
			{ResourceID: "/sub/rg/res3", ChangeType: whatif.ChangeTypeModify},
			{ResourceID: "/sub/rg/res4", ChangeType: whatif.ChangeTypeDelete},
		},
	}

	summary := buildChangeSummary(result)
	assert.Equal(t, 4, summary.TotalChanges)
	assert.Equal(t, 2, summary.Creates)
	assert.Equal(t, 1, summary.Modifies)
	assert.Equal(t, 1, summary.Deletes)
}

func TestBuildChangeSummaryNilResult(t *testing.T) {
	summary := buildChangeSummary(nil)
	assert.Equal(t, 0, summary.TotalChanges)
}
