// Package approval provides approval workflow for protected deployments.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/whatif"
)

// Constants for approval workflow.
const (
	DefaultApprovalTimeout = 24 * time.Hour
	MaxPendingApprovals    = 10
	ApprovalIDLength       = 16
)

// ApprovalStatus represents the status of an approval request.
type ApprovalStatus string

const (
	StatusPending  ApprovalStatus = "pending"
	StatusApproved ApprovalStatus = "approved"
	StatusRejected ApprovalStatus = "rejected"
	StatusExpired  ApprovalStatus = "expired"
)

// Errors.
var (
	ErrApprovalNotFound   = errors.New("approval not found")
	ErrApprovalExpired    = errors.New("approval has expired")
	ErrApprovalNotPending = errors.New("approval is not pending")
	ErrTooManyPending     = errors.New("too many pending approvals")
)

// Request represents an approval request.
type Request struct {
	ID              string         `json:"id"`
	Domain          string         `json:"domain"`
	Status          ApprovalStatus `json:"status"`
	CreatedAt       time.Time      `json:"createdAt"`
	ExpiresAt       time.Time      `json:"expiresAt"`
	ApprovedAt      *time.Time     `json:"approvedAt,omitempty"`
	ApprovedBy      string         `json:"approvedBy,omitempty"`
	RejectedAt      *time.Time     `json:"rejectedAt,omitempty"`
	RejectedBy      string         `json:"rejectedBy,omitempty"`
	RejectionReason string         `json:"rejectionReason,omitempty"`
	ChangeSummary   ChangeSummary  `json:"changeSummary"`
	DeploymentName  string         `json:"deploymentName"`
	ResourceGroup   string         `json:"resourceGroup,omitempty"`
}

// ChangeSummary summarizes proposed changes.
type ChangeSummary struct {
	TotalChanges      int      `json:"totalChanges"`
	Creates           int      `json:"creates"`
	Modifies          int      `json:"modifies"`
	Deletes           int      `json:"deletes"`
	AffectedResources []string `json:"affectedResources"`
}

// IsExpired returns true if the request has expired.
func (r *Request) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsPending returns true if the request is pending.
func (r *Request) IsPending() bool {
	return r.Status == StatusPending && !r.IsExpired()
}

// Manager handles approval workflow.
type Manager struct {
	config     *config.Config
	logger     *zap.Logger
	storageDir string
	mu         sync.RWMutex
}

// NewManager creates a new approval manager.
func NewManager(cfg *config.Config, logger *zap.Logger, storageDir string) (*Manager, error) {
	if storageDir == "" {
		storageDir = "/tmp/azure-operator/approvals"
	}

	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create approval storage: %w", err)
	}

	return &Manager{
		config:     cfg,
		logger:     logger,
		storageDir: storageDir,
	}, nil
}

// CreateRequest creates a new approval request.
func (m *Manager) CreateRequest(
	_ context.Context,
	deploymentName string,
	resourceGroup string,
	whatIfResult *whatif.Result,
) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pending, err := m.listPendingLocked()
	if err != nil {
		return nil, err
	}
	if len(pending) >= MaxPendingApprovals {
		return nil, ErrTooManyPending
	}

	id, err := generateApprovalID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate approval ID: %w", err)
	}

	summary := buildChangeSummary(whatIfResult)

	now := time.Now().UTC()
	request := &Request{
		ID:             id,
		Domain:         m.config.Domain,
		Status:         StatusPending,
		CreatedAt:      now,
		ExpiresAt:      now.Add(DefaultApprovalTimeout),
		ChangeSummary:  summary,
		DeploymentName: deploymentName,
		ResourceGroup:  resourceGroup,
	}

	if err := m.saveRequest(request); err != nil {
		return nil, err
	}

	m.logger.Info("Approval request created",
		zap.String("id", id),
		zap.String("domain", m.config.Domain),
		zap.Int("total_changes", summary.TotalChanges),
		zap.Time("expires_at", request.ExpiresAt),
	)

	return request, nil
}

// GetRequest retrieves an approval request by ID.
func (m *Manager) GetRequest(_ context.Context, id string) (*Request, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadRequest(id)
}

// Approve approves a pending request.
func (m *Manager) Approve(_ context.Context, id string, approvedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	request, err := m.loadRequest(id)
	if err != nil {
		return err
	}

	if request.IsExpired() {
		request.Status = StatusExpired
		_ = m.saveRequest(request)
		return ErrApprovalExpired
	}

	if request.Status != StatusPending {
		return ErrApprovalNotPending
	}

	now := time.Now().UTC()
	request.Status = StatusApproved
	request.ApprovedAt = &now
	request.ApprovedBy = approvedBy

	if err := m.saveRequest(request); err != nil {
		return err
	}

	m.logger.Info("Approval request approved",
		zap.String("id", id),
		zap.String("domain", request.Domain),
		zap.String("approved_by", approvedBy),
	)

	return nil
}

// Reject rejects a pending request.
func (m *Manager) Reject(_ context.Context, id string, rejectedBy string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	request, err := m.loadRequest(id)
	if err != nil {
		return err
	}

	if request.Status != StatusPending {
		return ErrApprovalNotPending
	}

	now := time.Now().UTC()
	request.Status = StatusRejected
	request.RejectedAt = &now
	request.RejectedBy = rejectedBy
	request.RejectionReason = reason

	if err := m.saveRequest(request); err != nil {
		return err
	}

	m.logger.Info("Approval request rejected",
		zap.String("id", id),
		zap.String("domain", request.Domain),
		zap.String("rejected_by", rejectedBy),
		zap.String("reason", reason),
	)

	return nil
}

// ListPending returns all pending approval requests for the domain.
func (m *Manager) ListPending(_ context.Context) ([]*Request, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listPendingLocked()
}

func (m *Manager) listPendingLocked() ([]*Request, error) {
	files, err := os.ReadDir(m.storageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage dir: %w", err)
	}

	var pending []*Request
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		id := file.Name()[:len(file.Name())-5]
		request, err := m.loadRequest(id)
		if err != nil {
			continue
		}

		if request.Domain == m.config.Domain && request.IsPending() {
			pending = append(pending, request)
		}
	}

	return pending, nil
}

func (m *Manager) loadRequest(id string) (*Request, error) {
	path := filepath.Join(m.storageDir, id+".json")

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrApprovalNotFound
		}
		return nil, fmt.Errorf("failed to read approval: %w", err)
	}

	var request Request
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("failed to parse approval: %w", err)
	}

	return &request, nil
}

func (m *Manager) saveRequest(request *Request) error {
	path := filepath.Join(m.storageDir, request.ID+".json")

	data, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal approval: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write approval: %w", err)
	}

	return nil
}

func generateApprovalID() (string, error) {
	bytes := make([]byte, ApprovalIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func buildChangeSummary(result *whatif.Result) ChangeSummary {
	summary := ChangeSummary{
		AffectedResources: make([]string, 0),
	}

	if result == nil {
		return summary
	}

	for _, change := range result.Changes {
		summary.TotalChanges++
		summary.AffectedResources = append(summary.AffectedResources, change.ResourceID)

		switch change.ChangeType {
		case whatif.ChangeTypeCreate:
			summary.Creates++
		case whatif.ChangeTypeModify:
			summary.Modifies++
		case whatif.ChangeTypeDelete:
			summary.Deletes++
		}
	}

	return summary
}
