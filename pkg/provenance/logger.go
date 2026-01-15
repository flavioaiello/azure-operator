// Package provenance provides audit trail and git attribution for deployments.
//
// Records who deployed what, when, and from which git commit, enabling
// full traceability of infrastructure changes.
package provenance

import (
	"encoding/json"
	"os"
	"time"

	"go.uber.org/zap"
)

// Action represents the type of operation performed.
type Action string

const (
	ReconcileAction Action = "reconcile"
	WhatIfAction    Action = "whatif"
	DeployAction    Action = "deploy"
	RollbackAction  Action = "rollback"
)

// Record captures the provenance of a deployment operation.
type Record struct {
	Timestamp time.Time      `json:"timestamp"`
	Action    Action         `json:"action"`
	Scope     string         `json:"scope"`     // Subscription ID or management group
	SpecPath  string         `json:"spec_path"` // Path to the spec file
	GitSHA    string         `json:"git_sha,omitempty"`
	GitBranch string         `json:"git_branch,omitempty"`
	GitRepo   string         `json:"git_repo,omitempty"`
	Operator  string         `json:"operator"` // user@host or managed identity
	Changes   *ChangeSummary `json:"changes,omitempty"`
}

// ToJSON serializes the record to JSON.
func (r Record) ToJSON() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ChangeSummary summarizes the changes in a deployment.
type ChangeSummary struct {
	Created  int `json:"created"`
	Modified int `json:"modified"`
	Deleted  int `json:"deleted"`
	NoChange int `json:"no_change"`
	Ignored  int `json:"ignored"`
}

// TotalSignificant returns the count of significant changes.
func (s ChangeSummary) TotalSignificant() int {
	return s.Created + s.Modified + s.Deleted
}

// IsEmpty returns true if there are no resources at all.
func (s ChangeSummary) IsEmpty() bool {
	return s.Created == 0 && s.Modified == 0 && s.Deleted == 0 && s.NoChange == 0 && s.Ignored == 0
}

// Logger provides structured provenance logging.
type Logger struct {
	log *zap.Logger
}

// NewLogger creates a provenance logger.
func NewLogger(log *zap.Logger) *Logger {
	return &Logger{log: log}
}

// CreateRecord creates a new provenance record with environment context.
func (l *Logger) CreateRecord(scope, specPath string, action Action) Record {
	hostname, _ := os.Hostname() //nolint:errcheck // Empty hostname fallback is handled below
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}

	operator := user
	if hostname != "" {
		operator = user + "@" + hostname
	}

	return Record{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Scope:     scope,
		SpecPath:  specPath,
		GitSHA:    os.Getenv("GIT_COMMIT_SHA"),
		GitBranch: os.Getenv("GIT_BRANCH"),
		GitRepo:   os.Getenv("GIT_REPO"),
		Operator:  operator,
		Changes:   &ChangeSummary{},
	}
}

// LogProvenance logs a provenance record as structured JSON.
func (l *Logger) LogProvenance(record Record) {
	l.log.Info("provenance",
		zap.String("action", string(record.Action)),
		zap.String("scope", record.Scope),
		zap.String("spec_path", record.SpecPath),
		zap.String("git_sha", record.GitSHA),
		zap.String("git_branch", record.GitBranch),
		zap.String("git_repo", record.GitRepo),
		zap.String("operator", record.Operator),
		zap.Time("timestamp", record.Timestamp),
		zap.Any("changes", record.Changes),
	)
}

// LogChangeDetail logs detailed change information for audit purposes.
func (l *Logger) LogChangeDetail(record Record, resourceType, resourceName, changeType string, before, after interface{}) {
	l.log.Info("change_detail",
		zap.String("git_sha", record.GitSHA),
		zap.String("scope", record.Scope),
		zap.String("resource_type", resourceType),
		zap.String("resource_name", resourceName),
		zap.String("change_type", changeType),
		zap.Any("before", before),
		zap.Any("after", after),
	)
}
