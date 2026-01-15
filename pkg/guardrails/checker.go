// Package guardrails provides safety checks for deployments.
package guardrails

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
	"github.com/flavioaiello/azure-operator/pkg/whatif"
)

// Constants for guardrail limits.
const (
	MaxDeletesPerDeployment           = 5
	MaxAffectedResourcesPerDeployment = 50
	DeploymentRateLimitWindow         = 1 * time.Hour
	MaxDeploymentsPerWindow           = 10
	DefaultCooldownPeriod             = 30 * time.Second
)

// Errors.
var (
	ErrTooManyDeletes      = errors.New("deployment would delete too many resources")
	ErrBlastRadiusExceeded = errors.New("deployment affects too many resources")
	ErrRateLimitExceeded   = errors.New("deployment rate limit exceeded")
	ErrProtectedResource   = errors.New("deployment would affect protected resource")
	ErrCooldownActive      = errors.New("deployment cooldown period active")
)

// ViolationType identifies the type of guardrail violation.
type ViolationType string

const (
	ViolationTooManyDeletes    ViolationType = "too_many_deletes"
	ViolationBlastRadius       ViolationType = "blast_radius_exceeded"
	ViolationRateLimit         ViolationType = "rate_limit_exceeded"
	ViolationProtectedResource ViolationType = "protected_resource"
	ViolationCooldown          ViolationType = "cooldown_active"
)

// Violation represents a guardrail violation.
type Violation struct {
	Type        ViolationType `json:"type"`
	Message     string        `json:"message"`
	ResourceIDs []string      `json:"resourceIds,omitempty"`
	Limit       int           `json:"limit,omitempty"`
	Actual      int           `json:"actual,omitempty"`
}

// Result is the result of a guardrails check.
type Result struct {
	Passed     bool        `json:"passed"`
	Violations []Violation `json:"violations,omitempty"`
	CheckedAt  time.Time   `json:"checkedAt"`
}

// ProtectedPattern defines a protected resource pattern.
type ProtectedPattern struct {
	Pattern     *regexp.Regexp
	Description string
	AllowModify bool
}

// Checker performs guardrail checks.
type Checker struct {
	config            *config.Config
	logger            *zap.Logger
	protectedPatterns []ProtectedPattern
	deploymentHistory []time.Time
	lastDeployment    time.Time
	mu                sync.RWMutex
}

// NewChecker creates a new guardrails checker.
func NewChecker(cfg *config.Config, logger *zap.Logger) *Checker {
	return &Checker{
		config:            cfg,
		logger:            logger,
		protectedPatterns: defaultProtectedPatterns(),
		deploymentHistory: make([]time.Time, 0, MaxDeploymentsPerWindow),
	}
}

func defaultProtectedPatterns() []ProtectedPattern {
	return []ProtectedPattern{
		{
			Pattern:     regexp.MustCompile(`(?i)/providers/Microsoft\.Authorization/roleAssignments/`),
			Description: "Role assignments (RBAC)",
			AllowModify: false,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)/providers/Microsoft\.Authorization/policyAssignments/`),
			Description: "Policy assignments",
			AllowModify: true,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)/providers/Microsoft\.Management/managementGroups/`),
			Description: "Management groups",
			AllowModify: true,
		},
		{
			Pattern:     regexp.MustCompile(`(?i)/providers/Microsoft\.KeyVault/vaults/`),
			Description: "Key Vaults",
			AllowModify: true,
		},
	}
}

// Check performs all guardrail checks on a WhatIf result.
func (c *Checker) Check(_ context.Context, result *whatif.Result) Result {
	c.mu.Lock()
	defer c.mu.Unlock()

	checkResult := Result{
		Passed:    true,
		CheckedAt: time.Now().UTC(),
	}

	if result == nil {
		return checkResult
	}

	if v := c.checkRateLimitLocked(); v != nil {
		checkResult.Passed = false
		checkResult.Violations = append(checkResult.Violations, *v)
	}

	if v := c.checkCooldownLocked(); v != nil {
		checkResult.Passed = false
		checkResult.Violations = append(checkResult.Violations, *v)
	}

	if v := c.checkDeleteCount(result); v != nil {
		checkResult.Passed = false
		checkResult.Violations = append(checkResult.Violations, *v)
	}

	if v := c.checkBlastRadius(result); v != nil {
		checkResult.Passed = false
		checkResult.Violations = append(checkResult.Violations, *v)
	}

	if violations := c.checkProtectedResources(result); len(violations) > 0 {
		checkResult.Passed = false
		checkResult.Violations = append(checkResult.Violations, violations...)
	}

	return checkResult
}

// RecordDeployment records a successful deployment for rate limiting.
func (c *Checker) RecordDeployment() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.lastDeployment = now
	c.deploymentHistory = append(c.deploymentHistory, now)

	cutoff := now.Add(-DeploymentRateLimitWindow)
	pruned := make([]time.Time, 0, len(c.deploymentHistory))
	for _, t := range c.deploymentHistory {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	c.deploymentHistory = pruned
}

func (c *Checker) checkRateLimitLocked() *Violation {
	now := time.Now()
	cutoff := now.Add(-DeploymentRateLimitWindow)

	count := 0
	for _, t := range c.deploymentHistory {
		if t.After(cutoff) {
			count++
		}
	}

	if count >= MaxDeploymentsPerWindow {
		return &Violation{
			Type:    ViolationRateLimit,
			Message: fmt.Sprintf("Rate limit exceeded: %d deployments in last hour (max %d)", count, MaxDeploymentsPerWindow),
			Limit:   MaxDeploymentsPerWindow,
			Actual:  count,
		}
	}

	return nil
}

func (c *Checker) checkCooldownLocked() *Violation {
	if c.lastDeployment.IsZero() {
		return nil
	}

	elapsed := time.Since(c.lastDeployment)
	if elapsed < DefaultCooldownPeriod {
		remaining := DefaultCooldownPeriod - elapsed
		return &Violation{
			Type:    ViolationCooldown,
			Message: fmt.Sprintf("Cooldown active: %v remaining", remaining.Round(time.Second)),
		}
	}

	return nil
}

func (c *Checker) checkDeleteCount(result *whatif.Result) *Violation {
	deleteCount := 0
	deletedResources := make([]string, 0)

	for _, change := range result.Changes {
		if change.ChangeType == whatif.ChangeTypeDelete {
			deleteCount++
			deletedResources = append(deletedResources, change.ResourceID)
		}
	}

	if deleteCount > MaxDeletesPerDeployment {
		return &Violation{
			Type:        ViolationTooManyDeletes,
			Message:     fmt.Sprintf("Too many deletes: %d resources (max %d)", deleteCount, MaxDeletesPerDeployment),
			Limit:       MaxDeletesPerDeployment,
			Actual:      deleteCount,
			ResourceIDs: deletedResources,
		}
	}

	return nil
}

func (c *Checker) checkBlastRadius(result *whatif.Result) *Violation {
	affectedCount := len(result.Changes)

	if affectedCount > MaxAffectedResourcesPerDeployment {
		resourceIDs := make([]string, 0, len(result.Changes))
		for _, change := range result.Changes {
			resourceIDs = append(resourceIDs, change.ResourceID)
		}

		return &Violation{
			Type:        ViolationBlastRadius,
			Message:     fmt.Sprintf("Blast radius exceeded: %d resources affected (max %d)", affectedCount, MaxAffectedResourcesPerDeployment),
			Limit:       MaxAffectedResourcesPerDeployment,
			Actual:      affectedCount,
			ResourceIDs: resourceIDs,
		}
	}

	return nil
}

func (c *Checker) checkProtectedResources(result *whatif.Result) []Violation {
	var violations []Violation

	for _, change := range result.Changes {
		for _, pattern := range c.protectedPatterns {
			if pattern.Pattern.MatchString(change.ResourceID) {
				if change.ChangeType == whatif.ChangeTypeDelete {
					violations = append(violations, Violation{
						Type:        ViolationProtectedResource,
						Message:     fmt.Sprintf("Cannot delete protected resource (%s): %s", pattern.Description, change.ResourceID),
						ResourceIDs: []string{change.ResourceID},
					})
				} else if change.ChangeType == whatif.ChangeTypeModify && !pattern.AllowModify {
					violations = append(violations, Violation{
						Type:        ViolationProtectedResource,
						Message:     fmt.Sprintf("Cannot modify protected resource (%s): %s", pattern.Description, change.ResourceID),
						ResourceIDs: []string{change.ResourceID},
					})
				}
			}
		}
	}

	return violations
}

// ResetRateLimit resets the rate limit counters (for testing).
func (c *Checker) ResetRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deploymentHistory = make([]time.Time, 0, MaxDeploymentsPerWindow)
	c.lastDeployment = time.Time{}
}
