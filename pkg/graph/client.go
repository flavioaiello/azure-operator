// Package graph provides Azure Resource Graph integration for fast drift detection.
//
// The Resource Graph enables:
//  1. Fast queries (~2s) across all subscriptions
//  2. Change attribution via changeTrackingTag
//  3. Orphan detection (resources not in spec)
//  4. Reduction of WhatIf calls by ~90%
//
// HYBRID DRIFT DETECTION:
// Resource Graph is used as fast-path check. If changes detected,
// ARM WhatIf is invoked for precise diff.
package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
)

// Constants for Resource Graph queries.
const (
	// MaxQueryResultRows is the maximum rows per query.
	MaxQueryResultRows = 1000
	// QueryTimeout is the timeout for Resource Graph queries.
	QueryTimeout = 30 * time.Second
	// ChangeTrackingTag is the tag used to track operator-managed resources.
	ChangeTrackingTag = "azo-managed"
	// OperatorDomainTag is the tag for the operator domain.
	OperatorDomainTag = "azo-domain"
)

// safeKQLPattern validates strings safe for KQL interpolation.
// SECURITY: Only alphanumeric, hyphens, and underscores allowed.
var safeKQLPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Errors.
var (
	ErrQueryFailed       = errors.New("resource graph query failed")
	ErrQueryTimeout      = errors.New("resource graph query timed out")
	ErrTooManyResults    = errors.New("query returned too many results")
	ErrInvalidResponse   = errors.New("invalid response from resource graph")
	ErrNoSubscriptions   = errors.New("no subscriptions to query")
	ErrInvalidQueryParam = errors.New("invalid query parameter - contains unsafe characters")
)

// Resource represents a resource from Resource Graph.
type Resource struct {
	// ID is the resource ID.
	ID string `json:"id"`
	// Name is the resource name.
	Name string `json:"name"`
	// Type is the resource type.
	Type string `json:"type"`
	// Location is the Azure region.
	Location string `json:"location"`
	// ResourceGroup is the resource group name.
	ResourceGroup string `json:"resourceGroup"`
	// SubscriptionID is the subscription ID.
	SubscriptionID string `json:"subscriptionId"`
	// Tags are the resource tags.
	Tags map[string]string `json:"tags"`
	// Properties are the resource properties.
	Properties map[string]interface{} `json:"properties"`
	// ChangedTime is the last modification time.
	ChangedTime *time.Time `json:"changedTime,omitempty"`
}

// ChangeInfo represents change tracking information.
type ChangeInfo struct {
	// Resource is the changed resource.
	Resource Resource
	// ChangeType is the type of change (Create, Update, Delete).
	ChangeType string
	// ChangedBy is the principal that made the change.
	ChangedBy string
	// ChangeTime is when the change occurred.
	ChangeTime time.Time
}

// Client is the Resource Graph client.
type Client struct {
	client *armresourcegraph.Client
	config *config.Config
	logger *zap.Logger
}

// NewClient creates a new Resource Graph client.
func NewClient(cfg *config.Config, cred azcore.TokenCredential, logger *zap.Logger) (*Client, error) {
	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource graph client: %w", err)
	}

	return &Client{
		client: client,
		config: cfg,
		logger: logger,
	}, nil
}

// validateKQLParam validates a string is safe for KQL query interpolation.
// SECURITY: Prevents KQL injection attacks.
func validateKQLParam(param, name string) error {
	if !safeKQLPattern.MatchString(param) {
		return fmt.Errorf("%w: %s contains unsafe characters", ErrInvalidQueryParam, name)
	}
	return nil
}

// QueryManagedResources queries all resources managed by this operator domain.
func (c *Client) QueryManagedResources(ctx context.Context) ([]Resource, error) {
	// SECURITY: Validate domain before query interpolation.
	if err := validateKQLParam(c.config.Domain, "domain"); err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
		Resources
		| where tags['%s'] == '%s'
		| where tags['%s'] == '%s'
		| project id, name, type, location, resourceGroup, subscriptionId, tags, properties
		| order by id asc
		| take %d
	`, ChangeTrackingTag, "true", OperatorDomainTag, c.config.Domain, MaxQueryResultRows)

	return c.executeQuery(ctx, query)
}

// QueryResourcesByType queries resources of a specific type in the scope.
func (c *Client) QueryResourcesByType(ctx context.Context, resourceType string) ([]Resource, error) {
	// SECURITY: Validate resourceType before query interpolation.
	if err := validateKQLParam(resourceType, "resourceType"); err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
		Resources
		| where type =~ '%s'
		| project id, name, type, location, resourceGroup, subscriptionId, tags, properties
		| order by id asc
		| take %d
	`, resourceType, MaxQueryResultRows)

	return c.executeQuery(ctx, query)
}

// QueryRecentChanges queries resources changed since the given time.
// NOTE: Time-based filtering is not directly supported by Azure Resource Graph.
// This queries resources with the managed tag and relies on change tracking
// via the Azure Resource Changes API in a future enhancement.
func (c *Client) QueryRecentChanges(ctx context.Context, _ time.Time) ([]Resource, error) {
	// SECURITY: Validate domain before query interpolation.
	if err := validateKQLParam(c.config.Domain, "domain"); err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
		Resources
		| where tags['%s'] == 'true'
		| where tags['%s'] == '%s'
		| project id, name, type, location, resourceGroup, subscriptionId, tags, properties
		| order by id asc
		| take %d
	`, ChangeTrackingTag, OperatorDomainTag, c.config.Domain, MaxQueryResultRows)

	return c.executeQuery(ctx, query)
}

// QueryOrphanedResources queries resources that might be orphaned.
// Orphans are resources with the managed tag but not in the expected resource groups.
func (c *Client) QueryOrphanedResources(ctx context.Context, expectedResourceGroups []string) ([]Resource, error) {
	if len(expectedResourceGroups) == 0 {
		return nil, nil
	}

	// SECURITY: Validate domain before query interpolation.
	if err := validateKQLParam(c.config.Domain, "domain"); err != nil {
		return nil, err
	}

	// SECURITY: Validate each resource group name.
	rgFilter := ""
	for i, rg := range expectedResourceGroups {
		if err := validateKQLParam(rg, "resourceGroup"); err != nil {
			return nil, err
		}
		if i > 0 {
			rgFilter += ", "
		}
		rgFilter += fmt.Sprintf("'%s'", rg)
	}

	query := fmt.Sprintf(`
		Resources
		| where tags['%s'] == 'true'
		| where tags['%s'] == '%s'
		| where resourceGroup !in~ (%s)
		| project id, name, type, location, resourceGroup, subscriptionId, tags, properties
		| order by id asc
		| take %d
	`, ChangeTrackingTag, OperatorDomainTag, c.config.Domain, rgFilter, MaxQueryResultRows)

	return c.executeQuery(ctx, query)
}

// GetResourceByID queries a single resource by ID.
func (c *Client) GetResourceByID(ctx context.Context, resourceID string) (*Resource, error) {
	// SECURITY: Resource IDs have a specific format - validate length.
	if resourceID == "" || len(resourceID) > 2048 {
		return nil, fmt.Errorf("%w: resourceID invalid length", ErrInvalidQueryParam)
	}

	query := fmt.Sprintf(`
		Resources
		| where id =~ '%s'
		| project id, name, type, location, resourceGroup, subscriptionId, tags, properties
	`, resourceID)

	resources, err := c.executeQuery(ctx, query)
	if err != nil {
		return nil, err
	}

	if len(resources) == 0 {
		return nil, nil
	}

	return &resources[0], nil
}

// executeQuery executes a Resource Graph query.
func (c *Client) executeQuery(ctx context.Context, query string) ([]Resource, error) {
	// Apply timeout.
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()

	subscriptions := c.getSubscriptions()
	if len(subscriptions) == 0 {
		return nil, ErrNoSubscriptions
	}

	c.logger.Debug("Executing Resource Graph query",
		zap.String("domain", c.config.Domain),
		zap.Int("subscriptions", len(subscriptions)),
	)

	// Build request.
	request := armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: subscriptions,
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: toPtr(armresourcegraph.ResultFormatObjectArray),
		},
	}

	// Execute query.
	resp, err := c.client.Resources(ctx, request, nil)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrQueryTimeout
		}
		c.logger.Error("Resource Graph query failed",
			zap.Error(err),
			zap.String("domain", c.config.Domain),
		)
		return nil, fmt.Errorf("%w: %v", ErrQueryFailed, err)
	}

	// Parse response.
	return c.parseResponse(resp)
}

// parseResponse parses the Resource Graph response.
func (c *Client) parseResponse(resp armresourcegraph.ClientResourcesResponse) ([]Resource, error) {
	if resp.Data == nil {
		return nil, nil
	}

	// Check row count.
	if resp.TotalRecords != nil && *resp.TotalRecords > MaxQueryResultRows {
		c.logger.Warn("Query returned more results than limit",
			zap.Int64("total", *resp.TotalRecords),
			zap.Int("limit", MaxQueryResultRows),
		)
	}

	// Parse data array.
	data, ok := resp.Data.([]interface{})
	if !ok {
		return nil, ErrInvalidResponse
	}

	resources := make([]Resource, 0, len(data))
	for _, item := range data {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Convert to JSON and back for clean parsing.
		jsonBytes, err := json.Marshal(itemMap)
		if err != nil {
			c.logger.Warn("Failed to marshal resource",
				zap.Error(err),
			)
			continue
		}

		var resource Resource
		if err := json.Unmarshal(jsonBytes, &resource); err != nil {
			c.logger.Warn("Failed to unmarshal resource",
				zap.Error(err),
			)
			continue
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

// getSubscriptions returns the subscriptions to query.
func (c *Client) getSubscriptions() []*string {
	if c.config.Scope == config.ScopeManagementGroup {
		// For management group scope, we'd need to enumerate subscriptions.
		// For now, return the configured subscription.
		return []*string{&c.config.SubscriptionID}
	}

	return []*string{&c.config.SubscriptionID}
}

// toPtr returns a pointer to the value.
func toPtr[T any](v T) *T {
	return &v
}
