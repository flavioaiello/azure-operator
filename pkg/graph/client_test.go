package graph

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
)

func TestConstants(t *testing.T) {
	assert.Equal(t, 1000, MaxQueryResultRows)
	assert.Equal(t, 30*time.Second, QueryTimeout)
	assert.Equal(t, "azo-managed", ChangeTrackingTag)
	assert.Equal(t, "azo-domain", OperatorDomainTag)
}

func TestResourceFields(t *testing.T) {
	now := time.Now()
	resource := Resource{
		ID:             "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
		Name:           "vnet",
		Type:           "microsoft.network/virtualnetworks",
		Location:       "westeurope",
		ResourceGroup:  "rg",
		SubscriptionID: "xxx",
		Tags: map[string]string{
			ChangeTrackingTag: "true",
			OperatorDomainTag: "connectivity",
		},
		Properties:  map[string]interface{}{"addressSpace": "10.0.0.0/16"},
		ChangedTime: &now,
	}

	assert.Equal(t, "vnet", resource.Name)
	assert.Equal(t, "westeurope", resource.Location)
	assert.True(t, resource.Tags[ChangeTrackingTag] == "true")
	assert.Equal(t, "connectivity", resource.Tags[OperatorDomainTag])
}

func TestChangeInfoFields(t *testing.T) {
	now := time.Now()
	change := ChangeInfo{
		Resource: Resource{
			ID:   "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
			Name: "vnet",
		},
		ChangeType: "Update",
		ChangedBy:  "user@example.com",
		ChangeTime: now,
	}

	assert.Equal(t, "Update", change.ChangeType)
	assert.Equal(t, "user@example.com", change.ChangedBy)
}

func TestClientGetSubscriptions(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name     string
		config   *config.Config
		expected int
	}{
		{
			name: "subscription scope",
			config: &config.Config{
				SubscriptionID: "12345678-1234-1234-1234-123456789012",
				Scope:          config.ScopeSubscription,
			},
			expected: 1,
		},
		{
			name: "management group scope",
			config: &config.Config{
				SubscriptionID:    "12345678-1234-1234-1234-123456789012",
				ManagementGroupID: "mg-platform",
				Scope:             config.ScopeManagementGroup,
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				config: tt.config,
				logger: logger,
			}

			subs := client.getSubscriptions()
			assert.Len(t, subs, tt.expected)
		})
	}
}

func TestErrors(t *testing.T) {
	assert.NotEqual(t, ErrQueryFailed, ErrQueryTimeout)
	assert.NotEqual(t, ErrTooManyResults, ErrInvalidResponse)
	assert.NotEqual(t, ErrNoSubscriptions, ErrQueryFailed)
}

func TestToPtr(t *testing.T) {
	s := "test"
	ptr := toPtr(s)
	assert.Equal(t, &s, ptr)
	assert.Equal(t, "test", *ptr)

	i := 42
	iptr := toPtr(i)
	assert.Equal(t, 42, *iptr)
}
