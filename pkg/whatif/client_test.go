package whatif

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/flavioaiello/azure-operator/pkg/config"
)

func TestConstants(t *testing.T) {
	assert.Equal(t, 5*time.Minute, WhatIfTimeout)
	assert.Equal(t, 500, MaxWhatIfChanges)
	assert.Equal(t, 5*time.Second, PollingInterval)
}

func TestChangeTypeValues(t *testing.T) {
	assert.Equal(t, ChangeType("Create"), ChangeTypeCreate)
	assert.Equal(t, ChangeType("Delete"), ChangeTypeDelete)
	assert.Equal(t, ChangeType("Modify"), ChangeTypeModify)
	assert.Equal(t, ChangeType("NoChange"), ChangeTypeNoChange)
	assert.Equal(t, ChangeType("Ignore"), ChangeTypeIgnore)
	assert.Equal(t, ChangeType("Deploy"), ChangeTypeDeploy)
	assert.Equal(t, ChangeType("Unsupported"), ChangeTypeUnsupported)
}

func TestResultHasChanges(t *testing.T) {
	tests := []struct {
		name       string
		changes    []Change
		hasChanges bool
	}{
		{
			name:       "empty",
			changes:    []Change{},
			hasChanges: false,
		},
		{
			name: "only no change",
			changes: []Change{
				{ChangeType: ChangeTypeNoChange},
			},
			hasChanges: false,
		},
		{
			name: "only ignore",
			changes: []Change{
				{ChangeType: ChangeTypeIgnore},
			},
			hasChanges: false,
		},
		{
			name: "create",
			changes: []Change{
				{ChangeType: ChangeTypeCreate},
			},
			hasChanges: true,
		},
		{
			name: "delete",
			changes: []Change{
				{ChangeType: ChangeTypeDelete},
			},
			hasChanges: true,
		},
		{
			name: "modify",
			changes: []Change{
				{ChangeType: ChangeTypeModify},
			},
			hasChanges: true,
		},
		{
			name: "mixed",
			changes: []Change{
				{ChangeType: ChangeTypeNoChange},
				{ChangeType: ChangeTypeModify},
				{ChangeType: ChangeTypeIgnore},
			},
			hasChanges: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &Result{Changes: tt.changes}
			assert.Equal(t, tt.hasChanges, result.HasChanges())
		})
	}
}

func TestResultChangeCount(t *testing.T) {
	result := &Result{
		Changes: []Change{
			{ChangeType: ChangeTypeCreate},
			{ChangeType: ChangeTypeCreate},
			{ChangeType: ChangeTypeModify},
			{ChangeType: ChangeTypeNoChange},
			{ChangeType: ChangeTypeNoChange},
			{ChangeType: ChangeTypeNoChange},
			{ChangeType: ChangeTypeDelete},
		},
	}

	count := result.ChangeCount()
	assert.Equal(t, 7, count)

	assert.Equal(t, 2, result.CountByType(ChangeTypeCreate))
	assert.Equal(t, 1, result.CountByType(ChangeTypeModify))
	assert.Equal(t, 3, result.CountByType(ChangeTypeNoChange))
	assert.Equal(t, 1, result.CountByType(ChangeTypeDelete))
}

func TestNewClientNoCredential(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		Domain:         "test",
		SubscriptionID: "12345678-1234-1234-1234-123456789012",
	}

	_, err := NewClient(cfg, nil, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential is required")
}

func TestChangeFields(t *testing.T) {
	change := Change{
		ResourceID: "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
		ChangeType: ChangeTypeModify,
		Before: map[string]interface{}{
			"addressSpace": "10.0.0.0/16",
		},
		After: map[string]interface{}{
			"addressSpace": "10.0.0.0/8",
		},
		PropertyChanges: []PropertyChange{
			{
				Path:       "properties.addressSpace.addressPrefixes[0]",
				Before:     "10.0.0.0/16",
				After:      "10.0.0.0/8",
				ChangeType: ChangeTypeModify,
			},
		},
	}

	assert.Equal(t, ChangeTypeModify, change.ChangeType)
	assert.Len(t, change.PropertyChanges, 1)
	assert.Equal(t, "properties.addressSpace.addressPrefixes[0]", change.PropertyChanges[0].Path)
}

func TestErrors(t *testing.T) {
	assert.NotEqual(t, ErrWhatIfFailed, ErrWhatIfTimeout)
	assert.NotEqual(t, ErrTooManyChanges, ErrInvalidTemplate)
}

func TestToPtr(t *testing.T) {
	s := "test"
	ptr := toPtr(s)
	assert.Equal(t, "test", *ptr)
}
