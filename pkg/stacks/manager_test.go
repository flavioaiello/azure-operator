package stacks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// Test constants to avoid literal duplication.
const testSubscriptionID = "00000000-0000-0000-0000-000000000001"

func TestConstants(t *testing.T) {
	assert.Equal(t, 60*time.Minute, DefaultStackTimeout)
	assert.Equal(t, 90, MaxStackNameLength)
	assert.Equal(t, 10*time.Second, StackPollingInterval)
}

func TestDenySettingsMode(t *testing.T) {
	assert.Equal(t, DenySettingsMode("None"), DenySettingsModeNone)
	assert.Equal(t, DenySettingsMode("DenyDelete"), DenySettingsModeDenyDelete)
	assert.Equal(t, DenySettingsMode("DenyWriteAndDelete"), DenySettingsModeDenyWriteDelete)
}

func TestDeleteResourcesMode(t *testing.T) {
	assert.Equal(t, DeleteResourcesMode("Detach"), DeleteResourcesModeDetach)
	assert.Equal(t, DeleteResourcesMode("Delete"), DeleteResourcesModeDelete)
}

func TestStackStatus(t *testing.T) {
	assert.Equal(t, StackStatus("Succeeded"), StackStatusSucceeded)
	assert.Equal(t, StackStatus("Failed"), StackStatusFailed)
	assert.Equal(t, StackStatus("Deploying"), StackStatusDeploying)
	assert.Equal(t, StackStatus("Deleting"), StackStatusDeleting)
	assert.Equal(t, StackStatus("Canceled"), StackStatusCanceled)
	assert.Equal(t, StackStatus("Unknown"), StackStatusUnknown)
}

func TestErrors(t *testing.T) {
	assert.NotNil(t, ErrStackNotFound)
	assert.NotNil(t, ErrStackDeploymentFailed)
	assert.NotNil(t, ErrStackDeletionFailed)
	assert.NotNil(t, ErrStackNameTooLong)
	assert.NotNil(t, ErrInvalidDenySettings)
}

func TestStackConfig(t *testing.T) {
	cfg := StackConfig{
		Name:          "my-stack",
		Description:   "Test deployment stack",
		ResourceGroup: "rg-test",
		DenySettings:  DenySettingsModeDenyDelete,
		DeleteMode:    DeleteResourcesModeDetach,
		Tags: map[string]string{
			"environment": "test",
		},
	}

	assert.Equal(t, "my-stack", cfg.Name)
	assert.Equal(t, DenySettingsModeDenyDelete, cfg.DenySettings)
	assert.Contains(t, cfg.Tags, "environment")
}

func TestStackResult(t *testing.T) {
	result := StackResult{
		ID:     "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Resources/deploymentStacks/stack1",
		Name:   "stack1",
		Status: StackStatusSucceeded,
		Resources: []ManagedResource{
			{
				ID:   "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
				Type: "Microsoft.Network/virtualNetworks",
			},
		},
		Duration: 5 * time.Minute,
	}

	assert.Equal(t, "stack1", result.Name)
	assert.Equal(t, StackStatusSucceeded, result.Status)
	assert.Len(t, result.Resources, 1)
}

func TestManagedResource(t *testing.T) {
	resource := ManagedResource{
		ID:         "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
		Name:       "vm1",
		Type:       "Microsoft.Compute/virtualMachines",
		Status:     "Managed",
		DenyStatus: "DenyDelete",
	}

	assert.Equal(t, "vm1", resource.Name)
	assert.Equal(t, "DenyDelete", resource.DenyStatus)
}

func TestNewManager(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	manager := NewManager(logger, nil, testSubscriptionID)

	assert.NotNil(t, manager)
	assert.Equal(t, testSubscriptionID, manager.subscriptionID)
	assert.Equal(t, DefaultStackTimeout, manager.timeout)
}

func TestWithTimeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	manager := NewManager(logger, nil, testSubscriptionID)

	manager = manager.WithTimeout(30 * time.Minute)

	assert.Equal(t, 30*time.Minute, manager.timeout)
}

func TestStackNameValidation(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{"short name", 10, false},
		{"max length", MaxStackNameLength, false},
		{"too long", MaxStackNameLength + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := make([]byte, tt.length)
			for i := range name {
				name[i] = 'a'
			}
			if tt.wantErr {
				assert.Greater(t, len(name), MaxStackNameLength)
			} else {
				assert.LessOrEqual(t, len(name), MaxStackNameLength)
			}
		})
	}
}

func TestBuildDenySettings(t *testing.T) {
	tests := []struct {
		mode DenySettingsMode
	}{
		{DenySettingsModeNone},
		{DenySettingsModeDenyDelete},
		{DenySettingsModeDenyWriteDelete},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			settings := buildDenySettings(tt.mode)
			assert.NotNil(t, settings)
			assert.NotNil(t, settings.Mode)
		})
	}
}

func TestBuildActionOnUnmanage(t *testing.T) {
	tests := []struct {
		mode DeleteResourcesMode
	}{
		{DeleteResourcesModeDetach},
		{DeleteResourcesModeDelete},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			action := buildActionOnUnmanage(tt.mode)
			assert.NotNil(t, action)
			assert.NotNil(t, action.Resources)
		})
	}
}

func TestIsNotFoundError(t *testing.T) {
	assert.False(t, isNotFoundError(nil))
}

func TestToStringPtrMap(t *testing.T) {
	t.Run("nil map", func(t *testing.T) {
		result := toStringPtrMap(nil)
		assert.Nil(t, result)
	})

	t.Run("non-empty map", func(t *testing.T) {
		input := map[string]string{
			"key1": "value1",
			"key2": "value2",
		}
		result := toStringPtrMap(input)
		assert.Len(t, result, 2)
		assert.Equal(t, "value1", *result["key1"])
		assert.Equal(t, "value2", *result["key2"])
	})
}

func TestToPtr(t *testing.T) {
	s := "test"
	ptr := toPtr(s)
	assert.Equal(t, "test", *ptr)
}
