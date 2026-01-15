package specs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagementSpec_Validate_Valid(t *testing.T) {
	spec := &ManagementSpec{
		BaseSpec: BaseSpec{
			Location:          "westeurope",
			ResourceGroupName: "rg-management",
			Tags: map[string]string{
				"environment": "production",
			},
		},
		LogAnalytics: LogAnalyticsConfig{
			Name:          "log-platform",
			RetentionDays: 365,
			SKU:           "PerGB2018",
		},
		Automation: &AutomationConfig{
			Name: "aa-platform",
		},
	}

	err := spec.Validate()
	assert.NoError(t, err)
}

func TestManagementSpec_Validate_MissingLogAnalytics(t *testing.T) {
	spec := &ManagementSpec{
		BaseSpec: BaseSpec{
			Location: "westeurope",
		},
		// LogAnalytics is required but missing name
		LogAnalytics: LogAnalyticsConfig{},
	}

	err := spec.Validate()
	require.Error(t, err)
}

func TestManagementSpec_Validate_InvalidSKU(t *testing.T) {
	spec := &ManagementSpec{
		BaseSpec: BaseSpec{
			Location: "westeurope",
		},
		LogAnalytics: LogAnalyticsConfig{
			Name:          "log-platform",
			RetentionDays: 365,
			SKU:           "InvalidSKU",
		},
	}

	err := spec.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SKU")
}

func TestManagementSpec_Validate_RetentionOutOfRange(t *testing.T) {
	tests := []struct {
		name          string
		retentionDays int
		wantErr       bool
	}{
		{"below_minimum", 29, true},
		{"minimum", 30, false},
		{"maximum", 730, false},
		{"above_maximum", 731, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &ManagementSpec{
				LogAnalytics: LogAnalyticsConfig{
					Name:          "log-test",
					RetentionDays: tt.retentionDays,
					SKU:           "PerGB2018",
				},
			}

			err := spec.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManagementSpec_ToARMParameters(t *testing.T) {
	spec := &ManagementSpec{
		BaseSpec: BaseSpec{
			Location:          "westeurope",
			ResourceGroupName: "rg-management",
			Tags: map[string]string{
				"environment": "production",
			},
		},
		LogAnalytics: LogAnalyticsConfig{
			Name:          "log-platform",
			RetentionDays: 365,
			SKU:           "PerGB2018",
		},
		Automation: &AutomationConfig{
			Name: "aa-platform",
		},
		DataCollectionRules: []DataCollectionRuleConfig{
			{
				Name:        "dcr-vm-insights",
				Description: "VM Insights DCR",
			},
		},
		ManagedIdentities: []ManagedIdentityConfig{
			{
				Name:        "mi-operator",
				Description: "Operator identity",
			},
		},
	}

	params := spec.ToARMParameters()

	// Check location.
	assert.Equal(t, "westeurope", params["location"].(map[string]interface{})["value"])

	// Check resource group.
	assert.Equal(t, "rg-management", params["resourceGroupName"].(map[string]interface{})["value"])

	// Check Log Analytics.
	assert.Equal(t, "log-platform", params["logAnalyticsName"].(map[string]interface{})["value"])
	assert.Equal(t, 365, params["logAnalyticsRetentionDays"].(map[string]interface{})["value"])
	assert.Equal(t, "PerGB2018", params["logAnalyticsSku"].(map[string]interface{})["value"])

	// Check Automation.
	assert.Equal(t, "aa-platform", params["automationAccountName"].(map[string]interface{})["value"])
}

func TestManagementSpec_ToARMParameters_Minimal(t *testing.T) {
	spec := &ManagementSpec{
		LogAnalytics: LogAnalyticsConfig{
			Name:          "log-minimal",
			RetentionDays: 30,
			SKU:           "Free",
		},
	}

	params := spec.ToARMParameters()

	// Should have Log Analytics params.
	assert.Equal(t, "log-minimal", params["logAnalyticsName"].(map[string]interface{})["value"])

	// Should NOT have optional params.
	assert.Nil(t, params["location"])
	assert.Nil(t, params["resourceGroupName"])
	assert.Nil(t, params["automationAccountName"])
	assert.Nil(t, params["dataCollectionRules"])
	assert.Nil(t, params["managedIdentities"])
	assert.Nil(t, params["tags"])
}

func TestLogAnalyticsConfig_ValidSKUs(t *testing.T) {
	validSKUs := []string{"PerGB2018", "CapacityReservation", "Free", "Standalone"}

	for _, sku := range validSKUs {
		t.Run(sku, func(t *testing.T) {
			spec := &ManagementSpec{
				LogAnalytics: LogAnalyticsConfig{
					Name:          "log-test",
					RetentionDays: 30,
					SKU:           sku,
				},
			}

			err := spec.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestBaseSpec_GetDependsOn(t *testing.T) {
	spec := &ManagementSpec{
		BaseSpec: BaseSpec{
			DependsOn: []string{"hub-network", "log-analytics"},
		},
		LogAnalytics: LogAnalyticsConfig{
			Name:          "log-test",
			RetentionDays: 30,
			SKU:           "Free",
		},
	}

	deps := spec.GetDependsOn()
	assert.Equal(t, []string{"hub-network", "log-analytics"}, deps)
}
