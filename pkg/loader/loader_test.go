package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTemplateForOperator(t *testing.T) {
	tests := []struct {
		operator string
		expected string
		wantErr  bool
	}{
		{"firewall", "connectivity", false},
		{"bastion", "connectivity", false},
		{"hub-network", "connectivity", false},
		{"log-analytics", "management", false},
		{"automation", "management", false},
		{"defender", "security", false},
		{"keyvault", "security", false},
		{"bootstrap", "identity", false},
		{"policy", "identity", false},
		{"firewall-secondary", "connectivity", false},
		{"unknown-operator", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.operator, func(t *testing.T) {
			template, err := GetTemplateForOperator(tt.operator)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrUnknownDomain)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, template)
			}
		})
	}
}

func TestLoader_LoadSpec_Valid(t *testing.T) {
	// Create temp directory with spec file.
	tempDir := t.TempDir()

	specContent := `
logAnalytics:
  name: log-test
  retentionDays: 365
  sku: PerGB2018
location: westeurope
resourceGroupName: rg-test
tags:
  environment: test
`
	specPath := filepath.Join(tempDir, "management.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(specContent), 0644))

	loader := New(tempDir, tempDir, nil)
	spec, err := loader.LoadSpec("management")
	require.NoError(t, err)
	assert.NotNil(t, spec)

	params := spec.ToARMParameters()
	assert.Equal(t, "log-test", params["logAnalyticsName"].(map[string]interface{})["value"])
	assert.Equal(t, "westeurope", params["location"].(map[string]interface{})["value"])
}

func TestLoader_LoadSpec_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	loader := New(tempDir, tempDir, nil)

	_, err := loader.LoadSpec("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSpecNotFound)
}

func TestLoader_LoadSpec_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()

	invalidYAML := `
logAnalytics:
  name: [invalid yaml
`
	specPath := filepath.Join(tempDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(invalidYAML), 0644))

	loader := New(tempDir, tempDir, nil)
	_, err := loader.LoadSpec("invalid")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidYAML)
}

func TestLoader_LoadSpec_TooLarge(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file larger than max size.
	largeContent := make([]byte, 2*1024*1024) // 2MB
	specPath := filepath.Join(tempDir, "large.yaml")
	require.NoError(t, os.WriteFile(specPath, largeContent, 0644))

	loader := New(tempDir, tempDir, nil)
	_, err := loader.LoadSpec("large")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSpecTooLarge)
}

func TestLoader_LoadSpec_KubernetesStyle(t *testing.T) {
	tempDir := t.TempDir()

	k8sStyle := `
apiVersion: azure-operator.io/v1alpha1
kind: ManagementSpec
metadata:
  name: management
spec:
  logAnalytics:
    name: log-k8s-style
    retentionDays: 90
    sku: Free
  location: eastus
`
	specPath := filepath.Join(tempDir, "management.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(k8sStyle), 0644))

	loader := New(tempDir, tempDir, nil)
	spec, err := loader.LoadSpec("management")
	require.NoError(t, err)
	assert.NotNil(t, spec)

	params := spec.ToARMParameters()
	assert.Equal(t, "log-k8s-style", params["logAnalyticsName"].(map[string]interface{})["value"])
	assert.Equal(t, "eastus", params["location"].(map[string]interface{})["value"])
}

func TestLoader_LoadSpec_ValidationFailure(t *testing.T) {
	tempDir := t.TempDir()

	// Invalid: retention days below minimum.
	invalidSpec := `
logAnalytics:
  name: log-test
  retentionDays: 10
  sku: PerGB2018
`
	specPath := filepath.Join(tempDir, "invalid-validation.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(invalidSpec), 0644))

	loader := New(tempDir, tempDir, nil)
	_, err := loader.LoadSpec("invalid-validation")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestLoader_LoadTemplate_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	loader := New(tempDir, tempDir, nil)

	_, err := loader.LoadTemplate("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTemplateNotFound)
}

func TestLoader_LoadTemplate_Valid(t *testing.T) {
	tempDir := t.TempDir()

	// Create template directory and file.
	templateDir := filepath.Join(tempDir, "management")
	require.NoError(t, os.MkdirAll(templateDir, 0755))

	templateContent := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": []
}`
	templatePath := filepath.Join(templateDir, "main.json")
	require.NoError(t, os.WriteFile(templatePath, []byte(templateContent), 0644))

	loader := New(tempDir, tempDir, nil)
	template, err := loader.LoadTemplate("management")
	require.NoError(t, err)
	assert.NotNil(t, template)
	assert.Equal(t, "1.0.0.0", template["contentVersion"])
}

func TestOperatorToTemplate_Complete(t *testing.T) {
	// Verify key operators are mapped.
	expectedMappings := map[string]string{
		"bootstrap":     "identity",
		"firewall":      "connectivity",
		"log-analytics": "management",
		"defender":      "security",
		"policy":        "identity",
	}

	for operator, expectedTemplate := range expectedMappings {
		t.Run(operator, func(t *testing.T) {
			template, ok := OperatorToTemplate[operator]
			assert.True(t, ok, "operator %s should be mapped", operator)
			assert.Equal(t, expectedTemplate, template)
		})
	}
}
