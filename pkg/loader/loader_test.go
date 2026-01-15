package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTemplateDir(t *testing.T) {
	tests := []struct {
		operator string
		expected string
	}{
		{"firewall", "connectivity"},
		{"bastion", "connectivity"},
		{"hub-network", "connectivity"},
		{"log-analytics", "management"},
		{"automation", "management"},
		{"defender", "security"},
		{"keyvault", "security"},
		{"bootstrap", "identity"},
		{"policy", "identity"},
		{"firewall-secondary", "connectivity"},
		{"unknown-operator", "unknown-operator"}, // Falls back to operator name.
	}

	for _, tt := range tests {
		t.Run(tt.operator, func(t *testing.T) {
			result := GetTemplateDir(tt.operator)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoader_LoadSpec_Valid(t *testing.T) {
	tempDir := t.TempDir()

	// Generic spec - passes through to AVM.
	specContent := `
location: westeurope
resourceGroupName: rg-test
tags:
  environment: test
virtualNetwork:
  name: vnet-hub
  addressSpace:
    - "10.0.0.0/16"
firewall:
  enabled: true
  sku: Premium
`
	specPath := filepath.Join(tempDir, "connectivity.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(specContent), 0644))

	loader := New(tempDir, tempDir)
	spec, err := loader.LoadSpec("connectivity")
	require.NoError(t, err)
	assert.NotNil(t, spec)
	assert.Equal(t, "connectivity", spec.GetOperator())

	params := spec.ToARMParameters()
	assert.Equal(t, "westeurope", params["location"].(map[string]interface{})["value"])
	assert.Equal(t, "rg-test", params["resourceGroupName"].(map[string]interface{})["value"])

	// Verify pass-through parameters.
	assert.Contains(t, params, "virtualNetwork")
	assert.Contains(t, params, "firewall")
}

func TestLoader_LoadSpec_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	loader := New(tempDir, tempDir)

	_, err := loader.LoadSpec("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSpecNotFound)
}

func TestLoader_LoadSpec_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()

	invalidYAML := `
virtualNetwork:
  name: [invalid yaml
`
	specPath := filepath.Join(tempDir, "invalid.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(invalidYAML), 0644))

	loader := New(tempDir, tempDir)
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

	loader := New(tempDir, tempDir)
	_, err := loader.LoadSpec("large")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSpecTooLarge)
}

func TestLoader_LoadSpec_KubernetesStyle(t *testing.T) {
	tempDir := t.TempDir()

	// Kubernetes-style wrapper.
	k8sStyle := `
apiVersion: azure-operator/v1
kind: Operator
metadata:
  name: connectivity
spec:
  location: eastus
  resourceGroupName: rg-connectivity
  virtualNetwork:
    name: vnet-hub
    addressSpace:
      - "10.0.0.0/16"
`
	specPath := filepath.Join(tempDir, "connectivity.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(k8sStyle), 0644))

	loader := New(tempDir, tempDir)
	spec, err := loader.LoadSpec("connectivity")
	require.NoError(t, err)
	assert.NotNil(t, spec)

	params := spec.ToARMParameters()
	assert.Equal(t, "eastus", params["location"].(map[string]interface{})["value"])
}

func TestLoader_LoadSpec_DependsOn(t *testing.T) {
	tempDir := t.TempDir()

	specContent := `
location: westeurope
dependsOn:
  - hub-network
  - log-analytics
`
	specPath := filepath.Join(tempDir, "firewall.yaml")
	require.NoError(t, os.WriteFile(specPath, []byte(specContent), 0644))

	loader := New(tempDir, tempDir)
	spec, err := loader.LoadSpec("firewall")
	require.NoError(t, err)

	deps := spec.GetDependsOn()
	assert.Contains(t, deps, "hub-network")
	assert.Contains(t, deps, "log-analytics")
}

func TestLoader_LoadTemplate_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	loader := New(tempDir, tempDir)

	_, err := loader.LoadTemplate("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTemplateNotFound)
}

func TestLoader_LoadTemplate_Valid(t *testing.T) {
	tempDir := t.TempDir()

	// Create template directory and file.
	templateDir := filepath.Join(tempDir, "connectivity")
	require.NoError(t, os.MkdirAll(templateDir, 0755))

	templateContent := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": []
}`
	templatePath := filepath.Join(templateDir, "main.json")
	require.NoError(t, os.WriteFile(templatePath, []byte(templateContent), 0644))

	loader := New(tempDir, tempDir)
	template, err := loader.LoadTemplate("connectivity")
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
