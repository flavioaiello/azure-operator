package validate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Test constants to avoid literal duplication.
const (
	testSpecFilename = "test.yaml"
	testVNetFilename = "vnet.yaml"
)

func TestNewValidator(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)
	assert.NotNil(t, v)
}

func TestValidateSpecFileValid(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, testSpecFilename)

	content := `apiVersion: v1
kind: VirtualNetwork
metadata:
  name: test-vnet
spec:
  addressSpace:
    - 10.0.0.0/16`

	err := os.WriteFile(specPath, []byte(content), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	result, err := v.ValidateSpecFile(context.Background(), specPath)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)
}

func TestValidateSpecFileMissingFields(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, testSpecFilename)

	content := `kind: VirtualNetwork`

	err := os.WriteFile(specPath, []byte(content), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	result, err := v.ValidateSpecFile(context.Background(), specPath)
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.NotEmpty(t, result.Errors)
}

func TestValidateSpecFileInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, testSpecFilename)

	content := `invalid: yaml: content:`

	err := os.WriteFile(specPath, []byte(content), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	result, err := v.ValidateSpecFile(context.Background(), specPath)
	require.NoError(t, err)
	assert.False(t, result.Valid)
}

func TestValidateSpecDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create valid spec.
	spec1 := `apiVersion: v1
kind: VirtualNetwork
metadata:
  name: vnet1
spec:
  addressSpace: ["10.0.0.0/16"]`
	err := os.WriteFile(filepath.Join(dir, testVNetFilename), []byte(spec1), 0o644)
	require.NoError(t, err)

	// Create invalid spec.
	spec2 := `kind: Subnet`
	err = os.WriteFile(filepath.Join(dir, "subnet.yaml"), []byte(spec2), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	results, err := v.ValidateSpecDirectory(context.Background(), dir)
	require.NoError(t, err)
	assert.Len(t, results, 2)

	// One valid, one invalid.
	validCount := 0
	for _, r := range results {
		if r.Valid {
			validCount++
		}
	}
	assert.Equal(t, 1, validCount)
}

func TestValidateTemplateARM(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "template.json")

	content := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": []
}`

	err := os.WriteFile(templatePath, []byte(content), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	result, err := v.ValidateTemplate(context.Background(), templatePath)
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestValidateTemplateARMMissingSchema(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "template.json")

	content := `{
  "contentVersion": "1.0.0.0",
  "resources": []
}`

	err := os.WriteFile(templatePath, []byte(content), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	result, err := v.ValidateTemplate(context.Background(), templatePath)
	require.NoError(t, err)
	assert.False(t, result.Valid)
}

func TestValidateTemplateBicep(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "main.bicep")

	content := `param location string = resourceGroup().location
resource vnet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
  name: 'test-vnet'
  location: location
}`

	err := os.WriteFile(templatePath, []byte(content), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	result, err := v.ValidateTemplate(context.Background(), templatePath)
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestCompareSpecs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Same spec in both.
	spec := `apiVersion: v1
kind: VirtualNetwork
metadata:
  name: vnet1
spec:
  addressSpace: ["10.0.0.0/16"]`
	err := os.WriteFile(filepath.Join(dir1, testVNetFilename), []byte(spec), 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir2, testVNetFilename), []byte(spec), 0o644)
	require.NoError(t, err)

	// Extra spec in dir1.
	extraSpec := `apiVersion: v1
kind: Subnet
metadata:
  name: subnet1
spec:
  addressPrefix: "10.0.1.0/24"`
	err = os.WriteFile(filepath.Join(dir1, "subnet.yaml"), []byte(extraSpec), 0o644)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	v := NewValidator(logger)

	differences, err := v.CompareSpecs(context.Background(), dir1, dir2)
	require.NoError(t, err)
	// Should find the missing subnet.yaml in dir2.
	assert.NotEmpty(t, differences)
}

func TestDiffTypes(t *testing.T) {
	assert.Equal(t, DiffType("missing"), DiffTypeMissing)
	assert.Equal(t, DiffType("extra"), DiffTypeExtra)
	assert.Equal(t, DiffType("field-missing"), DiffTypeFieldMissing)
	assert.Equal(t, DiffType("field-extra"), DiffTypeFieldExtra)
	assert.Equal(t, DiffType("value-change"), DiffTypeValueChange)
}

func TestErrors(t *testing.T) {
	assert.NotNil(t, ErrInvalidSpec)
	assert.NotNil(t, ErrMissingField)
	assert.NotNil(t, ErrInvalidFieldType)
	assert.NotNil(t, ErrSchemaViolation)
}

func TestIsYAMLFile(t *testing.T) {
	assert.True(t, isYAMLFile(testSpecFilename))
	assert.True(t, isYAMLFile("test.yml"))
	assert.True(t, isYAMLFile("test.YAML"))
	assert.True(t, isYAMLFile("test.YML"))
	assert.False(t, isYAMLFile("test.json"))
	assert.False(t, isYAMLFile("test.bicep"))
}
