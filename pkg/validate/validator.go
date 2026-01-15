// Package validate provides validation utilities for migration.
//
// Features:
//  1. Spec compatibility validation
//  2. Template validation
//  3. Configuration drift detection between implementations
package validate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Errors.
var (
	ErrInvalidSpec      = errors.New("invalid spec")
	ErrMissingField     = errors.New("missing required field")
	ErrInvalidFieldType = errors.New("invalid field type")
	ErrSchemaViolation  = errors.New("schema violation")
)

// ValidationResult represents the outcome of validation.
type ValidationResult struct {
	Valid    bool              `json:"valid"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Warnings []ValidationError `json:"warnings,omitempty"`
	FilePath string            `json:"filePath,omitempty"`
}

// ValidationError represents a single validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
}

// Validator validates specs and templates.
type Validator struct {
	logger *zap.Logger
}

// NewValidator creates a new validator.
func NewValidator(logger *zap.Logger) *Validator {
	return &Validator{
		logger: logger,
	}
}

// ValidateSpecFile validates a single spec file.
func (v *Validator) ValidateSpecFile(_ context.Context, filePath string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		FilePath: filePath,
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse YAML.
	var spec map[string]interface{}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Message: fmt.Sprintf("YAML parse error: %v", err),
		})
		return result, nil
	}

	// Validate required fields.
	requiredFields := []string{"apiVersion", "kind", "metadata"}
	for _, field := range requiredFields {
		if _, ok := spec[field]; !ok {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   field,
				Message: fmt.Sprintf("missing required field: %s", field),
			})
		}
	}

	// Validate metadata.
	if metadata, ok := spec["metadata"].(map[string]interface{}); ok {
		if _, ok := metadata["name"]; !ok {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   "metadata.name",
				Message: "missing required field: metadata.name",
			})
		}
	}

	// Validate spec field.
	if _, ok := spec["spec"]; !ok {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "spec",
			Message: "missing required field: spec",
		})
	}

	return result, nil
}

// ValidateSpecDirectory validates all specs in a directory.
func (v *Validator) ValidateSpecDirectory(ctx context.Context, dir string) ([]*ValidationResult, error) {
	var results []*ValidationResult

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		if !isYAMLFile(path) {
			return nil
		}

		result, err := v.ValidateSpecFile(ctx, path)
		if err != nil {
			v.logger.Warn("Failed to validate file",
				zap.String("path", path),
				zap.Error(err),
			)
			return nil
		}

		results = append(results, result)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return results, nil
}

// ValidateTemplate validates a Bicep/ARM template.
func (v *Validator) ValidateTemplate(_ context.Context, filePath string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		FilePath: filePath,
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".json":
		return v.validateARMTemplate(data, result)
	case ".bicep":
		return v.validateBicepTemplate(data, result)
	default:
		result.Warnings = append(result.Warnings, ValidationError{
			Message: fmt.Sprintf("unknown template type: %s", ext),
		})
	}

	return result, nil
}

func (v *Validator) validateARMTemplate(data []byte, result *ValidationResult) (*ValidationResult, error) {
	var template map[string]interface{}
	if err := json.Unmarshal(data, &template); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Message: fmt.Sprintf("JSON parse error: %v", err),
		})
		return result, nil
	}

	// Check required ARM template fields.
	if _, ok := template["$schema"]; !ok {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "$schema",
			Message: "missing required field: $schema",
		})
	}

	if _, ok := template["contentVersion"]; !ok {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "contentVersion",
			Message: "missing required field: contentVersion",
		})
	}

	if _, ok := template["resources"]; !ok {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "resources",
			Message: "no resources defined in template",
		})
	}

	return result, nil
}

func (v *Validator) validateBicepTemplate(data []byte, result *ValidationResult) (*ValidationResult, error) {
	// Basic Bicep validation.
	content := string(data)

	if len(strings.TrimSpace(content)) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Message: "empty Bicep template",
		})
		return result, nil
	}

	// Check for common Bicep patterns.
	if !strings.Contains(content, "param") && !strings.Contains(content, "resource") && !strings.Contains(content, "module") {
		result.Warnings = append(result.Warnings, ValidationError{
			Message: "template has no params, resources, or modules",
		})
	}

	return result, nil
}

// CompareSpecs compares specs from two directories.
func (v *Validator) CompareSpecs(ctx context.Context, dir1, dir2 string) ([]SpecDifference, error) {
	specs1, err := v.loadSpecs(ctx, dir1)
	if err != nil {
		return nil, fmt.Errorf("failed to load specs from %s: %w", dir1, err)
	}

	specs2, err := v.loadSpecs(ctx, dir2)
	if err != nil {
		return nil, fmt.Errorf("failed to load specs from %s: %w", dir2, err)
	}

	var differences []SpecDifference

	// Find specs in dir1 but not in dir2.
	for name := range specs1 {
		if _, ok := specs2[name]; !ok {
			differences = append(differences, SpecDifference{
				SpecName: name,
				Type:     DiffTypeMissing,
				Message:  fmt.Sprintf("spec exists in %s but not in %s", dir1, dir2),
			})
		}
	}

	// Find specs in dir2 but not in dir1.
	for name := range specs2 {
		if _, ok := specs1[name]; !ok {
			differences = append(differences, SpecDifference{
				SpecName: name,
				Type:     DiffTypeExtra,
				Message:  fmt.Sprintf("spec exists in %s but not in %s", dir2, dir1),
			})
		}
	}

	// Compare common specs.
	for name, spec1 := range specs1 {
		if spec2, ok := specs2[name]; ok {
			diffs := v.compareSpec(name, spec1, spec2)
			differences = append(differences, diffs...)
		}
	}

	return differences, nil
}

func (v *Validator) loadSpecs(_ context.Context, dir string) (map[string]map[string]interface{}, error) {
	specs := make(map[string]map[string]interface{})

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !isYAMLFile(path) {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		spec := make(map[string]interface{})
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil
		}

		name := filepath.Base(path)
		specs[name] = spec
		return nil
	})

	if err != nil {
		return nil, err
	}

	return specs, nil
}

func (v *Validator) compareSpec(name string, spec1, spec2 map[string]interface{}) []SpecDifference {
	var differences []SpecDifference

	// Compare top-level keys.
	for key := range spec1 {
		if _, ok := spec2[key]; !ok {
			differences = append(differences, SpecDifference{
				SpecName: name,
				Type:     DiffTypeFieldMissing,
				Field:    key,
				Message:  fmt.Sprintf("field %s missing in second spec", key),
			})
		}
	}

	for key := range spec2 {
		if _, ok := spec1[key]; !ok {
			differences = append(differences, SpecDifference{
				SpecName: name,
				Type:     DiffTypeFieldExtra,
				Field:    key,
				Message:  fmt.Sprintf("field %s missing in first spec", key),
			})
		}
	}

	return differences
}

// SpecDifference represents a difference between specs.
type SpecDifference struct {
	SpecName string   `json:"specName"`
	Type     DiffType `json:"type"`
	Field    string   `json:"field,omitempty"`
	Message  string   `json:"message"`
}

// DiffType categorizes the type of difference.
type DiffType string

const (
	DiffTypeMissing      DiffType = "missing"
	DiffTypeExtra        DiffType = "extra"
	DiffTypeFieldMissing DiffType = "field-missing"
	DiffTypeFieldExtra   DiffType = "field-extra"
	DiffTypeValueChange  DiffType = "value-change"
)

func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
