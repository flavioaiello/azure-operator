// Package loader provides spec and template loading.
//
// Design Philosophy:
// - Specs are generic YAML that passes through to AVM
// - No domain-specific parsing - AVM validates at deployment time
// - Simple file loading with size limits for security
//
// SECURITY: All file operations enforce size limits to prevent DoS attacks.
package loader

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/flavioaiello/azure-operator/pkg/specs"
)

// File size limits.
const (
	// MaxSpecFileSizeBytes is the maximum size of a spec file (1MB).
	MaxSpecFileSizeBytes = 1 * 1024 * 1024
	// MaxTemplateFileSizeBytes is the maximum size of a template file (10MB).
	MaxTemplateFileSizeBytes = 10 * 1024 * 1024
)

// Errors.
var (
	ErrSpecNotFound     = errors.New("spec file not found")
	ErrSpecTooLarge     = errors.New("spec file exceeds maximum size")
	ErrTemplateNotFound = errors.New("template file not found")
	ErrTemplateTooLarge = errors.New("template file exceeds maximum size")
	ErrInvalidYAML      = errors.New("invalid YAML syntax")
	ErrInvalidJSON      = errors.New("invalid JSON syntax")
)

// OperatorToTemplate maps operator names to template directories.
var OperatorToTemplate = map[string]string{
	// Bootstrap operator.
	"bootstrap": "identity",

	// Connectivity operators.
	"firewall":     "connectivity",
	"vpn-gateway":  "connectivity",
	"expressroute": "connectivity",
	"bastion":      "connectivity",
	"dns":          "connectivity",
	"hub-network":  "connectivity",

	// vWAN operators.
	"vwan":              "connectivity",
	"vwan-hub":          "connectivity",
	"vwan-firewall":     "connectivity",
	"vwan-vpn-gateway":  "connectivity",
	"vwan-expressroute": "connectivity",

	// Management operators.
	"log-analytics": "management",
	"automation":    "management",
	"monitor":       "management",

	// Security operators.
	"defender": "security",
	"keyvault": "security",
	"sentinel": "security",

	// Governance operators.
	"management-group": "identity",
	"policy":           "identity",
	"role":             "identity",

	// Secondary region operators.
	"bastion-secondary":           "connectivity",
	"firewall-secondary":          "connectivity",
	"hub-network-secondary":       "connectivity",
	"vpn-gateway-secondary":       "connectivity",
	"expressroute-secondary":      "connectivity",
	"dns-secondary":               "connectivity",
	"vwan-hub-secondary":          "connectivity",
	"vwan-firewall-secondary":     "connectivity",
	"vwan-vpn-gateway-secondary":  "connectivity",
	"vwan-expressroute-secondary": "connectivity",
}

// Loader handles spec and template loading.
type Loader struct {
	specsDir     string
	templatesDir string
}

// New creates a new Loader.
func New(specsDir, templatesDir string) *Loader {
	return &Loader{
		specsDir:     specsDir,
		templatesDir: templatesDir,
	}
}

// GetTemplateDir returns the template directory for an operator.
func GetTemplateDir(operator string) string {
	if dir, ok := OperatorToTemplate[operator]; ok {
		return dir
	}
	// Default to operator name as directory.
	return operator
}

// LoadSpec loads a spec from YAML and returns a generic spec.
// All parameters pass through to AVM - no domain-specific validation.
func (l *Loader) LoadSpec(domain string) (specs.Spec, error) {
	specPath := filepath.Join(l.specsDir, domain+".yaml")

	// Check file exists and size.
	info, err := os.Stat(specPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrSpecNotFound, specPath)
		}
		return nil, fmt.Errorf("failed to stat spec file: %w", err)
	}

	// SECURITY: Check file size before reading.
	if info.Size() > MaxSpecFileSizeBytes {
		return nil, fmt.Errorf("%w: %s (%d bytes, max %d)",
			ErrSpecTooLarge, specPath, info.Size(), MaxSpecFileSizeBytes)
	}

	// Read file with limit.
	file, err := os.Open(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, MaxSpecFileSizeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}

	// Parse YAML.
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidYAML, specPath, err)
	}

	// Handle Kubernetes-style wrapper (apiVersion/kind/metadata/spec).
	specData := raw
	if _, hasAPIVersion := raw["apiVersion"]; hasAPIVersion {
		if specSection, ok := raw["spec"].(map[string]interface{}); ok {
			specData = specSection
		}
	}

	// Create generic spec - passes through to AVM.
	spec := &specs.GenericSpec{
		Operator:   domain,
		Parameters: make(map[string]interface{}),
	}

	// Extract known fields, rest goes to Parameters.
	for k, v := range specData {
		switch k {
		case "location":
			if s, ok := v.(string); ok {
				spec.Location = s
			}
		case "resourceGroupName":
			if s, ok := v.(string); ok {
				spec.ResourceGroupName = s
			}
		case "tags":
			if m, ok := v.(map[string]interface{}); ok {
				spec.Tags = make(map[string]string)
				for tk, tv := range m {
					if ts, ok := tv.(string); ok {
						spec.Tags[tk] = ts
					}
				}
			}
		case "dependsOn":
			if arr, ok := v.([]interface{}); ok {
				for _, item := range arr {
					if s, ok := item.(string); ok {
						spec.DependsOn = append(spec.DependsOn, s)
					}
				}
			}
		default:
			// Pass through to AVM.
			spec.Parameters[k] = v
		}
	}

	return spec, nil
}

// LoadTemplate loads an ARM template from JSON.
func (l *Loader) LoadTemplate(domain string) (map[string]interface{}, error) {
	templateDir := GetTemplateDir(domain)
	templatePath := filepath.Join(l.templatesDir, templateDir, "main.json")

	// Check file exists and size.
	info, err := os.Stat(templatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrTemplateNotFound, templatePath)
		}
		return nil, fmt.Errorf("failed to stat template file: %w", err)
	}

	// SECURITY: Check file size before reading.
	if info.Size() > MaxTemplateFileSizeBytes {
		return nil, fmt.Errorf("%w: %s (%d bytes, max %d)",
			ErrTemplateTooLarge, templatePath, info.Size(), MaxTemplateFileSizeBytes)
	}

	// Read file.
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	// Parse JSON.
	var template map[string]interface{}
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidJSON, templatePath, err)
	}

	return template, nil
}
