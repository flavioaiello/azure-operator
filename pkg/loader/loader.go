// Package loader provides spec and template loading with validation.
//
// SECURITY: All file operations enforce size limits to prevent DoS attacks
// via large files. Input validation is performed at the boundary.
package loader

import (
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
	ErrSpecNotFound      = errors.New("spec file not found")
	ErrSpecTooLarge      = errors.New("spec file exceeds maximum size")
	ErrTemplateNotFound  = errors.New("template file not found")
	ErrTemplateTooLarge  = errors.New("template file exceeds maximum size")
	ErrInvalidYAML       = errors.New("invalid YAML syntax")
	ErrUnknownDomain     = errors.New("unknown domain")
	ErrInvalidSpecFormat = errors.New("spec must be a YAML mapping")
)

// OperatorToTemplate maps operator names to template domains.
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
	logger       interface{} // zap.Logger or nil
}

// New creates a new Loader.
func New(specsDir, templatesDir string, logger interface{}) *Loader {
	return &Loader{
		specsDir:     specsDir,
		templatesDir: templatesDir,
		logger:       logger,
	}
}

// GetTemplateForOperator returns the template name for an operator.
func GetTemplateForOperator(operator string) (string, error) {
	template, ok := OperatorToTemplate[operator]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownDomain, operator)
	}
	return template, nil
}

// LoadSpec loads and validates a domain spec from YAML.
func (l *Loader) LoadSpec(domain string) (specs.Spec, error) {
	specPath := filepath.Join(l.specsDir, domain+".yaml")

	// Check file exists.
	info, err := os.Stat(specPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrSpecNotFound, specPath)
		}
		return nil, fmt.Errorf("failed to stat spec file: %w", err)
	}

	// SECURITY: Check file size before reading to prevent DoS.
	if info.Size() > MaxSpecFileSizeBytes {
		return nil, fmt.Errorf("%w: %s (%d bytes, max %d)",
			ErrSpecTooLarge, specPath, info.Size(), MaxSpecFileSizeBytes)
	}

	// Open file.
	file, err := os.Open(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open spec file: %w", err)
	}
	defer file.Close()

	// Read with limit.
	limitedReader := io.LimitReader(file, MaxSpecFileSizeBytes+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read spec file: %w", err)
	}

	// Parse YAML to determine format.
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidYAML, specPath, err)
	}

	if raw == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSpecFormat, specPath)
	}

	// Handle Kubernetes-style wrapper.
	specData := data
	if _, hasAPIVersion := raw["apiVersion"]; hasAPIVersion {
		if specSection, ok := raw["spec"].(map[string]interface{}); ok {
			specData, err = yaml.Marshal(specSection)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal spec section: %w", err)
			}
		}
	}

	// Unmarshal into typed spec.
	spec, err := unmarshalSpec(domain, specData)
	if err != nil {
		return nil, err
	}

	// Validate.
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("spec validation failed: %w", err)
	}

	return spec, nil
}

// LoadTemplate loads an ARM template from JSON.
func (l *Loader) LoadTemplate(domain string) (map[string]interface{}, error) {
	templatePath := filepath.Join(l.templatesDir, domain, "main.json")

	// Check file exists.
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

	// Read template.
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	// Parse JSON as YAML (YAML is a superset of JSON).
	var template map[string]interface{}
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	return template, nil
}

// unmarshalSpec unmarshals YAML data into the appropriate spec type.
func unmarshalSpec(domain string, data []byte) (specs.Spec, error) {
	// Get the base template domain.
	templateDomain, err := GetTemplateForOperator(domain)
	if err != nil {
		// Fall back to using domain as template domain.
		templateDomain = domain
	}

	switch templateDomain {
	case "management":
		var spec specs.ManagementSpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("failed to unmarshal management spec: %w", err)
		}
		spec.Operator = domain
		return &spec, nil

	case "connectivity":
		var spec specs.ConnectivitySpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("failed to unmarshal connectivity spec: %w", err)
		}
		spec.Operator = domain
		return &spec, nil

	case "security":
		var spec specs.SecuritySpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("failed to unmarshal security spec: %w", err)
		}
		spec.Operator = domain
		return &spec, nil

	case "identity":
		// Identity specs for bootstrap, management groups, etc.
		var spec specs.ManagementSpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("failed to unmarshal identity spec: %w", err)
		}
		spec.Operator = domain
		return &spec, nil

	default:
		// For now, return a management spec as default.
		// This will be expanded as more spec types are implemented.
		var spec specs.ManagementSpec
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("failed to unmarshal spec: %w", err)
		}
		spec.Operator = domain
		return &spec, nil
	}
}
