// Package specs provides domain specification models with validation.
//
// These models provide:
//  1. Type-safe YAML parsing via struct tags
//  2. Validation at the boundary (fail fast, fail loudly)
//  3. Clean transformation to ARM parameters
//
// SECURITY: All spec parsing uses strict validation.
// Unknown fields are rejected to prevent injection.
package specs

import (
	"fmt"
	"regexp"

	"github.com/go-playground/validator/v10"
)

// Validation patterns.
var (
	domainPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}[a-z0-9]$`)
	locationPattern = regexp.MustCompile(`^[a-z]{2,}[a-z0-9]*$`)
)

// validate is the singleton validator instance.
var validate *validator.Validate

func init() {
	validate = validator.New()
	registerCustomValidators(validate)
}

// registerCustomValidators registers custom validation functions.
func registerCustomValidators(v *validator.Validate) {
	// Domain name validation.
	_ = v.RegisterValidation("domain", func(fl validator.FieldLevel) bool {
		return domainPattern.MatchString(fl.Field().String())
	})

	// Azure location validation.
	_ = v.RegisterValidation("location", func(fl validator.FieldLevel) bool {
		return locationPattern.MatchString(fl.Field().String())
	})

	// Log Analytics SKU validation.
	_ = v.RegisterValidation("la_sku", func(fl validator.FieldLevel) bool {
		validSKUs := map[string]bool{
			"PerGB2018":           true,
			"CapacityReservation": true,
			"Free":                true,
			"Standalone":          true,
		}
		return validSKUs[fl.Field().String()]
	})

	// CIDR notation validation.
	_ = v.RegisterValidation("cidr", func(fl validator.FieldLevel) bool {
		return isValidCIDR(fl.Field().String())
	})
}

// Spec is the interface for all domain specifications.
type Spec interface {
	// Validate validates the spec using the registered validators.
	Validate() error
	// ToARMParameters converts the spec to ARM template parameters.
	ToARMParameters() map[string]interface{}
	// GetDependsOn returns the list of domain dependencies.
	GetDependsOn() []string
	// GetOperator returns the operator domain name.
	GetOperator() string
}

// BaseSpec contains common fields for all specs.
type BaseSpec struct {
	// Location is the Azure region.
	Location string `yaml:"location" validate:"omitempty,location"`
	// ResourceGroupName is the target resource group.
	ResourceGroupName string `yaml:"resourceGroupName" validate:"omitempty,max=90"`
	// Tags are Azure resource tags.
	Tags map[string]string `yaml:"tags"`
	// DependsOn lists domains that must deploy first.
	DependsOn []string `yaml:"dependsOn"`
	// ModeConfig allows per-resource mode overrides.
	ModeConfig *ModeConfig `yaml:"modeConfig,omitempty"`
}

// Validate validates the base spec.
func (s *BaseSpec) Validate() error {
	return validate.Struct(s)
}

// GetDependsOn returns the dependency list.
func (s *BaseSpec) GetDependsOn() []string {
	return s.DependsOn
}

// ModeConfig allows per-resource mode overrides.
type ModeConfig struct {
	// DefaultMode is the default reconciliation mode for this spec.
	DefaultMode string `yaml:"defaultMode" validate:"omitempty,oneof=observe enforce protect"`
	// Overrides specify mode for specific resource types.
	Overrides []ModeOverride `yaml:"overrides"`
}

// ModeOverride specifies mode for specific resource types.
type ModeOverride struct {
	// ResourceTypes are the resource types to match.
	ResourceTypes []string `yaml:"resourceTypes" validate:"required,min=1"`
	// Mode is the reconciliation mode for these types.
	Mode string `yaml:"mode" validate:"required,oneof=observe enforce protect"`
}

// ValidationError wraps validation errors with context.
type ValidationError struct {
	Field   string
	Tag     string
	Value   interface{}
	Message string
}

// Error returns the error message.
func (e ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s': %s (value: %v)",
		e.Field, e.Message, e.Value)
}

// WrapValidationErrors converts validator.ValidationErrors to a readable error.
func WrapValidationErrors(err error) error {
	if err == nil {
		return nil
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return err
	}

	if len(validationErrors) == 0 {
		return nil
	}

	// Return the first validation error for clarity.
	fe := validationErrors[0]
	return ValidationError{
		Field:   fe.Field(),
		Tag:     fe.Tag(),
		Value:   fe.Value(),
		Message: formatValidationMessage(fe),
	}
}

// formatValidationMessage creates a human-readable validation message.
func formatValidationMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "this field is required"
	case "min":
		return fmt.Sprintf("must be at least %s", fe.Param())
	case "max":
		return fmt.Sprintf("must be at most %s", fe.Param())
	case "oneof":
		return fmt.Sprintf("must be one of: %s", fe.Param())
	case "domain":
		return "must be a valid domain name (lowercase alphanumeric with hyphens)"
	case "location":
		return "must be a valid Azure location (lowercase alphanumeric)"
	case "la_sku":
		return "must be a valid Log Analytics SKU"
	case "cidr":
		return "must be a valid CIDR notation (e.g., 10.0.0.0/16)"
	default:
		return fmt.Sprintf("failed validation '%s'", fe.Tag())
	}
}

// isValidCIDR validates CIDR notation.
func isValidCIDR(cidr string) bool {
	if cidr == "" {
		return false
	}

	// Simple CIDR validation pattern.
	// Format: x.x.x.x/y where x is 0-255 and y is 0-32.
	cidrPattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$`)
	if !cidrPattern.MatchString(cidr) {
		return false
	}

	// Parse the parts.
	var a, b, c, d, prefix int
	_, err := fmt.Sscanf(cidr, "%d.%d.%d.%d/%d", &a, &b, &c, &d, &prefix)
	if err != nil {
		return false
	}

	// Validate octet ranges.
	if a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255 {
		return false
	}

	// Validate prefix length.
	if prefix < 0 || prefix > 32 {
		return false
	}

	return true
}
