// Package specs provides a generic spec model that passes through to AVM.
//
// Design Philosophy:
// - We "trust" Azure Verified Modules (AVM) for parameter validation
// - Specs are generic YAML → ARM parameters pass-through
// - No duplication of AVM's type definitions in Go
// - ARM/Bicep validates at deployment time
//
// SECURITY: File size limits prevent DoS. Unknown fields pass through
// to AVM which validates at deployment time.
package specs

// Spec is the interface for all domain specifications.
// Implementations wrap generic map[string]interface{} and pass through to AVM.
type Spec interface {
	// Validate performs basic structural validation.
	// Detailed validation is deferred to AVM/ARM at deployment time.
	Validate() error

	// ToARMParameters returns the spec as ARM template parameters.
	ToARMParameters() map[string]interface{}

	// GetDependsOn returns the list of domain dependencies.
	GetDependsOn() []string

	// GetOperator returns the operator domain name.
	GetOperator() string
}

// GenericSpec is a pass-through spec that forwards YAML to AVM parameters.
// No domain-specific type definitions - AVM handles validation.
type GenericSpec struct {
	// Operator is the operator domain name.
	Operator string `yaml:"-"`

	// Location is the Azure region.
	Location string `yaml:"location,omitempty"`

	// ResourceGroupName is the target resource group.
	ResourceGroupName string `yaml:"resourceGroupName,omitempty"`

	// Tags are Azure resource tags.
	Tags map[string]string `yaml:"tags,omitempty"`

	// DependsOn lists domains that must deploy first.
	DependsOn []string `yaml:"dependsOn,omitempty"`

	// Parameters contains all domain-specific parameters.
	// These are passed directly to AVM without Go-side validation.
	Parameters map[string]interface{} `yaml:",inline"`
}

// Validate performs basic structural validation.
// Detailed parameter validation is deferred to AVM at deployment time.
func (s *GenericSpec) Validate() error {
	// Minimal validation - AVM does the heavy lifting
	return nil
}

// ToARMParameters converts the spec to ARM template parameters.
// All parameters are passed through to AVM.
func (s *GenericSpec) ToARMParameters() map[string]interface{} {
	params := make(map[string]interface{})

	// Copy base fields.
	if s.Location != "" {
		params["location"] = armParam(s.Location)
	}
	if s.ResourceGroupName != "" {
		params["resourceGroupName"] = armParam(s.ResourceGroupName)
	}
	if len(s.Tags) > 0 {
		params["tags"] = armParam(s.Tags)
	}

	// Pass through all other parameters to AVM.
	for k, v := range s.Parameters {
		// Skip fields we've already handled.
		if k == "location" || k == "resourceGroupName" || k == "tags" || k == "dependsOn" {
			continue
		}
		params[k] = armParam(v)
	}

	return params
}

// GetDependsOn returns the dependency list.
func (s *GenericSpec) GetDependsOn() []string {
	return s.DependsOn
}

// GetOperator returns the operator domain name.
func (s *GenericSpec) GetOperator() string {
	return s.Operator
}

// armParam wraps a value in ARM parameter format.
func armParam(value interface{}) map[string]interface{} {
	return map[string]interface{}{
		"value": value,
	}
}
