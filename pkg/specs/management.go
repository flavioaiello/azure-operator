package specs

// ManagementSpec represents the management domain specification.
type ManagementSpec struct {
	BaseSpec `yaml:",inline"`

	// Operator is the operator domain name (set by loader).
	Operator string `yaml:"-"`
	// LogAnalytics is the Log Analytics workspace configuration.
	LogAnalytics LogAnalyticsConfig `yaml:"logAnalytics" validate:"required"`
	// Automation is the optional Automation account configuration.
	Automation *AutomationConfig `yaml:"automation,omitempty"`
	// DataCollectionRules are the DCR configurations.
	DataCollectionRules []DataCollectionRuleConfig `yaml:"dataCollectionRules"`
	// ManagedIdentities are the managed identity configurations.
	ManagedIdentities []ManagedIdentityConfig `yaml:"managedIdentities"`
}

// LogAnalyticsConfig represents Log Analytics workspace configuration.
type LogAnalyticsConfig struct {
	// Name is the workspace name.
	Name string `yaml:"name" validate:"required,min=1,max=63"`
	// RetentionDays is the data retention period.
	RetentionDays int `yaml:"retentionDays" validate:"required,min=30,max=730"`
	// SKU is the pricing tier.
	SKU string `yaml:"sku" validate:"required,la_sku"`
}

// AutomationConfig represents Automation account configuration.
type AutomationConfig struct {
	// Name is the automation account name.
	Name string `yaml:"name" validate:"required,min=1,max=50"`
}

// DataCollectionRuleConfig represents a data collection rule.
type DataCollectionRuleConfig struct {
	// Name is the DCR name.
	Name string `yaml:"name" validate:"required,min=1"`
	// Description is an optional description.
	Description string `yaml:"description,omitempty"`
	// Kind is the DCR kind.
	Kind string `yaml:"kind,omitempty"`
	// Streams are the data streams.
	Streams []string `yaml:"streams"`
	// Destinations are the data destinations.
	Destinations interface{} `yaml:"destinations,omitempty"`
	// DataSources are the data sources.
	DataSources interface{} `yaml:"dataSources,omitempty"`
	// DataFlows are the data flows.
	DataFlows []interface{} `yaml:"dataFlows,omitempty"`
}

// ManagedIdentityConfig represents a managed identity.
type ManagedIdentityConfig struct {
	// Name is the identity name.
	Name string `yaml:"name" validate:"required,min=1"`
	// Description is an optional description.
	Description string `yaml:"description,omitempty"`
}

// Validate validates the management spec.
func (s *ManagementSpec) Validate() error {
	if err := validate.Struct(s); err != nil {
		return WrapValidationErrors(err)
	}
	return nil
}

// ToARMParameters converts the spec to ARM template parameters.
func (s *ManagementSpec) ToARMParameters() map[string]interface{} {
	params := make(map[string]interface{})

	if s.Location != "" {
		params["location"] = map[string]interface{}{"value": s.Location}
	}
	if s.ResourceGroupName != "" {
		params["resourceGroupName"] = map[string]interface{}{"value": s.ResourceGroupName}
	}

	// Log Analytics.
	params["logAnalyticsName"] = map[string]interface{}{"value": s.LogAnalytics.Name}
	params["logAnalyticsRetentionDays"] = map[string]interface{}{"value": s.LogAnalytics.RetentionDays}
	params["logAnalyticsSku"] = map[string]interface{}{"value": s.LogAnalytics.SKU}

	// Automation.
	if s.Automation != nil {
		params["automationAccountName"] = map[string]interface{}{"value": s.Automation.Name}
	}

	// Data Collection Rules.
	if len(s.DataCollectionRules) > 0 {
		dcrs := make([]map[string]interface{}, len(s.DataCollectionRules))
		for i, dcr := range s.DataCollectionRules {
			dcrs[i] = map[string]interface{}{
				"name":        dcr.Name,
				"description": dcr.Description,
				"streams":     dcr.Streams,
			}
		}
		params["dataCollectionRules"] = map[string]interface{}{"value": dcrs}
	}

	// Managed Identities.
	if len(s.ManagedIdentities) > 0 {
		identities := make([]map[string]interface{}, len(s.ManagedIdentities))
		for i, mi := range s.ManagedIdentities {
			identities[i] = map[string]interface{}{
				"name":        mi.Name,
				"description": mi.Description,
			}
		}
		params["managedIdentities"] = map[string]interface{}{"value": identities}
	}

	// Tags.
	if len(s.Tags) > 0 {
		params["tags"] = map[string]interface{}{"value": s.Tags}
	}

	return params
}

// GetDependsOn returns the dependency list.
func (s *ManagementSpec) GetDependsOn() []string {
	return s.DependsOn
}

// GetOperator returns the operator domain name.
func (s *ManagementSpec) GetOperator() string {
	return s.Operator
}
