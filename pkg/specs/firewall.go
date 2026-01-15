package specs

// FirewallSpec represents the firewall domain specification.
type FirewallSpec struct {
	BaseSpec `yaml:",inline"`

	// Firewall is the Azure Firewall configuration.
	Firewall AzureFirewallConfig `yaml:"firewall" validate:"required"`
	// FirewallPolicy is the firewall policy configuration.
	FirewallPolicy *FirewallPolicyConfig `yaml:"firewallPolicy,omitempty"`
	// PublicIPAddresses are the public IP configurations.
	PublicIPAddresses []PublicIPConfig `yaml:"publicIpAddresses"`
}

// AzureFirewallConfig represents Azure Firewall configuration.
type AzureFirewallConfig struct {
	// Name is the firewall name.
	Name string `yaml:"name" validate:"required,min=1,max=56"`
	// SKU is the firewall SKU (Standard, Premium, Basic).
	SKU string `yaml:"sku" validate:"required,oneof=Standard Premium Basic"`
	// ThreatIntelMode is the threat intelligence mode.
	ThreatIntelMode string `yaml:"threatIntelMode" validate:"omitempty,oneof=Alert Deny Off"`
	// AvailabilityZones are the availability zones.
	AvailabilityZones []string `yaml:"availabilityZones"`
	// SubnetID is the AzureFirewallSubnet resource ID.
	SubnetID string `yaml:"subnetId,omitempty"`
	// ManagementSubnetID is the AzureFirewallManagementSubnet resource ID.
	ManagementSubnetID string `yaml:"managementSubnetId,omitempty"`
}

// FirewallPolicyConfig represents firewall policy configuration.
type FirewallPolicyConfig struct {
	// Name is the policy name.
	Name string `yaml:"name" validate:"required,min=1,max=56"`
	// BasePolicyID is the parent policy resource ID.
	BasePolicyID string `yaml:"basePolicyId,omitempty"`
	// ThreatIntelMode is the threat intelligence mode.
	ThreatIntelMode string `yaml:"threatIntelMode" validate:"omitempty,oneof=Alert Deny Off"`
	// RuleCollectionGroups are the rule collection groups.
	RuleCollectionGroups []RuleCollectionGroupConfig `yaml:"ruleCollectionGroups"`
}

// RuleCollectionGroupConfig represents a rule collection group.
type RuleCollectionGroupConfig struct {
	// Name is the group name.
	Name string `yaml:"name" validate:"required,min=1"`
	// Priority is the group priority (100-65000).
	Priority int `yaml:"priority" validate:"required,min=100,max=65000"`
	// RuleCollections are the rule collections.
	RuleCollections []RuleCollectionConfig `yaml:"ruleCollections"`
}

// RuleCollectionConfig represents a rule collection.
type RuleCollectionConfig struct {
	// Name is the collection name.
	Name string `yaml:"name" validate:"required,min=1"`
	// Priority is the collection priority.
	Priority int `yaml:"priority" validate:"required,min=100,max=65000"`
	// Action is Allow or Deny.
	Action string `yaml:"action" validate:"required,oneof=Allow Deny"`
	// RuleType is the rule type (Network, Application, NAT).
	RuleType string `yaml:"ruleType" validate:"required,oneof=Network Application NAT"`
	// Rules are the rules (interface for flexibility).
	Rules []interface{} `yaml:"rules"`
}

// PublicIPConfig represents public IP configuration.
type PublicIPConfig struct {
	// Name is the public IP name.
	Name string `yaml:"name" validate:"required,min=1,max=80"`
	// SKU is the SKU (Standard, Basic).
	SKU string `yaml:"sku" validate:"required,oneof=Standard Basic"`
	// AllocationMethod is Static or Dynamic.
	AllocationMethod string `yaml:"allocationMethod" validate:"required,oneof=Static Dynamic"`
	// AvailabilityZones are the zones.
	AvailabilityZones []string `yaml:"availabilityZones"`
}

// Validate validates the firewall spec.
func (s *FirewallSpec) Validate() error {
	if err := validate.Struct(s); err != nil {
		return WrapValidationErrors(err)
	}
	return nil
}

// ToARMParameters converts the spec to ARM template parameters.
func (s *FirewallSpec) ToARMParameters() map[string]interface{} {
	params := make(map[string]interface{})

	if s.Location != "" {
		params["location"] = map[string]interface{}{"value": s.Location}
	}
	if s.ResourceGroupName != "" {
		params["resourceGroupName"] = map[string]interface{}{"value": s.ResourceGroupName}
	}

	// Firewall.
	params["firewallName"] = map[string]interface{}{"value": s.Firewall.Name}
	params["firewallSku"] = map[string]interface{}{"value": s.Firewall.SKU}
	if s.Firewall.ThreatIntelMode != "" {
		params["threatIntelMode"] = map[string]interface{}{"value": s.Firewall.ThreatIntelMode}
	}
	if len(s.Firewall.AvailabilityZones) > 0 {
		params["availabilityZones"] = map[string]interface{}{"value": s.Firewall.AvailabilityZones}
	}

	// Firewall Policy.
	if s.FirewallPolicy != nil {
		params["firewallPolicyName"] = map[string]interface{}{"value": s.FirewallPolicy.Name}
		if s.FirewallPolicy.BasePolicyID != "" {
			params["basePolicyId"] = map[string]interface{}{"value": s.FirewallPolicy.BasePolicyID}
		}
	}

	// Public IPs.
	if len(s.PublicIPAddresses) > 0 {
		pips := make([]map[string]interface{}, len(s.PublicIPAddresses))
		for i, pip := range s.PublicIPAddresses {
			pips[i] = map[string]interface{}{
				"name":              pip.Name,
				"sku":               pip.SKU,
				"allocationMethod":  pip.AllocationMethod,
				"availabilityZones": pip.AvailabilityZones,
			}
		}
		params["publicIpAddresses"] = map[string]interface{}{"value": pips}
	}

	// Tags.
	if len(s.Tags) > 0 {
		params["tags"] = map[string]interface{}{"value": s.Tags}
	}

	return params
}
