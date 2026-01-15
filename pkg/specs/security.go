package specs

// SecuritySpec represents the security domain specification (Defender, KeyVault).
type SecuritySpec struct {
	BaseSpec `yaml:",inline"`

	// Operator is the operator domain name (set by loader).
	Operator string `yaml:"-"`
	// Defender is the Microsoft Defender for Cloud configuration.
	Defender *DefenderConfig `yaml:"defender,omitempty"`
	// KeyVaults are the Key Vault configurations.
	KeyVaults []KeyVaultConfig `yaml:"keyVaults"`
}

// DefenderConfig represents Microsoft Defender for Cloud configuration.
type DefenderConfig struct {
	// EnableAutoProvisioning enables auto-provisioning of agents.
	EnableAutoProvisioning bool `yaml:"enableAutoProvisioning"`
	// Tier is the Defender tier (Free, Standard).
	Tier string `yaml:"tier" validate:"required,oneof=Free Standard"`
	// Plans are the enabled Defender plans.
	Plans []DefenderPlan `yaml:"plans"`
	// SecurityContacts are the security contact configurations.
	SecurityContacts []SecurityContact `yaml:"securityContacts"`
}

// DefenderPlan represents a Defender for Cloud plan.
type DefenderPlan struct {
	// Name is the plan name.
	Name string `yaml:"name" validate:"required"`
	// Tier is Free or Standard.
	Tier string `yaml:"tier" validate:"required,oneof=Free Standard"`
	// SubPlan is an optional sub-plan.
	SubPlan string `yaml:"subPlan,omitempty"`
}

// SecurityContact represents a security contact.
type SecurityContact struct {
	// Email is the contact email.
	Email string `yaml:"email" validate:"required,email"`
	// Phone is the contact phone.
	Phone string `yaml:"phone,omitempty"`
	// AlertNotifications enables alert notifications.
	AlertNotifications bool `yaml:"alertNotifications"`
	// AlertsToAdmins sends alerts to subscription admins.
	AlertsToAdmins bool `yaml:"alertsToAdmins"`
}

// KeyVaultConfig represents Key Vault configuration.
type KeyVaultConfig struct {
	// Name is the Key Vault name.
	Name string `yaml:"name" validate:"required,min=3,max=24"`
	// SKU is the SKU (standard, premium).
	SKU string `yaml:"sku" validate:"required,oneof=standard premium"`
	// EnableSoftDelete enables soft delete.
	EnableSoftDelete bool `yaml:"enableSoftDelete"`
	// SoftDeleteRetentionDays is the retention period (7-90).
	SoftDeleteRetentionDays int `yaml:"softDeleteRetentionDays" validate:"omitempty,min=7,max=90"`
	// EnablePurgeProtection enables purge protection.
	EnablePurgeProtection bool `yaml:"enablePurgeProtection"`
	// EnableRBACAuthorization enables RBAC instead of access policies.
	EnableRBACAuthorization bool `yaml:"enableRbacAuthorization"`
	// NetworkACLs are the network access control rules.
	NetworkACLs *KeyVaultNetworkACLs `yaml:"networkAcls,omitempty"`
}

// KeyVaultNetworkACLs represents network ACLs for Key Vault.
type KeyVaultNetworkACLs struct {
	// DefaultAction is Allow or Deny.
	DefaultAction string `yaml:"defaultAction" validate:"required,oneof=Allow Deny"`
	// Bypass is AzureServices or None.
	Bypass string `yaml:"bypass" validate:"required,oneof=AzureServices None"`
	// IPRules are allowed IP ranges.
	IPRules []string `yaml:"ipRules"`
	// VirtualNetworkRules are allowed VNet subnets.
	VirtualNetworkRules []string `yaml:"virtualNetworkRules"`
}

// Validate validates the security spec.
func (s *SecuritySpec) Validate() error {
	if err := validate.Struct(s); err != nil {
		return WrapValidationErrors(err)
	}
	return nil
}

// ToARMParameters converts the spec to ARM template parameters.
func (s *SecuritySpec) ToARMParameters() map[string]interface{} {
	params := make(map[string]interface{})

	if s.Location != "" {
		params["location"] = map[string]interface{}{"value": s.Location}
	}
	if s.ResourceGroupName != "" {
		params["resourceGroupName"] = map[string]interface{}{"value": s.ResourceGroupName}
	}

	// Defender.
	if s.Defender != nil {
		params["defenderTier"] = map[string]interface{}{"value": s.Defender.Tier}
		params["enableAutoProvisioning"] = map[string]interface{}{"value": s.Defender.EnableAutoProvisioning}

		if len(s.Defender.Plans) > 0 {
			plans := make([]map[string]interface{}, len(s.Defender.Plans))
			for i, plan := range s.Defender.Plans {
				plans[i] = map[string]interface{}{
					"name":    plan.Name,
					"tier":    plan.Tier,
					"subPlan": plan.SubPlan,
				}
			}
			params["defenderPlans"] = map[string]interface{}{"value": plans}
		}

		if len(s.Defender.SecurityContacts) > 0 {
			contacts := make([]map[string]interface{}, len(s.Defender.SecurityContacts))
			for i, contact := range s.Defender.SecurityContacts {
				contacts[i] = map[string]interface{}{
					"email":              contact.Email,
					"phone":              contact.Phone,
					"alertNotifications": contact.AlertNotifications,
					"alertsToAdmins":     contact.AlertsToAdmins,
				}
			}
			params["securityContacts"] = map[string]interface{}{"value": contacts}
		}
	}

	// Key Vaults.
	if len(s.KeyVaults) > 0 {
		keyVaults := make([]map[string]interface{}, len(s.KeyVaults))
		for i, kv := range s.KeyVaults {
			keyVaults[i] = map[string]interface{}{
				"name":                    kv.Name,
				"sku":                     kv.SKU,
				"enableSoftDelete":        kv.EnableSoftDelete,
				"softDeleteRetentionDays": kv.SoftDeleteRetentionDays,
				"enablePurgeProtection":   kv.EnablePurgeProtection,
				"enableRbacAuthorization": kv.EnableRBACAuthorization,
			}
		}
		params["keyVaults"] = map[string]interface{}{"value": keyVaults}
	}

	// Tags.
	if len(s.Tags) > 0 {
		params["tags"] = map[string]interface{}{"value": s.Tags}
	}

	return params
}

// GetDependsOn returns the dependency list.
func (s *SecuritySpec) GetDependsOn() []string {
	return s.DependsOn
}

// GetOperator returns the operator domain name.
func (s *SecuritySpec) GetOperator() string {
	return s.Operator
}
