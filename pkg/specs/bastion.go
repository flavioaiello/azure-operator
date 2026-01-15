package specs

// BastionSpec represents the bastion domain specification.
type BastionSpec struct {
	BaseSpec `yaml:",inline"`

	// Bastion is the Azure Bastion configuration.
	Bastion AzureBastionConfig `yaml:"bastion" validate:"required"`
	// PublicIP is the public IP configuration.
	PublicIP *BastionPublicIPConfig `yaml:"publicIp,omitempty"`
}

// AzureBastionConfig represents Azure Bastion configuration.
type AzureBastionConfig struct {
	// Name is the bastion host name.
	Name string `yaml:"name" validate:"required,min=1,max=80"`
	// SKU is the bastion SKU (Basic, Standard, Developer).
	SKU string `yaml:"sku" validate:"required,oneof=Basic Standard Developer"`
	// SubnetID is the AzureBastionSubnet resource ID.
	SubnetID string `yaml:"subnetId,omitempty"`
	// VirtualNetworkID is the VNet resource ID (for Developer SKU).
	VirtualNetworkID string `yaml:"virtualNetworkId,omitempty"`
	// EnableTunneling enables native client support.
	EnableTunneling bool `yaml:"enableTunneling"`
	// EnableIPConnect enables IP-based connection.
	EnableIPConnect bool `yaml:"enableIpConnect"`
	// EnableCopyPaste enables copy/paste.
	EnableCopyPaste bool `yaml:"enableCopyPaste"`
	// EnableFileCopy enables file copy.
	EnableFileCopy bool `yaml:"enableFileCopy"`
	// EnableShareableLink enables shareable links.
	EnableShareableLink bool `yaml:"enableShareableLink"`
	// ScaleUnits is the number of scale units (2-50 for Standard).
	ScaleUnits int `yaml:"scaleUnits" validate:"omitempty,min=2,max=50"`
}

// BastionPublicIPConfig represents public IP for bastion.
type BastionPublicIPConfig struct {
	// Name is the public IP name.
	Name string `yaml:"name" validate:"required,min=1,max=80"`
	// AvailabilityZones are the zones.
	AvailabilityZones []string `yaml:"availabilityZones"`
}

// Validate validates the bastion spec.
func (s *BastionSpec) Validate() error {
	if err := validate.Struct(s); err != nil {
		return WrapValidationErrors(err)
	}

	// Custom validation: Developer SKU requires VirtualNetworkID.
	if s.Bastion.SKU == "Developer" && s.Bastion.VirtualNetworkID == "" {
		return ValidationError{
			Field:   "VirtualNetworkID",
			Tag:     "required_for_developer",
			Value:   "",
			Message: "VirtualNetworkID is required for Developer SKU",
		}
	}

	// Custom validation: Basic/Standard SKU requires SubnetID.
	if (s.Bastion.SKU == "Basic" || s.Bastion.SKU == "Standard") && s.Bastion.SubnetID == "" {
		return ValidationError{
			Field:   "SubnetID",
			Tag:     "required_for_basic_standard",
			Value:   "",
			Message: "SubnetID is required for Basic and Standard SKU",
		}
	}

	// Custom validation: ScaleUnits only for Standard.
	if s.Bastion.ScaleUnits > 0 && s.Bastion.SKU != "Standard" {
		return ValidationError{
			Field:   "ScaleUnits",
			Tag:     "standard_only",
			Value:   s.Bastion.ScaleUnits,
			Message: "ScaleUnits is only valid for Standard SKU",
		}
	}

	return nil
}

// ToARMParameters converts the spec to ARM template parameters.
func (s *BastionSpec) ToARMParameters() map[string]interface{} {
	params := make(map[string]interface{})

	if s.Location != "" {
		params["location"] = map[string]interface{}{"value": s.Location}
	}
	if s.ResourceGroupName != "" {
		params["resourceGroupName"] = map[string]interface{}{"value": s.ResourceGroupName}
	}

	// Bastion.
	params["bastionName"] = map[string]interface{}{"value": s.Bastion.Name}
	params["bastionSku"] = map[string]interface{}{"value": s.Bastion.SKU}

	if s.Bastion.SubnetID != "" {
		params["subnetId"] = map[string]interface{}{"value": s.Bastion.SubnetID}
	}
	if s.Bastion.VirtualNetworkID != "" {
		params["virtualNetworkId"] = map[string]interface{}{"value": s.Bastion.VirtualNetworkID}
	}

	// Features (Standard SKU).
	params["enableTunneling"] = map[string]interface{}{"value": s.Bastion.EnableTunneling}
	params["enableIpConnect"] = map[string]interface{}{"value": s.Bastion.EnableIPConnect}
	params["enableCopyPaste"] = map[string]interface{}{"value": s.Bastion.EnableCopyPaste}
	params["enableFileCopy"] = map[string]interface{}{"value": s.Bastion.EnableFileCopy}
	params["enableShareableLink"] = map[string]interface{}{"value": s.Bastion.EnableShareableLink}

	if s.Bastion.ScaleUnits > 0 {
		params["scaleUnits"] = map[string]interface{}{"value": s.Bastion.ScaleUnits}
	}

	// Public IP.
	if s.PublicIP != nil {
		params["publicIpName"] = map[string]interface{}{"value": s.PublicIP.Name}
		if len(s.PublicIP.AvailabilityZones) > 0 {
			params["publicIpZones"] = map[string]interface{}{"value": s.PublicIP.AvailabilityZones}
		}
	}

	// Tags.
	if len(s.Tags) > 0 {
		params["tags"] = map[string]interface{}{"value": s.Tags}
	}

	return params
}
