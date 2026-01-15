package specs

// ConnectivitySpec represents the connectivity domain specification.
type ConnectivitySpec struct {
	BaseSpec `yaml:",inline"`

	// Operator is the operator domain name (set by loader).
	Operator string `yaml:"-"`
	// VirtualNetwork is the hub virtual network configuration.
	VirtualNetwork VirtualNetworkConfig `yaml:"virtualNetwork" validate:"required"`
	// Subnets are the subnet configurations.
	Subnets []SubnetConfig `yaml:"subnets"`
	// Peerings are the VNet peering configurations.
	Peerings []PeeringConfig `yaml:"peerings"`
	// RouteTables are the route table configurations.
	RouteTables []RouteTableConfig `yaml:"routeTables"`
	// NetworkSecurityGroups are the NSG configurations.
	NetworkSecurityGroups []NSGConfig `yaml:"networkSecurityGroups"`
}

// VirtualNetworkConfig represents virtual network configuration.
type VirtualNetworkConfig struct {
	// Name is the VNet name.
	Name string `yaml:"name" validate:"required,min=1,max=64"`
	// AddressSpace is the CIDR address space.
	AddressSpace []string `yaml:"addressSpace" validate:"required,min=1,dive,cidr"`
	// DNSServers are custom DNS servers.
	DNSServers []string `yaml:"dnsServers"`
	// EnableDDoSProtection enables DDoS protection plan.
	EnableDDoSProtection bool `yaml:"enableDDoSProtection"`
}

// SubnetConfig represents subnet configuration.
type SubnetConfig struct {
	// Name is the subnet name.
	Name string `yaml:"name" validate:"required,min=1,max=80"`
	// AddressPrefix is the CIDR address prefix.
	AddressPrefix string `yaml:"addressPrefix" validate:"required,cidr"`
	// NetworkSecurityGroup is the associated NSG name.
	NetworkSecurityGroup string `yaml:"networkSecurityGroup,omitempty"`
	// RouteTable is the associated route table name.
	RouteTable string `yaml:"routeTable,omitempty"`
	// ServiceEndpoints are the enabled service endpoints.
	ServiceEndpoints []string `yaml:"serviceEndpoints"`
	// Delegations are subnet delegations.
	Delegations []string `yaml:"delegations"`
	// PrivateEndpointNetworkPolicies controls private endpoint policies.
	PrivateEndpointNetworkPolicies string `yaml:"privateEndpointNetworkPolicies,omitempty"`
}

// PeeringConfig represents VNet peering configuration.
type PeeringConfig struct {
	// Name is the peering name.
	Name string `yaml:"name" validate:"required,min=1"`
	// RemoteVNetID is the resource ID of the remote VNet.
	RemoteVNetID string `yaml:"remoteVNetId" validate:"required"`
	// AllowVNetAccess allows VNet access.
	AllowVNetAccess bool `yaml:"allowVNetAccess"`
	// AllowForwardedTraffic allows forwarded traffic.
	AllowForwardedTraffic bool `yaml:"allowForwardedTraffic"`
	// AllowGatewayTransit allows gateway transit.
	AllowGatewayTransit bool `yaml:"allowGatewayTransit"`
	// UseRemoteGateways uses remote gateways.
	UseRemoteGateways bool `yaml:"useRemoteGateways"`
}

// RouteTableConfig represents route table configuration.
type RouteTableConfig struct {
	// Name is the route table name.
	Name string `yaml:"name" validate:"required,min=1,max=80"`
	// DisableBGPRoutePropagation disables BGP route propagation.
	DisableBGPRoutePropagation bool `yaml:"disableBgpRoutePropagation"`
	// Routes are the route entries.
	Routes []RouteConfig `yaml:"routes"`
}

// RouteConfig represents a single route.
type RouteConfig struct {
	// Name is the route name.
	Name string `yaml:"name" validate:"required,min=1"`
	// AddressPrefix is the destination CIDR.
	AddressPrefix string `yaml:"addressPrefix" validate:"required,cidr"`
	// NextHopType is the next hop type.
	NextHopType string `yaml:"nextHopType" validate:"required,oneof=VirtualNetworkGateway VnetLocal Internet VirtualAppliance None"`
	// NextHopIPAddress is the next hop IP (for VirtualAppliance).
	NextHopIPAddress string `yaml:"nextHopIpAddress,omitempty"`
}

// NSGConfig represents network security group configuration.
type NSGConfig struct {
	// Name is the NSG name.
	Name string `yaml:"name" validate:"required,min=1,max=80"`
	// Rules are the security rules.
	Rules []NSGRuleConfig `yaml:"rules"`
}

// NSGRuleConfig represents a single NSG rule.
type NSGRuleConfig struct {
	// Name is the rule name.
	Name string `yaml:"name" validate:"required,min=1"`
	// Priority is the rule priority (100-4096).
	Priority int `yaml:"priority" validate:"required,min=100,max=4096"`
	// Direction is Inbound or Outbound.
	Direction string `yaml:"direction" validate:"required,oneof=Inbound Outbound"`
	// Access is Allow or Deny.
	Access string `yaml:"access" validate:"required,oneof=Allow Deny"`
	// Protocol is the protocol (Tcp, Udp, Icmp, Esp, Ah, *).
	Protocol string `yaml:"protocol" validate:"required"`
	// SourceAddressPrefix is the source address prefix.
	SourceAddressPrefix string `yaml:"sourceAddressPrefix,omitempty"`
	// SourceAddressPrefixes are multiple source prefixes.
	SourceAddressPrefixes []string `yaml:"sourceAddressPrefixes,omitempty"`
	// SourcePortRange is the source port range.
	SourcePortRange string `yaml:"sourcePortRange,omitempty"`
	// DestinationAddressPrefix is the destination address prefix.
	DestinationAddressPrefix string `yaml:"destinationAddressPrefix,omitempty"`
	// DestinationAddressPrefixes are multiple destination prefixes.
	DestinationAddressPrefixes []string `yaml:"destinationAddressPrefixes,omitempty"`
	// DestinationPortRange is the destination port range.
	DestinationPortRange string `yaml:"destinationPortRange,omitempty"`
	// DestinationPortRanges are multiple destination port ranges.
	DestinationPortRanges []string `yaml:"destinationPortRanges,omitempty"`
}

// Validate validates the connectivity spec.
func (s *ConnectivitySpec) Validate() error {
	if err := validate.Struct(s); err != nil {
		return WrapValidationErrors(err)
	}
	return nil
}

// ToARMParameters converts the spec to ARM template parameters.
func (s *ConnectivitySpec) ToARMParameters() map[string]interface{} {
	params := make(map[string]interface{})

	if s.Location != "" {
		params["location"] = map[string]interface{}{"value": s.Location}
	}
	if s.ResourceGroupName != "" {
		params["resourceGroupName"] = map[string]interface{}{"value": s.ResourceGroupName}
	}

	// Virtual Network.
	params["vnetName"] = map[string]interface{}{"value": s.VirtualNetwork.Name}
	params["addressSpace"] = map[string]interface{}{"value": s.VirtualNetwork.AddressSpace}
	if len(s.VirtualNetwork.DNSServers) > 0 {
		params["dnsServers"] = map[string]interface{}{"value": s.VirtualNetwork.DNSServers}
	}
	params["enableDDoSProtection"] = map[string]interface{}{"value": s.VirtualNetwork.EnableDDoSProtection}

	// Subnets.
	if len(s.Subnets) > 0 {
		subnets := make([]map[string]interface{}, len(s.Subnets))
		for i, subnet := range s.Subnets {
			subnets[i] = map[string]interface{}{
				"name":                 subnet.Name,
				"addressPrefix":        subnet.AddressPrefix,
				"networkSecurityGroup": subnet.NetworkSecurityGroup,
				"routeTable":           subnet.RouteTable,
				"serviceEndpoints":     subnet.ServiceEndpoints,
				"delegations":          subnet.Delegations,
			}
		}
		params["subnets"] = map[string]interface{}{"value": subnets}
	}

	// Route Tables.
	if len(s.RouteTables) > 0 {
		routeTables := make([]map[string]interface{}, len(s.RouteTables))
		for i, rt := range s.RouteTables {
			routes := make([]map[string]interface{}, len(rt.Routes))
			for j, route := range rt.Routes {
				routes[j] = map[string]interface{}{
					"name":             route.Name,
					"addressPrefix":    route.AddressPrefix,
					"nextHopType":      route.NextHopType,
					"nextHopIpAddress": route.NextHopIPAddress,
				}
			}
			routeTables[i] = map[string]interface{}{
				"name":                       rt.Name,
				"disableBgpRoutePropagation": rt.DisableBGPRoutePropagation,
				"routes":                     routes,
			}
		}
		params["routeTables"] = map[string]interface{}{"value": routeTables}
	}

	// Tags.
	if len(s.Tags) > 0 {
		params["tags"] = map[string]interface{}{"value": s.Tags}
	}

	return params
}

// GetDependsOn returns the dependency list.
func (s *ConnectivitySpec) GetDependsOn() []string {
	return s.DependsOn
}

// GetOperator returns the operator domain name.
func (s *ConnectivitySpec) GetOperator() string {
	return s.Operator
}
