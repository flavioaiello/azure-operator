package modes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants to avoid literal duplication.
const (
	testModeFormat       = "mode=%s"
	testPatternNetwork   = "Microsoft.Network/*"
	testResourceTypeVNet = "Microsoft.Network/virtualNetworks"
	testResourceTypeVM   = "Microsoft.Compute/virtualMachines"
	testPatternProd      = "prod-*"
	testResourceProdHub  = "prod-hub"
)

func TestModeValid(t *testing.T) {
	tests := []struct {
		mode  Mode
		valid bool
	}{
		{ModeObserve, true},
		{ModeEnforce, true},
		{ModeProtect, true},
		{Mode("invalid"), false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.valid, tt.mode.Valid(), testModeFormat, tt.mode)
	}
}

func TestModeAllowsCreate(t *testing.T) {
	tests := []struct {
		mode   Mode
		allows bool
	}{
		{ModeObserve, false},
		{ModeEnforce, true},
		{ModeProtect, true},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.allows, tt.mode.AllowsCreate(), testModeFormat, tt.mode)
	}
}

func TestModeAllowsModify(t *testing.T) {
	tests := []struct {
		mode   Mode
		allows bool
	}{
		{ModeObserve, false},
		{ModeEnforce, true},
		{ModeProtect, false}, // protect prevents modification
	}

	for _, tt := range tests {
		assert.Equal(t, tt.allows, tt.mode.AllowsModify(), testModeFormat, tt.mode)
	}
}

func TestModeAllowsDelete(t *testing.T) {
	tests := []struct {
		mode   Mode
		allows bool
	}{
		{ModeObserve, false},
		{ModeEnforce, true},
		{ModeProtect, false}, // protect prevents deletion
	}

	for _, tt := range tests {
		assert.Equal(t, tt.allows, tt.mode.AllowsDelete(), testModeFormat, tt.mode)
	}
}

func TestOverrideMatches(t *testing.T) {
	override := Override{
		Pattern:      testPatternNetwork,
		ResourceType: "",
		Mode:         ModeProtect,
		Action:       ActionSet,
	}

	assert.True(t, override.Matches("hub-vnet", testResourceTypeVNet))
	assert.True(t, override.Matches("any-nsg", "Microsoft.Network/networkSecurityGroups"))
	assert.False(t, override.Matches("vm1", testResourceTypeVM))
}

func TestOverrideMatchesResourceName(t *testing.T) {
	override := Override{
		Pattern:      testPatternProd,
		ResourceType: testResourceTypeVNet,
		Mode:         ModeProtect,
		Action:       ActionSet,
	}

	assert.True(t, override.Matches(testResourceProdHub, testResourceTypeVNet))
	assert.False(t, override.Matches("dev-hub", testResourceTypeVNet))
	assert.False(t, override.Matches(testResourceProdHub, testResourceTypeVM))
}

func TestResolverResolveDefaultMode(t *testing.T) {
	config := NewConfig(ModeEnforce)
	resolver := NewResolver(config)

	mode := resolver.Resolve("any-resource", testResourceTypeVNet)
	assert.Equal(t, ModeEnforce, mode)
}

func TestResolverResolveOverride(t *testing.T) {
	config := NewConfig(ModeEnforce)
	config.AddOverride(Override{
		Pattern:      testPatternNetwork,
		ResourceType: "",
		Mode:         ModeProtect,
		Action:       ActionSet,
	})

	resolver := NewResolver(config)

	// Matching resource should get override
	mode := resolver.Resolve("hub-vnet", testResourceTypeVNet)
	assert.Equal(t, ModeProtect, mode)

	// Non-matching resource should get default
	mode = resolver.Resolve("vm1", testResourceTypeVM)
	assert.Equal(t, ModeEnforce, mode)
}

func TestResolverResolveRestrict(t *testing.T) {
	config := NewConfig(ModeEnforce) // default is enforce (allows all)
	config.AddOverride(Override{
		Pattern:      "*",
		ResourceType: "Microsoft.Authorization/roleAssignments",
		Mode:         ModeProtect, // more restrictive
		Action:       ActionRestrict,
	})

	resolver := NewResolver(config)

	// RESTRICT: Should use more restrictive mode (protect < enforce)
	mode := resolver.Resolve("rbac1", "Microsoft.Authorization/roleAssignments")
	assert.Equal(t, ModeProtect, mode)
}

func TestResolverResolveEscalate(t *testing.T) {
	config := NewConfig(ModeObserve) // default is observe-only
	config.AddOverride(Override{
		Pattern:      "critical-*",
		ResourceType: "",
		Mode:         ModeEnforce, // less restrictive
		Action:       ActionEscalate,
	})

	resolver := NewResolver(config)

	// ESCALATE: Should use less restrictive mode for critical resources
	mode := resolver.Resolve("critical-vnet", testResourceTypeVNet)
	assert.Equal(t, ModeEnforce, mode)

	// Non-critical stays at default
	mode = resolver.Resolve("dev-vnet", testResourceTypeVNet)
	assert.Equal(t, ModeObserve, mode)
}

func TestFromYAML(t *testing.T) {
	yamlContent := `
defaultMode: enforce
logModeResolution: true
overrides:
  - pattern: "Microsoft.Authorization/*"
    resourceType: ""
    mode: protect
    action: set
    reason: "Protect all RBAC from modification"
  - pattern: "prod-*"
    resourceType: "Microsoft.Network/virtualNetworks"
    mode: protect
    action: restrict
    reason: "Protect production VNets"
`

	config, err := FromYAML([]byte(yamlContent))
	require.NoError(t, err)

	assert.Equal(t, ModeEnforce, config.DefaultMode)
	assert.True(t, config.LogModeResolution)
	assert.Len(t, config.Overrides, 2)
	assert.Equal(t, "Microsoft.Authorization/*", config.Overrides[0].Pattern)
	assert.Equal(t, ModeProtect, config.Overrides[0].Mode)
}

func TestFromYAMLInvalidDefaultMode(t *testing.T) {
	yamlContent := `
defaultMode: invalid_mode
`

	_, err := FromYAML([]byte(yamlContent))
	assert.Error(t, err)
}

func TestFromYAMLInvalidOverrideMode(t *testing.T) {
	yamlContent := `
defaultMode: enforce
overrides:
  - pattern: "test-*"
    mode: bad_mode
    action: set
`

	_, err := FromYAML([]byte(yamlContent))
	assert.Error(t, err)
}

func TestModeRestrictiveness(t *testing.T) {
	// ModeObserve < ModeProtect < ModeEnforce
	assert.True(t, modeRestrictiveness(ModeObserve) < modeRestrictiveness(ModeProtect))
	assert.True(t, modeRestrictiveness(ModeProtect) < modeRestrictiveness(ModeEnforce))
}

func TestActionValid(t *testing.T) {
	assert.True(t, ActionSet.Valid())
	assert.True(t, ActionRestrict.Valid())
	assert.True(t, ActionEscalate.Valid())
	assert.False(t, Action("invalid").Valid())
}

func TestResolverMultipleOverridesPriority(t *testing.T) {
	config := NewConfig(ModeEnforce)

	// Add overrides in order - last matching wins
	config.AddOverride(Override{
		Pattern: "*",
		Mode:    ModeObserve,
		Action:  ActionSet,
	})
	config.AddOverride(Override{
		Pattern:      "critical-*",
		ResourceType: "",
		Mode:         ModeEnforce,
		Action:       ActionSet,
	})

	resolver := NewResolver(config)

	// Specific pattern should override wildcard (last match wins)
	mode := resolver.Resolve("critical-vnet", testResourceTypeVNet)
	assert.Equal(t, ModeEnforce, mode)

	// Non-matching second pattern uses first override
	mode = resolver.Resolve("dev-vnet", testResourceTypeVNet)
	assert.Equal(t, ModeObserve, mode)
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		value   string
		pattern string
		matches bool
	}{
		{testResourceTypeVNet, testPatternNetwork, true},
		{testResourceTypeVM, testPatternNetwork, false},
		{testResourceProdHub, testPatternProd, true},
		{"dev-hub", testPatternProd, false},
		{"vm1", "*", true},
		{"anything", "*", true},
	}

	for _, tt := range tests {
		result := globMatch(tt.value, tt.pattern)
		assert.Equal(t, tt.matches, result, "value=%s pattern=%s", tt.value, tt.pattern)
	}
}
