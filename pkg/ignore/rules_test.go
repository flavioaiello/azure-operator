package ignore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants to avoid literal duplication.
const (
	testResourceTypeVNet            = "Microsoft.Network/virtualNetworks"
	testPathProvisioningState       = "properties.provisioningState"
	testPathSubnetProvisioningState = "properties.subnets.0.properties.provisioningState"
	testPathAddressSpace            = "properties.addressSpace"
	testResourceTypeCustom          = "Microsoft.Custom/resources"
	// testPrivateCIDR is a RFC 1918 private address range used for testing.
	testPrivateCIDR = "10.0.0.0/16" //nolint:gosec // Test data, not a real network.
)

func TestRuleMatchesResource(t *testing.T) {
	rule := Rule{
		ResourceType: testResourceTypeVNet,
		Paths:        []string{testPathProvisioningState},
	}

	assert.True(t, rule.MatchesResource(testResourceTypeVNet))
	assert.True(t, rule.MatchesResource("microsoft.network/virtualnetworks")) // case insensitive
	assert.False(t, rule.MatchesResource("Microsoft.Network/subnets"))
}

func TestRuleMatchesResourceWildcard(t *testing.T) {
	rule := Rule{
		ResourceType: "*",
		Paths:        []string{testPathProvisioningState},
	}

	assert.True(t, rule.MatchesResource(testResourceTypeVNet))
	assert.True(t, rule.MatchesResource("Microsoft.Compute/virtualMachines"))
}

func TestRuleShouldIgnorePath(t *testing.T) {
	rule := Rule{
		ResourceType: "*",
		Paths: []string{
			testPathProvisioningState,
			"properties.subnets.*.properties.provisioningState",
		},
	}

	assert.True(t, rule.ShouldIgnorePath(testPathProvisioningState))
	assert.True(t, rule.ShouldIgnorePath(testPathSubnetProvisioningState))
	assert.True(t, rule.ShouldIgnorePath("properties.subnets.subnet1.properties.provisioningState"))
	assert.False(t, rule.ShouldIgnorePath(testPathAddressSpace))
}

func TestRuleShouldIgnorePathDoubleWildcard(t *testing.T) {
	rule := Rule{
		ResourceType: "*",
		Paths:        []string{"**.provisioningState"},
	}

	assert.True(t, rule.ShouldIgnorePath(testPathProvisioningState))
	assert.True(t, rule.ShouldIgnorePath(testPathSubnetProvisioningState))
	assert.True(t, rule.ShouldIgnorePath("deep.nested.path.provisioningState"))
}

func TestConfigGetEffectiveRules(t *testing.T) {
	config := NewConfig()
	config.AddRule(Rule{
		ResourceType: testResourceTypeCustom,
		Paths:        []string{"custom.path"},
	})

	rules := config.GetEffectiveRules()

	// Should include default rules + custom rule
	assert.True(t, len(rules) > 1)

	// Check custom rule is included
	hasCustom := false
	for _, r := range rules {
		if r.ResourceType == testResourceTypeCustom {
			hasCustom = true
			break
		}
	}
	assert.True(t, hasCustom)
}

func TestConfigDisableDefaults(t *testing.T) {
	config := NewConfig()
	config.EnableDefaultRules = false
	config.AddRule(Rule{
		ResourceType: testResourceTypeCustom,
		Paths:        []string{"custom.path"},
	})

	rules := config.GetEffectiveRules()

	assert.Len(t, rules, 1)
	assert.Equal(t, testResourceTypeCustom, rules[0].ResourceType)
}

func TestFromYAML(t *testing.T) {
	yamlContent := `
enableDefaultRules: true
logIgnoredChanges: true
rules:
  - resourceType: Microsoft.Network/virtualNetworks
    paths:
      - properties.provisioningState
      - "tags.createdBy"
    reason: "Tolerate tags set by automation"
`

	config, err := FromYAML([]byte(yamlContent))
	require.NoError(t, err)

	assert.True(t, config.EnableDefaultRules)
	assert.True(t, config.LogIgnoredChanges)
	assert.Len(t, config.Rules, 1)
	assert.Equal(t, testResourceTypeVNet, config.Rules[0].ResourceType)
	assert.Len(t, config.Rules[0].Paths, 2)
}

func TestFromYAMLInvalidResourceType(t *testing.T) {
	yamlContent := `
rules:
  - resourceType: ""
    paths:
      - "some.path"
`

	_, err := FromYAML([]byte(yamlContent))
	assert.Error(t, err)
}

func TestEvaluatorShouldIgnore(t *testing.T) {
	config := NewConfig()
	evaluator := NewEvaluator(config)

	// Should ignore system properties by default
	ignored, reason := evaluator.ShouldIgnore(testResourceTypeVNet, testPathProvisioningState)
	assert.True(t, ignored)
	assert.NotEmpty(t, reason)

	// Should not ignore address space
	ignored, _ = evaluator.ShouldIgnore(testResourceTypeVNet, testPathAddressSpace)
	assert.False(t, ignored)
}

func TestEvaluatorFilterChanges(t *testing.T) {
	config := NewConfig()
	evaluator := NewEvaluator(config)

	changes := map[string]interface{}{
		testPathProvisioningState: "Succeeded",
		testPathAddressSpace:      []string{testPrivateCIDR},
		"etag":                    "abc123",
	}

	filtered := evaluator.FilterChanges(testResourceTypeVNet, changes)

	// provisioningState and etag should be filtered out
	assert.Len(t, filtered, 1)
	assert.Contains(t, filtered, testPathAddressSpace)
}

func TestDefaultIgnoreRules(t *testing.T) {
	assert.NotEmpty(t, DefaultIgnoreRules)

	// Verify wildcard rule for system properties
	hasWildcardRule := false
	for _, rule := range DefaultIgnoreRules {
		if rule.ResourceType == "*" {
			hasWildcardRule = true
			break
		}
	}
	assert.True(t, hasWildcardRule)
}

func TestPathMatches(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		matches bool
	}{
		{testPathProvisioningState, testPathProvisioningState, true},
		{testPathSubnetProvisioningState, "properties.subnets.*.properties.provisioningState", true},
		{"deep.nested.path.value", "**.value", true},
		{testPathAddressSpace, testPathProvisioningState, false},
	}

	for _, tt := range tests {
		result := pathMatches(tt.path, tt.pattern)
		assert.Equal(t, tt.matches, result, "path=%s pattern=%s", tt.path, tt.pattern)
	}
}
