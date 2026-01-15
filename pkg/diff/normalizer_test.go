package diff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test constants to avoid literal duplication.
const (
	testPathPropertiesEnabled     = "properties.enabled"
	testResourceTypeVNet          = "Microsoft.Network/virtualNetworks"
	testPathProvisioningStateGlob = "**.provisioningState"
	testPathProvisioningState     = "properties.provisioningState"
	testResourceTypeGeneric       = "Test/Type"
)

func TestNormalizationRuleMatches(t *testing.T) {
	rule := NormalizationRule{
		PathPattern:   testPathPropertiesEnabled,
		Type:          NormalizeBool,
		ResourceTypes: []string{testResourceTypeVNet},
	}

	assert.True(t, rule.Matches(testPathPropertiesEnabled, testResourceTypeVNet))
	assert.False(t, rule.Matches(testPathPropertiesEnabled, "Microsoft.Compute/virtualMachines"))
	assert.False(t, rule.Matches("properties.name", testResourceTypeVNet))
}

func TestNormalizationRuleMatchesWildcard(t *testing.T) {
	rule := NormalizationRule{
		PathPattern:   testPathProvisioningStateGlob,
		Type:          NormalizeCaseInsensitive,
		ResourceTypes: []string{"*"},
	}

	assert.True(t, rule.Matches(testPathProvisioningState, testResourceTypeVNet))
	assert.True(t, rule.Matches("deep.nested.provisioningState", "Microsoft.Compute/virtualMachines"))
}

func TestNormalizerNormalizeEmpty(t *testing.T) {
	n := NewNormalizer([]NormalizationRule{
		{PathPattern: "tags", Type: NormalizeEmpty, ResourceTypes: []string{"*"}},
	})

	// nil stays nil
	result := n.Normalize("tags", testResourceTypeVNet, nil)
	assert.Nil(t, result)

	// empty string becomes nil
	result = n.Normalize("tags", testResourceTypeVNet, "")
	assert.Nil(t, result)

	// empty map becomes nil
	result = n.Normalize("tags", testResourceTypeVNet, map[string]interface{}{})
	assert.Nil(t, result)

	// non-empty stays as-is
	result = n.Normalize("tags", testResourceTypeVNet, map[string]interface{}{"env": "prod"})
	assert.NotNil(t, result)
}

func TestNormalizerNormalizeBool(t *testing.T) {
	n := NewNormalizer([]NormalizationRule{
		{PathPattern: "enabled", Type: NormalizeBool, ResourceTypes: []string{"*"}},
	})

	tests := []struct {
		input    interface{}
		expected interface{}
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"false", false},
		{"False", false},
		{"yes", true},
		{"no", false},
		{"1", true},
		{"0", false},
		{true, true},
		{false, false},
		{nil, nil},
	}

	for _, tt := range tests {
		result := n.Normalize("enabled", testResourceTypeGeneric, tt.input)
		assert.Equal(t, tt.expected, result, "input=%v", tt.input)
	}
}

func TestNormalizerNormalizeCaseInsensitive(t *testing.T) {
	n := NewNormalizer([]NormalizationRule{
		{PathPattern: testPathProvisioningStateGlob, Type: NormalizeCaseInsensitive, ResourceTypes: []string{"*"}},
	})

	result := n.Normalize(testPathProvisioningState, testResourceTypeGeneric, "Succeeded")
	assert.Equal(t, "succeeded", result)

	result = n.Normalize(testPathProvisioningState, testResourceTypeGeneric, "SUCCEEDED")
	assert.Equal(t, "succeeded", result)
}

func TestNormalizerAreEquivalent(t *testing.T) {
	n := NewNormalizer(DefaultNormalizationRules)

	// Boolean equivalence
	assert.True(t, n.AreEquivalent(testPathPropertiesEnabled, testResourceTypeGeneric, true, "true"))
	assert.True(t, n.AreEquivalent(testPathPropertiesEnabled, testResourceTypeGeneric, false, "false"))

	// Case insensitive
	assert.True(t, n.AreEquivalent(testPathProvisioningState, testResourceTypeGeneric, "Succeeded", "succeeded"))

	// Empty equivalence
	assert.True(t, n.AreEquivalent("properties.tags", testResourceTypeGeneric, nil, map[string]interface{}{}))
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		value   string
		pattern string
		matches bool
	}{
		{testPathPropertiesEnabled, testPathPropertiesEnabled, true},
		{testPathPropertiesEnabled, "properties.*", true},
		{"properties.subnets.0.enabled", "properties.subnets.*.enabled", true},
		{testPathProvisioningState, testPathProvisioningStateGlob, true},
		{"deep.nested.provisioningState", testPathProvisioningStateGlob, true},
		{"properties.name", testPathPropertiesEnabled, false},
	}

	for _, tt := range tests {
		result := globMatch(tt.value, tt.pattern)
		assert.Equal(t, tt.matches, result, "value=%s pattern=%s", tt.value, tt.pattern)
	}
}

func TestDeepEqual(t *testing.T) {
	// Same types
	assert.True(t, deepEqual("a", "a"))
	assert.True(t, deepEqual(1, 1))
	assert.True(t, deepEqual(nil, nil))

	// Different types, same value
	assert.True(t, deepEqual(int(1), int64(1)))
	assert.True(t, deepEqual(float64(1.0), int(1)))

	// Different values
	assert.False(t, deepEqual("a", "b"))
	assert.False(t, deepEqual(1, 2))
	assert.False(t, deepEqual(nil, "a"))
}
