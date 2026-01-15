// Package diff provides WhatIf semantic normalization.
//
// Normalizes Azure WhatIf differences to reduce false positives:
// - Empty vs null equivalence
// - Boolean string coercion ("true" == true)
// - Numeric string coercion ("1" == 1)
// - Case-insensitive comparison for enums
package diff

import (
	"reflect"
	"strconv"
	"strings"
)

// NormalizationType defines the type of normalization to apply.
type NormalizationType string

const (
	// NormalizeEmpty treats empty and null as equivalent.
	NormalizeEmpty NormalizationType = "empty"
	// NormalizeBool normalizes boolean strings ("true"/"false").
	NormalizeBool NormalizationType = "bool"
	// NormalizeNumeric normalizes numeric strings ("1" == 1).
	NormalizeNumeric NormalizationType = "numeric"
	// NormalizeCaseInsensitive compares case-insensitively.
	NormalizeCaseInsensitive NormalizationType = "case_insensitive"
)

// NormalizationRule defines a path pattern and normalization type.
type NormalizationRule struct {
	PathPattern   string            // Glob pattern for JSON path (e.g., "properties.enabled")
	Type          NormalizationType // Type of normalization to apply
	ResourceTypes []string          // Optional: only apply to these resource types ("*" = all)
}

// Matches checks if this rule applies to the given path and resource type.
func (r NormalizationRule) Matches(path, resourceType string) bool {
	// Check resource type match
	if len(r.ResourceTypes) > 0 {
		matched := false
		for _, rt := range r.ResourceTypes {
			if rt == "*" || strings.EqualFold(rt, resourceType) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check path pattern match
	return globMatch(path, r.PathPattern)
}

// DefaultNormalizationRules provides sensible defaults for Azure WhatIf.
var DefaultNormalizationRules = []NormalizationRule{
	// Provisioning states are often case-different
	{PathPattern: "**.provisioningState", Type: NormalizeCaseInsensitive, ResourceTypes: []string{"*"}},
	// Boolean properties often come back as strings
	{PathPattern: "**.enabled", Type: NormalizeBool, ResourceTypes: []string{"*"}},
	{PathPattern: "**.isEnabled", Type: NormalizeBool, ResourceTypes: []string{"*"}},
	// Empty vs null for optional collections
	{PathPattern: "**.tags", Type: NormalizeEmpty, ResourceTypes: []string{"*"}},
	{PathPattern: "**.subnets", Type: NormalizeEmpty, ResourceTypes: []string{"*"}},
}

// Normalizer performs semantic normalization on WhatIf values.
type Normalizer struct {
	rules []NormalizationRule
}

// NewNormalizer creates a normalizer with the given rules.
func NewNormalizer(rules []NormalizationRule) *Normalizer {
	if rules == nil {
		rules = DefaultNormalizationRules
	}
	return &Normalizer{rules: rules}
}

// Normalize applies all matching normalization rules to a value.
func (n *Normalizer) Normalize(path, resourceType string, value interface{}) interface{} {
	result := value
	for _, rule := range n.rules {
		if rule.Matches(path, resourceType) {
			result = n.applyNormalization(result, rule.Type)
		}
	}
	return result
}

// applyNormalization applies a specific normalization type.
func (n *Normalizer) applyNormalization(value interface{}, normType NormalizationType) interface{} {
	switch normType {
	case NormalizeEmpty:
		return n.normalizeEmpty(value)
	case NormalizeBool:
		return n.normalizeBool(value)
	case NormalizeNumeric:
		return n.normalizeNumeric(value)
	case NormalizeCaseInsensitive:
		return n.normalizeCaseInsensitive(value)
	default:
		return value
	}
}

// normalizeEmpty converts null/nil/empty to a canonical empty form.
func (n *Normalizer) normalizeEmpty(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		if v.String() == "" {
			return nil
		}
	case reflect.Slice, reflect.Map:
		if v.IsNil() || v.Len() == 0 {
			return nil
		}
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return nil
		}
	}
	return value
}

// normalizeBool converts boolean strings to actual booleans.
func (n *Normalizer) normalizeBool(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	if s, ok := value.(string); ok {
		switch strings.ToLower(s) {
		case "true", "yes", "1":
			return true
		case "false", "no", "0":
			return false
		}
	}
	return value
}

// normalizeNumeric converts numeric strings to numbers.
func (n *Normalizer) normalizeNumeric(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	if s, ok := value.(string); ok {
		// Try integer first
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
		// Try float
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return value
}

// normalizeCaseInsensitive converts strings to lowercase for comparison.
func (n *Normalizer) normalizeCaseInsensitive(value interface{}) interface{} {
	if s, ok := value.(string); ok {
		return strings.ToLower(s)
	}
	return value
}

// AreEquivalent checks if two values are semantically equivalent.
func (n *Normalizer) AreEquivalent(path, resourceType string, before, after interface{}) bool {
	normBefore := n.Normalize(path, resourceType, before)
	normAfter := n.Normalize(path, resourceType, after)
	return deepEqual(normBefore, normAfter)
}

// deepEqual performs deep equality check with nil/empty equivalence.
func deepEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Direct comparison for primitives
	if reflect.TypeOf(a) == reflect.TypeOf(b) {
		return reflect.DeepEqual(a, b)
	}

	// Handle numeric type mismatches (int vs float64 from JSON)
	aVal := reflect.ValueOf(a)
	bVal := reflect.ValueOf(b)

	if isNumeric(aVal.Kind()) && isNumeric(bVal.Kind()) {
		return toFloat64(a) == toFloat64(b)
	}

	return false
}

// isNumeric checks if a kind is a numeric type.
func isNumeric(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// toFloat64 converts any numeric value to float64.
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case float32:
		return float64(n)
	case float64:
		return n
	default:
		return 0
	}
}

// globMatch performs simple glob matching with * and **.
func globMatch(value, pattern string) bool {
	if pattern == value {
		return true
	}

	if strings.Contains(pattern, "**") {
		return globMatchDoubleStar(value, pattern)
	}

	if strings.Contains(pattern, "*") {
		return globMatchSingleStar(value, pattern)
	}

	return false
}

// globMatchDoubleStar handles ** patterns that match any path depth.
func globMatchDoubleStar(value, pattern string) bool {
	parts := strings.Split(pattern, "**")
	if len(parts) != 2 {
		return false
	}

	prefix := parts[0]
	suffix := parts[1]
	if strings.HasPrefix(suffix, ".") {
		suffix = suffix[1:]
	}

	if strings.HasSuffix(value, suffix) {
		return true
	}
	return prefix != "" && strings.HasPrefix(value, prefix) && strings.HasSuffix(value, suffix)
}

// globMatchSingleStar handles * patterns that match single segments.
func globMatchSingleStar(value, pattern string) bool {
	patternParts := strings.Split(pattern, ".")
	valueParts := strings.Split(value, ".")

	if len(patternParts) != len(valueParts) {
		return false
	}

	for i, pp := range patternParts {
		if pp == "*" {
			continue
		}
		if pp != valueParts[i] {
			return false
		}
	}
	return true
}
