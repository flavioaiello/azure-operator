// Package ignore implements K8s-style ignoreDifferences for drift detection.
//
// Allows users to specify JSON paths that should be ignored during WhatIf
// comparison, similar to ArgoCD's ignoreDifferences feature.
package ignore

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule defines an ignore rule for a specific resource type and paths.
type Rule struct {
	ResourceType string   `yaml:"resourceType" json:"resourceType"` // Resource type to match (e.g., "Microsoft.Network/virtualNetworks")
	Paths        []string `yaml:"paths" json:"paths"`               // JSON paths to ignore (supports *, **)
	Reason       string   `yaml:"reason,omitempty" json:"reason"`   // Optional explanation
}

// MatchesResource checks if this rule applies to the given resource type.
func (r Rule) MatchesResource(resourceType string) bool {
	if r.ResourceType == "*" {
		return true
	}
	return strings.EqualFold(r.ResourceType, resourceType)
}

// ShouldIgnorePath checks if a specific path should be ignored.
func (r Rule) ShouldIgnorePath(path string) bool {
	for _, pattern := range r.Paths {
		if pathMatches(path, pattern) {
			return true
		}
	}
	return false
}

// DefaultIgnoreRules provides sensible defaults for Azure system properties.
var DefaultIgnoreRules = []Rule{
	{
		ResourceType: "*",
		Paths: []string{
			"id",
			"type",
			"etag",
			"**.provisioningState",
			"**.resourceGuid",
			"systemData",
			"systemData.**",
		},
		Reason: "System-managed properties that change outside of deployments",
	},
	{
		ResourceType: "Microsoft.Network/virtualNetworks",
		Paths: []string{
			"properties.subnets.*.properties.ipConfigurations",
			"properties.subnets.*.properties.provisioningState",
		},
		Reason: "Subnet IP configurations are managed by attached resources",
	},
}

// Config holds ignore rules configuration.
type Config struct {
	EnableDefaultRules bool   `yaml:"enableDefaultRules" json:"enableDefaultRules"`
	LogIgnoredChanges  bool   `yaml:"logIgnoredChanges" json:"logIgnoredChanges"`
	Rules              []Rule `yaml:"rules" json:"rules"`
}

// NewConfig creates a new config with default rules enabled.
func NewConfig() *Config {
	return &Config{
		EnableDefaultRules: true,
		LogIgnoredChanges:  false,
		Rules:              make([]Rule, 0),
	}
}

// AddRule adds a custom ignore rule.
func (c *Config) AddRule(rule Rule) {
	c.Rules = append(c.Rules, rule)
}

// GetEffectiveRules returns all rules including defaults if enabled.
func (c *Config) GetEffectiveRules() []Rule {
	if c.EnableDefaultRules {
		result := make([]Rule, 0, len(DefaultIgnoreRules)+len(c.Rules))
		result = append(result, DefaultIgnoreRules...)
		result = append(result, c.Rules...)
		return result
	}
	return c.Rules
}

// FromYAML parses ignore config from YAML content.
func FromYAML(content []byte) (*Config, error) {
	config := NewConfig()
	if err := yaml.Unmarshal(content, config); err != nil {
		return nil, fmt.Errorf("failed to parse ignore config: %w", err)
	}

	// Validate rules
	for i, rule := range config.Rules {
		if rule.ResourceType == "" {
			return nil, fmt.Errorf("rule %d: resourceType is required", i)
		}
		if len(rule.Paths) == 0 {
			return nil, fmt.Errorf("rule %d: at least one path is required", i)
		}
	}

	return config, nil
}

// Evaluator determines if changes should be ignored.
type Evaluator struct {
	config *Config
	rules  []Rule
}

// NewEvaluator creates an evaluator with the given config.
func NewEvaluator(config *Config) *Evaluator {
	if config == nil {
		config = NewConfig()
	}
	return &Evaluator{
		config: config,
		rules:  config.GetEffectiveRules(),
	}
}

// ShouldIgnore checks if a path should be ignored for the given resource type.
func (e *Evaluator) ShouldIgnore(resourceType, path string) (bool, string) {
	for _, rule := range e.rules {
		if rule.MatchesResource(resourceType) && rule.ShouldIgnorePath(path) {
			return true, rule.Reason
		}
	}
	return false, ""
}

// FilterChanges removes ignored paths from a change map.
func (e *Evaluator) FilterChanges(resourceType string, changes map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for path, value := range changes {
		ignored, _ := e.ShouldIgnore(resourceType, path)
		if !ignored {
			result[path] = value
		}
	}
	return result
}

// pathMatches checks if a path matches a pattern with glob support.
func pathMatches(path, pattern string) bool {
	if path == pattern {
		return true
	}

	if strings.Contains(pattern, "**") {
		return pathMatchesDoubleStar(path, pattern)
	}

	if strings.Contains(pattern, "*") {
		return pathMatchesSingleStar(path, pattern)
	}

	return false
}

// pathMatchesDoubleStar handles ** patterns that match any path depth.
func pathMatchesDoubleStar(path, pattern string) bool {
	parts := strings.Split(pattern, "**")
	if len(parts) != 2 {
		return false
	}

	prefix := strings.TrimSuffix(parts[0], ".")
	suffix := strings.TrimPrefix(parts[1], ".")

	// ** at start: match any prefix ending with suffix.
	if prefix == "" {
		return strings.HasSuffix(path, suffix) || strings.HasSuffix(path, "."+suffix)
	}

	// ** at end: match prefix followed by anything.
	if suffix == "" {
		return strings.HasPrefix(path, prefix) || strings.HasPrefix(path, prefix+".")
	}

	// ** in middle: prefix...suffix.
	if strings.HasPrefix(path, prefix) {
		return strings.HasSuffix(path, suffix)
	}

	return false
}

// pathMatchesSingleStar handles * patterns that match single segments.
func pathMatchesSingleStar(path, pattern string) bool {
	patternParts := strings.Split(pattern, ".")
	pathParts := strings.Split(path, ".")

	if len(patternParts) != len(pathParts) {
		return false
	}

	for i, pp := range patternParts {
		if pp == "*" {
			continue
		}
		if pp != pathParts[i] {
			return false
		}
	}
	return true
}
