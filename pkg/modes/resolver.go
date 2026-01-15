// Package modes implements per-resource reconciliation mode control.
//
// This package enables fine-grained mode overrides at the resource level:
//   - OBSERVE globally, but ENFORCE for DNS records (low risk)
//   - ENFORCE globally, but PROTECT for roleAssignments (high risk)
//   - OBSERVE globally, but ENFORCE for specific resource group
package modes

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode represents reconciliation modes.
type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
	ModeProtect Mode = "protect"
)

// Valid checks if the mode is valid.
func (m Mode) Valid() bool {
	switch m {
	case ModeObserve, ModeEnforce, ModeProtect:
		return true
	}
	return false
}

// AllowsCreate returns true if this mode allows resource creation.
func (m Mode) AllowsCreate() bool {
	return m == ModeEnforce || m == ModeProtect
}

// AllowsModify returns true if this mode allows resource modification.
func (m Mode) AllowsModify() bool {
	return m == ModeEnforce
}

// AllowsDelete returns true if this mode allows resource deletion.
func (m Mode) AllowsDelete() bool {
	return m == ModeEnforce
}

// Action defines how the mode override is applied.
type Action string

const (
	ActionSet      Action = "set"      // Use this mode for matching resources
	ActionRestrict Action = "restrict" // Restrict to at most this mode
	ActionEscalate Action = "escalate" // Escalate to at least this mode
)

// Valid checks if the action is valid.
func (a Action) Valid() bool {
	switch a {
	case ActionSet, ActionRestrict, ActionEscalate:
		return true
	}
	return false
}

// Override defines a single mode override rule.
type Override struct {
	Pattern      string `yaml:"pattern" json:"pattern"`           // Resource type or name pattern
	ResourceType string `yaml:"resourceType" json:"resourceType"` // Specific resource type to match
	Mode         Mode   `yaml:"mode" json:"mode"`                 // Target mode
	Action       Action `yaml:"action" json:"action"`             // How to apply
	Reason       string `yaml:"reason,omitempty" json:"reason"`   // Human-readable explanation
}

// Matches checks if this override applies to the given resource.
func (o Override) Matches(resourceName, resourceType string) bool {
	// Match by pattern (resource type pattern or name pattern)
	if o.Pattern != "" {
		// Check if pattern matches resource type
		if globMatch(resourceType, o.Pattern) {
			return true
		}
		// Check if pattern matches resource name
		if globMatch(resourceName, o.Pattern) {
			if o.ResourceType == "" || strings.EqualFold(o.ResourceType, resourceType) {
				return true
			}
		}
	}

	// Match by explicit resource type
	if o.ResourceType != "" && strings.EqualFold(o.ResourceType, resourceType) {
		if o.Pattern == "" || globMatch(resourceName, o.Pattern) {
			return true
		}
	}

	return false
}

// Config holds mode override configuration.
type Config struct {
	DefaultMode       Mode       `yaml:"defaultMode" json:"defaultMode"`
	LogModeResolution bool       `yaml:"logModeResolution" json:"logModeResolution"`
	Overrides         []Override `yaml:"overrides" json:"overrides"`
}

// NewConfig creates a config with the given default mode.
func NewConfig(defaultMode Mode) *Config {
	if !defaultMode.Valid() {
		defaultMode = ModeObserve
	}
	return &Config{
		DefaultMode: defaultMode,
		Overrides:   make([]Override, 0),
	}
}

// AddOverride adds a mode override.
func (c *Config) AddOverride(override Override) {
	if override.Action == "" {
		override.Action = ActionSet
	}
	c.Overrides = append(c.Overrides, override)
}

// FromYAML parses mode config from YAML content.
func FromYAML(content []byte) (*Config, error) {
	var yc struct {
		DefaultMode       string `yaml:"defaultMode"`
		LogModeResolution bool   `yaml:"logModeResolution"`
		Overrides         []struct {
			Pattern      string `yaml:"pattern"`
			ResourceType string `yaml:"resourceType"`
			Mode         string `yaml:"mode"`
			Action       string `yaml:"action"`
			Reason       string `yaml:"reason"`
		} `yaml:"overrides"`
	}

	if err := yaml.Unmarshal(content, &yc); err != nil {
		return nil, fmt.Errorf("failed to parse mode config: %w", err)
	}

	defaultMode := Mode(yc.DefaultMode)
	if !defaultMode.Valid() {
		return nil, fmt.Errorf("invalid default mode: %s", yc.DefaultMode)
	}

	config := &Config{
		DefaultMode:       defaultMode,
		LogModeResolution: yc.LogModeResolution,
		Overrides:         make([]Override, 0, len(yc.Overrides)),
	}

	for i, yo := range yc.Overrides {
		mode := Mode(yo.Mode)
		if !mode.Valid() {
			return nil, fmt.Errorf("override %d: invalid mode: %s", i, yo.Mode)
		}

		action := ActionSet
		if yo.Action != "" {
			action = Action(yo.Action)
			if !action.Valid() {
				return nil, fmt.Errorf("override %d: invalid action: %s", i, yo.Action)
			}
		}

		config.Overrides = append(config.Overrides, Override{
			Pattern:      yo.Pattern,
			ResourceType: yo.ResourceType,
			Mode:         mode,
			Action:       action,
			Reason:       yo.Reason,
		})
	}

	return config, nil
}

// Resolver determines the effective mode for resources.
type Resolver struct {
	config *Config
}

// NewResolver creates a mode resolver with the given config.
func NewResolver(config *Config) *Resolver {
	if config == nil {
		config = NewConfig(ModeObserve)
	}
	return &Resolver{config: config}
}

// Resolve determines the effective mode for a resource.
func (r *Resolver) Resolve(resourceName, resourceType string) Mode {
	effectiveMode := r.config.DefaultMode

	for _, override := range r.config.Overrides {
		if override.Matches(resourceName, resourceType) {
			switch override.Action {
			case ActionSet:
				effectiveMode = override.Mode
			case ActionRestrict:
				// Use the more restrictive mode
				if modeRestrictiveness(override.Mode) < modeRestrictiveness(effectiveMode) {
					effectiveMode = override.Mode
				}
			case ActionEscalate:
				// Use the less restrictive mode
				if modeRestrictiveness(override.Mode) > modeRestrictiveness(effectiveMode) {
					effectiveMode = override.Mode
				}
			}
		}
	}

	return effectiveMode
}

// modeRestrictiveness returns a numeric value for mode comparison.
// Lower = more restrictive (less actions allowed).
func modeRestrictiveness(m Mode) int {
	switch m {
	case ModeObserve:
		return 0 // Most restrictive (no changes)
	case ModeProtect:
		return 1 // Medium (create only)
	case ModeEnforce:
		return 2 // Least restrictive (all changes)
	default:
		return 0
	}
}

// globMatch performs simple glob matching with *.
func globMatch(value, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(value, pattern)
	}

	// Handle prefix wildcard: "*suffix"
	if strings.HasPrefix(pattern, "*") && !strings.HasSuffix(pattern, "*") {
		suffix := strings.ToLower(pattern[1:])
		return strings.HasSuffix(strings.ToLower(value), suffix)
	}

	// Handle suffix wildcard: "prefix*"
	if strings.HasSuffix(pattern, "*") && !strings.HasPrefix(pattern, "*") {
		prefix := strings.ToLower(pattern[:len(pattern)-1])
		return strings.HasPrefix(strings.ToLower(value), prefix)
	}

	// Handle middle wildcard: "prefix*suffix"
	if strings.Contains(pattern, "*") {
		parts := strings.SplitN(pattern, "*", 2)
		prefix := strings.ToLower(parts[0])
		suffix := strings.ToLower(parts[1])
		valueLower := strings.ToLower(value)
		return strings.HasPrefix(valueLower, prefix) && strings.HasSuffix(valueLower, suffix)
	}

	return false
}
