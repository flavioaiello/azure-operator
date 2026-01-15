package specs

import (
	"testing"
)

// Test constants.
const (
	testResourceGroup = "rg-test"
)

func TestGenericSpec_Validate(t *testing.T) {
	tests := []struct {
		name    string
		spec    *GenericSpec
		wantErr bool
	}{
		{
			name:    "empty spec is valid",
			spec:    &GenericSpec{},
			wantErr: false,
		},
		{
			name: "spec with all fields is valid",
			spec: &GenericSpec{
				Operator:          "connectivity",
				Location:          "westeurope",
				ResourceGroupName: testResourceGroup,
				Tags: map[string]string{
					"environment": "test",
				},
				DependsOn: []string{"management", "identity"},
				Parameters: map[string]interface{}{
					"vnetAddressSpace": "10.0.0.0/16",
					"enableDdos":       true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenericSpec.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenericSpec_ToARMParameters(t *testing.T) {
	tests := []struct {
		name         string
		spec         *GenericSpec
		wantKeys     []string
		dontWantKeys []string
	}{
		{
			name: "location is converted to ARM parameter",
			spec: &GenericSpec{
				Location: "westeurope",
			},
			wantKeys: []string{"location"},
		},
		{
			name: "resourceGroupName is converted to ARM parameter",
			spec: &GenericSpec{
				ResourceGroupName: testResourceGroup,
			},
			wantKeys: []string{"resourceGroupName"},
		},
		{
			name: "tags are converted to ARM parameter",
			spec: &GenericSpec{
				Tags: map[string]string{
					"env": "prod",
				},
			},
			wantKeys: []string{"tags"},
		},
		{
			name: "dependsOn is not included in ARM parameters",
			spec: &GenericSpec{
				DependsOn: []string{"management"},
			},
			dontWantKeys: []string{"dependsOn"},
		},
		{
			name: "custom parameters are passed through",
			spec: &GenericSpec{
				Parameters: map[string]interface{}{
					"customParam":   "value",
					"enableFeature": true,
				},
			},
			wantKeys: []string{"customParam", "enableFeature"},
		},
		{
			name:     "empty spec returns empty parameters",
			spec:     &GenericSpec{},
			wantKeys: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.ToARMParameters()
			for _, key := range tt.wantKeys {
				if _, ok := got[key]; !ok {
					t.Errorf("ToARMParameters() missing expected key %q", key)
				}
			}
			for _, key := range tt.dontWantKeys {
				if _, ok := got[key]; ok {
					t.Errorf("ToARMParameters() should not contain key %q", key)
				}
			}
		})
	}
}

func TestGenericSpec_ToARMParameters_Format(t *testing.T) {
	spec := &GenericSpec{
		Location: "eastus",
		Parameters: map[string]interface{}{
			"vmSize": "Standard_D2s_v3",
		},
	}

	params := spec.ToARMParameters()

	// Check that parameters are wrapped in ARM format {value: ...}
	if locationParam, ok := params["location"].(map[string]interface{}); ok {
		if val, ok := locationParam["value"]; !ok || val != "eastus" {
			t.Errorf("location parameter not in ARM format {value: 'eastus'}, got %v", locationParam)
		}
	} else {
		t.Error("location parameter not in expected ARM format")
	}

	if vmSizeParam, ok := params["vmSize"].(map[string]interface{}); ok {
		if val, ok := vmSizeParam["value"]; !ok || val != "Standard_D2s_v3" {
			t.Errorf("vmSize parameter not in ARM format, got %v", vmSizeParam)
		}
	} else {
		t.Error("vmSize parameter not in expected ARM format")
	}
}

func TestGenericSpec_GetDependsOn(t *testing.T) {
	tests := []struct {
		name string
		spec *GenericSpec
		want []string
	}{
		{
			name: "nil dependsOn returns nil",
			spec: &GenericSpec{},
			want: nil,
		},
		{
			name: "empty dependsOn returns empty",
			spec: &GenericSpec{DependsOn: []string{}},
			want: []string{},
		},
		{
			name: "single dependency",
			spec: &GenericSpec{DependsOn: []string{"management"}},
			want: []string{"management"},
		},
		{
			name: "multiple dependencies",
			spec: &GenericSpec{DependsOn: []string{"management", "identity", "connectivity"}},
			want: []string{"management", "identity", "connectivity"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetDependsOn()
			if len(got) != len(tt.want) {
				t.Errorf("GetDependsOn() = %v, want %v", got, tt.want)
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("GetDependsOn()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestGenericSpec_GetOperator(t *testing.T) {
	tests := []struct {
		name string
		spec *GenericSpec
		want string
	}{
		{
			name: "empty operator",
			spec: &GenericSpec{},
			want: "",
		},
		{
			name: "connectivity operator",
			spec: &GenericSpec{Operator: "connectivity"},
			want: "connectivity",
		},
		{
			name: "management operator",
			spec: &GenericSpec{Operator: "management"},
			want: "management",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.spec.GetOperator(); got != tt.want {
				t.Errorf("GetOperator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenericSpec_ImplementsSpec(_ *testing.T) {
	// Compile-time check that GenericSpec implements Spec interface.
	var _ Spec = (*GenericSpec)(nil)
}

func TestArmParam(t *testing.T) {
	// Test simple comparable types
	t.Run("string value", func(t *testing.T) {
		result := armParam("test")
		if val, ok := result["value"]; !ok || val != "test" {
			t.Errorf("armParam(\"test\") = %v, want {value: test}", result)
		}
	})

	t.Run("int value", func(t *testing.T) {
		result := armParam(42)
		if val, ok := result["value"]; !ok || val != 42 {
			t.Errorf("armParam(42) = %v, want {value: 42}", result)
		}
	})

	t.Run("bool value", func(t *testing.T) {
		result := armParam(true)
		if val, ok := result["value"]; !ok || val != true {
			t.Errorf("armParam(true) = %v, want {value: true}", result)
		}
	})

	// Test that maps are wrapped (can't compare directly due to type)
	t.Run("map value", func(t *testing.T) {
		input := map[string]string{"key": "value"}
		result := armParam(input)
		if _, ok := result["value"]; !ok {
			t.Error("armParam(map) should have 'value' key")
		}
	})

	// Test that slices are wrapped (can't compare directly due to type)
	t.Run("slice value", func(t *testing.T) {
		input := []string{"a", "b", "c"}
		result := armParam(input)
		if _, ok := result["value"]; !ok {
			t.Error("armParam(slice) should have 'value' key")
		}
	})
}

// TestGenericSpec_SkipsReservedFields verifies that reserved fields
// in Parameters are not duplicated in ARM output.
func TestGenericSpec_SkipsReservedFields(t *testing.T) {
	spec := &GenericSpec{
		Location:          "westeurope",
		ResourceGroupName: testResourceGroup,
		Tags:              map[string]string{"env": "test"},
		DependsOn:         []string{"identity"},
		Parameters: map[string]interface{}{
			// These should be skipped as they're handled by base fields.
			"location":          "eastus",                              // Should be ignored
			"resourceGroupName": "rg-override",                         // Should be ignored
			"tags":              map[string]string{"override": "true"}, // Should be ignored
			"dependsOn":         []string{"should-not-appear"},         // Should be ignored
			// This should be included.
			"customParam": "included",
		},
	}

	params := spec.ToARMParameters()

	// Check that base field values are used, not Parameters overrides.
	if loc, ok := params["location"].(map[string]interface{}); ok {
		if loc["value"] != "westeurope" {
			t.Errorf("location should be 'westeurope', got %v", loc["value"])
		}
	}

	if rg, ok := params["resourceGroupName"].(map[string]interface{}); ok {
		if rg["value"] != testResourceGroup {
			t.Errorf("resourceGroupName should be 'rg-test', got %v", rg["value"])
		}
	}

	// dependsOn should not be in ARM parameters.
	if _, ok := params["dependsOn"]; ok {
		t.Error("dependsOn should not be in ARM parameters")
	}

	// customParam should be included.
	if _, ok := params["customParam"]; !ok {
		t.Error("customParam should be in ARM parameters")
	}
}
