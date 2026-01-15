package bootstrap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConstants(t *testing.T) {
	assert.Equal(t, 30*time.Second, RBACPropagationDelay)
	assert.Equal(t, 5, MaxRBACRetries)
	assert.Equal(t, 30*time.Second, IdentityCheckTimeout)
}

func TestRoleDefinitions(t *testing.T) {
	assert.Contains(t, RoleContributor, "roleDefinitions")
	assert.Contains(t, RoleReader, "roleDefinitions")
	assert.Contains(t, RoleNetworkContributor, "roleDefinitions")
	assert.Contains(t, RoleSecurityAdmin, "roleDefinitions")
	assert.Contains(t, RoleKeyVaultContributor, "roleDefinitions")
	assert.Contains(t, RoleMonitoringContributor, "roleDefinitions")
}

func TestGenerateAssignmentName(t *testing.T) {
	name1 := generateAssignmentName("/subscriptions/sub1", RoleContributor, "principal1")
	name2 := generateAssignmentName("/subscriptions/sub1", RoleContributor, "principal1")
	name3 := generateAssignmentName("/subscriptions/sub1", RoleContributor, "principal2")

	// Same inputs should produce same name (deterministic).
	assert.Equal(t, name1, name2)
	// Different principal should produce different names.
	assert.NotEqual(t, name1, name3)
	// Name should be non-empty.
	assert.NotEmpty(t, name1)
}

func TestIsAlreadyExistsError(t *testing.T) {
	assert.False(t, isAlreadyExistsError(nil))
}

func TestIsNotFoundError(t *testing.T) {
	assert.False(t, isNotFoundError(nil))
}

func TestToStringPtrMap(t *testing.T) {
	input := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}

	result := toStringPtrMap(input)
	assert.Len(t, result, 2)
	assert.Equal(t, "value1", *result["key1"])
	assert.Equal(t, "value2", *result["key2"])
}

func TestToPtr(t *testing.T) {
	s := "test"
	ptr := toPtr(s)
	assert.Equal(t, "test", *ptr)

	i := 42
	iPtr := toPtr(i)
	assert.Equal(t, 42, *iPtr)
}

func TestOperatorIdentity(t *testing.T) {
	identity := OperatorIdentity{
		Name:          "id-connectivity",
		Domain:        "connectivity",
		PrincipalID:   "00000000-0000-0000-0000-000000000001",
		ClientID:      "00000000-0000-0000-0000-000000000002",
		ResourceID:    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-connectivity",
		ResourceGroup: "rg-identity",
	}

	assert.Equal(t, "id-connectivity", identity.Name)
	assert.Equal(t, "connectivity", identity.Domain)
	assert.NotEmpty(t, identity.PrincipalID)
}

func TestRoleAssignment(t *testing.T) {
	assignment := RoleAssignment{
		RoleDefinitionID: RoleContributor,
		Scope:            "/subscriptions/sub-123",
		PrincipalID:      "principal-456",
		Description:      "Connectivity operator contributor access",
	}

	assert.Contains(t, assignment.RoleDefinitionID, "roleDefinitions")
	assert.Contains(t, assignment.Scope, "subscriptions")
}

func TestBootstrapSpec(t *testing.T) {
	spec := BootstrapSpec{
		Operators: []OperatorConfig{
			{
				Name:   "connectivity",
				Domain: "connectivity",
				Roles:  []string{"NetworkContributor"},
				Scopes: []string{"/subscriptions/sub-123"},
			},
		},
		ResourceGroupName:      "rg-identity",
		Location:               "westeurope",
		RBACPropagationSeconds: 60,
	}

	assert.Len(t, spec.Operators, 1)
	assert.Equal(t, "connectivity", spec.Operators[0].Name)
}

func TestOperatorConfig_DependsOn(t *testing.T) {
	cfg := OperatorConfig{
		Name:      "firewall",
		Domain:    "firewall",
		Roles:     []string{"NetworkContributor"},
		DependsOn: []string{"connectivity"},
	}

	assert.Contains(t, cfg.DependsOn, "connectivity")
}

func TestErrors(t *testing.T) {
	assert.NotEqual(t, ErrIdentityNotFound, ErrRBACAssignmentFailed)
	assert.NotEqual(t, ErrIdentityCreationFailed, ErrRBACPropagationFailed)
}

func TestMin(t *testing.T) {
	assert.Equal(t, 5, min(5, 10))
	assert.Equal(t, 5, min(10, 5))
	assert.Equal(t, 5, min(5, 5))
}
