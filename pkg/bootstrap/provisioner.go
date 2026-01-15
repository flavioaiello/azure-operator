// Package bootstrap provides bootstrap operator functionality.
//
// The bootstrap operator provisions:
//  1. Managed identities for downstream operators
//  2. RBAC role assignments with least-privilege scopes
//  3. Operator cascade with dependency ordering
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"go.uber.org/zap"
)

// Config defines the minimal configuration needed by bootstrap.
type Config struct {
	SubscriptionID string
}

// Constants for bootstrap operations.
const (
	// RBACPropagationDelay is the time to wait for RBAC to propagate.
	RBACPropagationDelay = 30 * time.Second
	// MaxRBACRetries is the maximum retries for RBAC verification.
	MaxRBACRetries = 5
	// IdentityCheckTimeout is the timeout for identity existence checks.
	IdentityCheckTimeout = 30 * time.Second
)

// Standard role definition IDs.
var (
	RoleContributor           = "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
	RoleReader                = "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
	RoleNetworkContributor    = "/providers/Microsoft.Authorization/roleDefinitions/4d97b98b-1d4f-4787-a291-c67834d212e7"
	RoleSecurityAdmin         = "/providers/Microsoft.Authorization/roleDefinitions/fb1c8493-542b-48eb-b624-b4c8fea62acd"
	RoleKeyVaultContributor   = "/providers/Microsoft.Authorization/roleDefinitions/f25e0fa2-a7c8-4377-a976-54943a77a395"
	RoleMonitoringContributor = "/providers/Microsoft.Authorization/roleDefinitions/749f88d5-cbae-40b8-bcfc-e573ddc772fa"
)

// Errors.
var (
	ErrIdentityNotFound       = errors.New("managed identity not found")
	ErrRBACAssignmentFailed   = errors.New("RBAC assignment failed")
	ErrIdentityCreationFailed = errors.New("identity creation failed")
	ErrRBACPropagationFailed  = errors.New("RBAC propagation verification failed")
)

// OperatorIdentity represents an operator's managed identity.
type OperatorIdentity struct {
	Name          string
	Domain        string
	PrincipalID   string
	ClientID      string
	ResourceID    string
	ResourceGroup string
}

// RoleAssignment represents an RBAC role assignment.
type RoleAssignment struct {
	RoleDefinitionID string
	Scope            string
	PrincipalID      string
	Description      string
}

// BootstrapSpec defines bootstrap configuration.
type BootstrapSpec struct {
	// Operators lists operators to provision.
	Operators []OperatorConfig `yaml:"operators"`
	// ResourceGroupName for managed identities.
	ResourceGroupName string `yaml:"resourceGroupName"`
	// Location for identity resources.
	Location string `yaml:"location"`
	// RBACPropagationSeconds overrides default wait time.
	RBACPropagationSeconds int `yaml:"rbacPropagationSeconds"`
}

// OperatorConfig defines a single operator.
type OperatorConfig struct {
	Name      string   `yaml:"name"`
	Domain    string   `yaml:"domain"`
	Roles     []string `yaml:"roles"`
	Scopes    []string `yaml:"scopes"`
	DependsOn []string `yaml:"dependsOn"`
}

// Provisioner handles bootstrap operations.
type Provisioner struct {
	config           *Config
	logger           *zap.Logger
	credential       azcore.TokenCredential
	identitiesClient *armmsi.UserAssignedIdentitiesClient
	roleClient       *armauthorization.RoleAssignmentsClient
	resourcesClient  *armresources.Client
}

// NewProvisioner creates a new bootstrap reconciler.
func NewProvisioner(
	cfg *Config,
	logger *zap.Logger,
	cred azcore.TokenCredential,
) (*Provisioner, error) {
	identitiesClient, err := armmsi.NewUserAssignedIdentitiesClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identities client: %w", err)
	}

	roleClient, err := armauthorization.NewRoleAssignmentsClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	resourcesClient, err := armresources.NewClient(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resources client: %w", err)
	}

	return &Provisioner{
		config:           cfg,
		logger:           logger,
		credential:       cred,
		identitiesClient: identitiesClient,
		roleClient:       roleClient,
		resourcesClient:  resourcesClient,
	}, nil
}

// ProvisionIdentity creates or updates a managed identity.
func (p *Provisioner) ProvisionIdentity(
	ctx context.Context,
	name string,
	resourceGroup string,
	location string,
	tags map[string]string,
) (*OperatorIdentity, error) {
	p.logger.Info("Provisioning managed identity",
		zap.String("name", name),
		zap.String("resourceGroup", resourceGroup),
	)

	identity := armmsi.Identity{
		Location: &location,
		Tags:     toStringPtrMap(tags),
	}

	resp, err := p.identitiesClient.CreateOrUpdate(ctx, resourceGroup, name, identity, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdentityCreationFailed, err)
	}

	result := &OperatorIdentity{
		Name:          name,
		ResourceGroup: resourceGroup,
	}

	if resp.Properties != nil {
		if resp.Properties.PrincipalID != nil {
			result.PrincipalID = *resp.Properties.PrincipalID
		}
		if resp.Properties.ClientID != nil {
			result.ClientID = *resp.Properties.ClientID
		}
	}
	if resp.ID != nil {
		result.ResourceID = *resp.ID
	}

	p.logger.Info("Managed identity provisioned",
		zap.String("name", name),
		zap.String("principalId", result.PrincipalID),
	)

	return result, nil
}

// AssignRole creates an RBAC role assignment.
func (p *Provisioner) AssignRole(
	ctx context.Context,
	assignment RoleAssignment,
) error {
	p.logger.Info("Assigning RBAC role",
		zap.String("roleDefinitionId", assignment.RoleDefinitionID),
		zap.String("scope", assignment.Scope),
		zap.String("principalId", assignment.PrincipalID),
	)

	// Generate deterministic assignment name.
	assignmentName := generateAssignmentName(
		assignment.Scope,
		assignment.RoleDefinitionID,
		assignment.PrincipalID,
	)

	params := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: &assignment.RoleDefinitionID,
			PrincipalID:      &assignment.PrincipalID,
			PrincipalType:    toPtr(armauthorization.PrincipalTypeServicePrincipal),
			Description:      &assignment.Description,
		},
	}

	_, err := p.roleClient.Create(ctx, assignment.Scope, assignmentName, params, nil)
	if err != nil {
		// Check if already exists (idempotent).
		if isAlreadyExistsError(err) {
			p.logger.Debug("Role assignment already exists",
				zap.String("assignmentName", assignmentName),
			)
			return nil
		}
		return fmt.Errorf("%w: %v", ErrRBACAssignmentFailed, err)
	}

	p.logger.Info("RBAC role assigned",
		zap.String("assignmentName", assignmentName),
	)

	return nil
}

// WaitForRBACPropagation waits for RBAC changes to propagate.
func (p *Provisioner) WaitForRBACPropagation(ctx context.Context, delay time.Duration) error {
	p.logger.Info("Waiting for RBAC propagation",
		zap.Duration("delay", delay),
	)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

// VerifyIdentityExists checks if an identity exists.
func (p *Provisioner) VerifyIdentityExists(
	ctx context.Context,
	name string,
	resourceGroup string,
) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, IdentityCheckTimeout)
	defer cancel()

	_, err := p.identitiesClient.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// GetIdentity retrieves an existing identity.
func (p *Provisioner) GetIdentity(
	ctx context.Context,
	name string,
	resourceGroup string,
) (*OperatorIdentity, error) {
	resp, err := p.identitiesClient.Get(ctx, resourceGroup, name, nil)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrIdentityNotFound
		}
		return nil, err
	}

	result := &OperatorIdentity{
		Name:          name,
		ResourceGroup: resourceGroup,
	}

	if resp.Properties != nil {
		if resp.Properties.PrincipalID != nil {
			result.PrincipalID = *resp.Properties.PrincipalID
		}
		if resp.Properties.ClientID != nil {
			result.ClientID = *resp.Properties.ClientID
		}
	}
	if resp.ID != nil {
		result.ResourceID = *resp.ID
	}

	return result, nil
}

// generateAssignmentName creates a deterministic GUID for role assignment.
func generateAssignmentName(scope, roleDefID, principalID string) string {
	// Use a hash of scope + role + principal for deterministic naming.
	// Create a deterministic UUID v5-style name using simple hash.
	combined := fmt.Sprintf("%s|%s|%s", scope, roleDefID, principalID)
	hash := simpleHash(combined)
	// Format as UUID-like string for Azure role assignment.
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}

// simpleHash creates a simple 16-byte hash.
func simpleHash(s string) []byte {
	result := make([]byte, 16)
	for i, b := range []byte(s) {
		result[i%16] ^= b
		// Mix bits.
		result[(i+1)%16] = result[(i+1)%16] ^ (b >> 4) ^ (byte(i) << 2)
	}
	return result
}

// isAlreadyExistsError checks if error is "already exists".
func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsSubstr(errStr, "RoleAssignmentExists") || containsSubstr(errStr, "already exists")
}

// isNotFoundError checks if error is "not found".
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsSubstr(errStr, "ResourceNotFound") || containsSubstr(errStr, "not found")
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toStringPtrMap(m map[string]string) map[string]*string {
	result := make(map[string]*string)
	for k, v := range m {
		v := v
		result[k] = &v
	}
	return result
}

func toPtr[T any](v T) *T {
	return &v
}
