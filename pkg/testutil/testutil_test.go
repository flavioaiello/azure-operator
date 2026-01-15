package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test constants to avoid literal duplication.
const (
	testVNetResourceID   = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test-rg/providers/Microsoft.Network/virtualNetworks/test-vnet"
	testResourceTypeVNet = "Microsoft.Network/virtualNetworks"
)

func TestNewMockCredential(t *testing.T) {
	clientID := "test-client-id"
	cred := NewMockCredential(&clientID)

	assert.NotNil(t, cred)
	assert.Equal(t, &clientID, cred.ClientID())
	assert.Equal(t, 0, cred.GetTokenCallCount())
}

func TestMockCredentialGetToken(t *testing.T) {
	cred := NewMockCredential(nil)

	token, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})

	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)
	assert.True(t, token.ExpiresOn.After(time.Now()))
	assert.Equal(t, 1, cred.GetTokenCallCount())
}

func TestMockCredentialGetTokenFailure(t *testing.T) {
	cred := NewMockCredential(nil)
	cred.SetFailure(true, "auth failed")

	_, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth failed")
}

func TestMockCredentialGetTokenCancelled(t *testing.T) {
	cred := NewMockCredential(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := cred.GetToken(ctx, policy.TokenRequestOptions{})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestNewMockResourceState(t *testing.T) {
	state := NewMockResourceState()

	assert.NotNil(t, state)
	assert.Equal(t, 0, state.ResourceCount())
	assert.Equal(t, 0, state.DeploymentCount())
}

func TestMockResourceStatePutAndGetResource(t *testing.T) {
	state := NewMockResourceState()

	resource := NewMockResource(
		testVNetResourceID,
		testResourceTypeVNet,
		"vnet1",
		"westeurope",
	)
	resource.Properties["addressSpace"] = map[string]interface{}{
		"addressPrefixes": []string{"10.0.0.0/16"},
	}

	err := state.PutResource(resource)
	require.NoError(t, err)

	retrieved := state.GetResource(resource.ResourceID)
	assert.NotNil(t, retrieved)
	assert.Equal(t, resource.Name, retrieved.Name)
	assert.Equal(t, resource.ResourceType, retrieved.ResourceType)
}

func TestMockResourceStateListResources(t *testing.T) {
	state := NewMockResourceState()

	err := state.PutResource(NewMockResource(
		testVNetResourceID,
		testResourceTypeVNet,
		"vnet1",
		"westeurope",
	))
	require.NoError(t, err)

	err = state.PutResource(NewMockResource(
		"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/subnets/subnet1",
		"Microsoft.Network/subnets",
		"subnet1",
		"westeurope",
	))
	require.NoError(t, err)

	// List all
	all := state.ListResources(nil, nil)
	assert.Len(t, all, 2)

	// Filter by type
	vnetType := testResourceTypeVNet
	vnets := state.ListResources(&vnetType, nil)
	assert.Len(t, vnets, 1)
}

func TestMockResourceStateDeleteResource(t *testing.T) {
	state := NewMockResourceState()

	resourceID := testVNetResourceID
	err := state.PutResource(NewMockResource(resourceID, testResourceTypeVNet, "vnet1", "westeurope"))
	require.NoError(t, err)

	assert.Equal(t, 1, state.ResourceCount())

	deleted := state.DeleteResource(resourceID)
	assert.True(t, deleted)
	assert.Equal(t, 0, state.ResourceCount())

	// Delete non-existent
	deleted = state.DeleteResource(resourceID)
	assert.False(t, deleted)
}

func TestMockResourceStateDeployments(t *testing.T) {
	state := NewMockResourceState()

	deployment := &MockDeployment{
		Name:              "deploy1",
		SubscriptionID:    "sub1",
		Location:          "westeurope",
		Template:          map[string]interface{}{},
		Parameters:        map[string]interface{}{},
		Mode:              "Incremental",
		ProvisioningState: DeploymentStateAccepted,
		Timestamp:         time.Now(),
	}

	err := state.CreateDeployment(deployment)
	require.NoError(t, err)

	retrieved := state.GetDeployment("deploy1")
	assert.NotNil(t, retrieved)
	assert.Equal(t, DeploymentStateAccepted, retrieved.ProvisioningState)

	// Update state
	err = state.UpdateDeploymentState("deploy1", DeploymentStateSucceeded, nil, nil)
	require.NoError(t, err)

	retrieved = state.GetDeployment("deploy1")
	assert.Equal(t, DeploymentStateSucceeded, retrieved.ProvisioningState)
}

func TestMockResourceStateComputeWhatIfCreate(t *testing.T) {
	state := NewMockResourceState()

	template := map[string]interface{}{
		"resources": []interface{}{
			map[string]interface{}{
				"type":     testResourceTypeVNet,
				"name":     "vnet1",
				"location": "westeurope",
				"properties": map[string]interface{}{
					"addressSpace": []string{"10.0.0.0/16"},
				},
			},
		},
	}

	result := state.ComputeWhatIf(template, "sub1", nil, nil)

	assert.Equal(t, "Succeeded", result.Status)
	assert.Len(t, result.Changes, 1)
	assert.Equal(t, WhatIfChangeCreate, result.Changes[0].ChangeType)
	assert.True(t, result.HasChanges())
}

func TestNewMockGraphClient(t *testing.T) {
	client := NewMockGraphClient()

	assert.NotNil(t, client)
	assert.Equal(t, 0, client.QueryCount())
}

func TestMockGraphClientQueryResources(t *testing.T) {
	client := NewMockGraphClient()

	client.AddResource(MockGraphResource{
		ResourceID:     testVNetResourceID,
		Name:           "vnet1",
		Type:           testResourceTypeVNet,
		Location:       "westeurope",
		SubscriptionID: "sub1",
	})

	results, err := client.QueryResources(context.Background(), "resources", []string{"sub1"})
	require.NoError(t, err)

	assert.Len(t, results, 1)
	assert.Equal(t, "vnet1", results[0]["name"])
	assert.Equal(t, 1, client.QueryCount())
}

func TestMockGraphClientQueryChanges(t *testing.T) {
	client := NewMockGraphClient()

	now := time.Now()
	client.AddChange(MockGraphChange{
		ResourceID: testVNetResourceID,
		ChangeType: "Update",
		ChangedBy:  "user@example.com",
		Timestamp:  now,
	})

	changes, err := client.QueryChanges(
		context.Background(),
		[]string{testVNetResourceID},
		now.Add(-time.Hour),
		now.Add(time.Hour),
	)
	require.NoError(t, err)

	assert.Len(t, changes, 1)
	assert.Equal(t, "Update", changes[0].ChangeType)
}

func TestMockGraphClientFailure(t *testing.T) {
	client := NewMockGraphClient()
	client.SetShouldFail(true, "graph error")

	_, err := client.QueryResources(context.Background(), "resources", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "graph error")
}

func TestNewMockResourceClient(t *testing.T) {
	client := NewMockResourceClient(nil)

	assert.NotNil(t, client)
	assert.NotNil(t, client.State())
}

func TestMockResourceClientDeploy(t *testing.T) {
	client := NewMockResourceClient(nil)

	input := DeployInput{
		Name:           "deploy1",
		SubscriptionID: "sub1",
		Location:       "westeurope",
		Template: map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"type":     testResourceTypeVNet,
					"name":     "vnet1",
					"location": "westeurope",
				},
			},
		},
		Parameters: map[string]interface{}{},
		Mode:       "Incremental",
	}

	deployment, err := client.Deploy(context.Background(), input)
	require.NoError(t, err)

	assert.NotNil(t, deployment)
	assert.Equal(t, DeploymentStateSucceeded, deployment.ProvisioningState)
	assert.Equal(t, 1, client.State().DeploymentCount())
	assert.Equal(t, 1, client.State().ResourceCount())
}

func TestMockResourceClientDeployFailure(t *testing.T) {
	client := NewMockResourceClient(nil)
	client.SetDeploymentFailure(true, "deployment failed")

	input := DeployInput{
		Name:           "deploy1",
		SubscriptionID: "sub1",
		Location:       "westeurope",
		Template:       map[string]interface{}{},
		Parameters:     map[string]interface{}{},
		Mode:           "Incremental",
	}

	deployment, err := client.Deploy(context.Background(), input)
	require.NoError(t, err)

	assert.Equal(t, DeploymentStateFailed, deployment.ProvisioningState)
	assert.NotNil(t, deployment.Error)
}

func TestMockResourceClientWhatIf(t *testing.T) {
	client := NewMockResourceClient(nil)

	input := DeployInput{
		Name:           "whatif1",
		SubscriptionID: "sub1",
		Location:       "westeurope",
		Template: map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"type":     testResourceTypeVNet,
					"name":     "vnet1",
					"location": "westeurope",
				},
			},
		},
		Parameters: map[string]interface{}{},
	}

	result, err := client.WhatIf(context.Background(), input)
	require.NoError(t, err)

	assert.Equal(t, "Succeeded", result.Status)
	assert.True(t, result.HasChanges())
}

func TestNewMockContext(t *testing.T) {
	ctx := NewMockContext()
	defer ctx.Close()

	assert.NotNil(t, ctx.Credential())
	assert.NotNil(t, ctx.State())
	assert.NotNil(t, ctx.ResourceClient())
	assert.NotNil(t, ctx.GraphClient())
}

func TestMockContextWithOptions(t *testing.T) {
	clientID := "test-client"
	ctx := NewMockContext(
		WithClientID(clientID),
		WithInitialResources([]*MockResource{
			NewMockResource(
				testVNetResourceID,
				testResourceTypeVNet,
				"vnet1",
				"westeurope",
			),
		}),
	)
	defer ctx.Close()

	assert.Equal(t, &clientID, ctx.Credential().ClientID())
	assert.Equal(t, 1, ctx.ResourceCount())
}

func TestMockContextClear(t *testing.T) {
	ctx := NewMockContext()

	err := ctx.State().PutResource(NewMockResource(
		testVNetResourceID,
		testResourceTypeVNet,
		"vnet1",
		"westeurope",
	))
	require.NoError(t, err)

	assert.Equal(t, 1, ctx.ResourceCount())

	ctx.Clear()

	assert.Equal(t, 0, ctx.ResourceCount())
}

func TestMockDeploymentID(t *testing.T) {
	rg := "rg-test"
	deployment := &MockDeployment{
		Name:           "deploy1",
		SubscriptionID: "sub1",
		ResourceGroup:  &rg,
	}

	assert.Contains(t, deployment.ID(), "sub1")
	assert.Contains(t, deployment.ID(), "rg-test")
	assert.Contains(t, deployment.ID(), "deploy1")
}
