// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"errors"
	"testing"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

// callTrackingAPI wraps an EC2API and records CreateNetworkInterfacePermission
// and DeleteNetworkInterface calls so tests can assert on call counts
type callTrackingAPI struct {
	EC2API

	permissionCalls []permissionCall
	deleteCalls     []string
	permissionErr   error
}

type permissionCall struct {
	eniID     string
	accountID string
}

func (c *callTrackingAPI) CreateNetworkInterfacePermission(_ context.Context, eniID, accountID string) error {
	c.permissionCalls = append(c.permissionCalls, permissionCall{eniID: eniID, accountID: accountID})
	return c.permissionErr
}

func (c *callTrackingAPI) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	c.deleteCalls = append(c.deleteCalls, eniID)
	return c.EC2API.DeleteNetworkInterface(ctx, eniID)
}

func newTestCrossAccountClient(t *testing.T, local, remote EC2API, localAccountID string) *CrossAccountEC2Client {
	t.Helper()
	return NewCrossAccountEC2Client(hivetest.Logger(t), local, remote, localAccountID)
}

var (
	remoteSubnets = []*ipamTypes.Subnet{
		{ID: "subnet-remote", AvailableAddresses: 50, VirtualNetworkID: "vpc-remote", AvailabilityZone: "us-east-1"},
	}
	localSubnets = []*ipamTypes.Subnet{
		{ID: "subnet-local", AvailableAddresses: 50, VirtualNetworkID: "vpc-local", AvailabilityZone: "us-west-1"},
	}
	remoteVpcs = []*ipamTypes.VirtualNetwork{
		{ID: "vpc-remote", PrimaryCIDR: "10.0.0.0/16"},
	}
	localVpcs = []*ipamTypes.VirtualNetwork{
		{ID: "vpc-local", PrimaryCIDR: "192.168.0.0/16"},
	}
	noRouteTables = []*ipamTypes.RouteTable{}
)

// TestCrossAccountInfraOpsRouteToRemote verifies that infrastructure describe
// operations (subnets, vpcs, route tables) are forwarded to the remote
// (network-account) client and not the local client.
func TestCrossAccountInfraOpsRouteToRemote(t *testing.T) {
	remote := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, noRouteTables)
	local := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
	client := newTestCrossAccountClient(t, local, remote, "111222333444")
	ctx := t.Context()

	t.Run("GetSubnets returns remote subnets", func(t *testing.T) {
		got, err := client.GetSubnets(ctx, "")
		require.NoError(t, err)
		assert.Contains(t, got, "subnet-remote")
		assert.NotContains(t, got, "subnet-local")
	})

	t.Run("GetVpcs returns remote vpcs", func(t *testing.T) {
		got, err := client.GetVpcs(ctx, "")
		require.NoError(t, err)
		assert.Contains(t, got, "vpc-remote")
		assert.NotContains(t, got, "vpc-local")
	})

	t.Run("GetRouteTables returns remote route tables", func(t *testing.T) {
		remoteWithRT := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, []*ipamTypes.RouteTable{
			{ID: "rt-remote", VirtualNetworkID: "vpc-remote"},
		})
		localNoRT := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
		c := newTestCrossAccountClient(t, localNoRT, remoteWithRT, "111222333444")

		got, err := c.GetRouteTables(ctx, "")
		require.NoError(t, err)
		assert.Contains(t, got, "rt-remote")
	})
}

// TestCrossAccountInstanceOpsRouteToLocal verifies that instance-level
// operations (instance types, instance enumeration) use the local client.
func TestCrossAccountInstanceOpsRouteToLocal(t *testing.T) {
	remote := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, noRouteTables)
	local := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
	remote.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{InstanceType: "m5.large"}})
	local.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{InstanceType: "c5.xlarge"}})

	client := newTestCrossAccountClient(t, local, remote, "111222333444")
	ctx := t.Context()

	t.Run("GetInstanceTypes returns local instance types", func(t *testing.T) {
		got, err := client.GetInstanceTypes(ctx)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, ec2_types.InstanceType("c5.xlarge"), got[0].InstanceType)
	})

	t.Run("GetInstances returns local instances", func(t *testing.T) {
		localWithInstance := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
		localWithInstance.UpdateENIs(map[string]ec2mock.ENIMap{
			"i-local": {
				"eni-1": &eniTypes.ENI{
					ID:     "eni-1",
					IP:     "10.0.0.1",
					Number: 0,
					Subnet: eniTypes.AwsSubnet{ID: "subnet-local"},
					VPC:    eniTypes.AwsVPC{ID: "vpc-local"},
				},
			},
		})
		remoteNoInstances := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, noRouteTables)
		c := newTestCrossAccountClient(t, localWithInstance, remoteNoInstances, "111222333444")

		got, err := c.GetInstances(ctx, nil, nil)
		require.NoError(t, err)
		assert.True(t, got.Exists("i-local"), "expected local instance to be present")
	})
}

// TestCrossAccountCreateGrantsPermission verifies that after a successful
// CreateNetworkInterface on the remote, CreateNetworkInterfacePermission is
// called with the new ENI's ID and the configured local account ID.
func TestCrossAccountCreateGrantsPermission(t *testing.T) {
	const localAccountID = "111122223333"

	remote := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, noRouteTables)
	tracking := &callTrackingAPI{EC2API: remote}
	local := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
	client := newTestCrossAccountClient(t, local, tracking, localAccountID)

	eniID, _, err := client.CreateNetworkInterface(t.Context(), 5, "subnet-remote", "test-eni", nil, false)
	require.NoError(t, err)
	require.NotEmpty(t, eniID)

	require.Len(t, tracking.permissionCalls, 1, "expected exactly one permission grant")
	assert.Equal(t, eniID, tracking.permissionCalls[0].eniID)
	assert.Equal(t, localAccountID, tracking.permissionCalls[0].accountID)
	assert.Empty(t, tracking.deleteCalls, "ENI should not be deleted on success")
}

// TestCrossAccountCreateCleansUpOnPermissionFailure verifies that when
// CreateNetworkInterfacePermission fails, the freshly created ENI is
// immediately deleted and the error is propagated — preventing an orphaned ENI
// in the network account.
func TestCrossAccountCreateCleansUpOnPermissionFailure(t *testing.T) {
	permErr := errors.New("simulated permission grant failure")

	remote := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, noRouteTables)
	tracking := &callTrackingAPI{EC2API: remote, permissionErr: permErr}
	local := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
	client := newTestCrossAccountClient(t, local, tracking, "111122223333")

	eniID, eni, err := client.CreateNetworkInterface(t.Context(), 5, "subnet-remote", "test-eni", nil, false)

	assert.ErrorIs(t, err, permErr, "permission error should be propagated to caller")
	assert.Empty(t, eniID)
	assert.Nil(t, eni)

	require.Len(t, tracking.permissionCalls, 1, "permission grant should have been attempted once")
	require.Len(t, tracking.deleteCalls, 1, "the orphaned ENI should have been deleted")
	assert.Equal(t, tracking.permissionCalls[0].eniID, tracking.deleteCalls[0],
		"the deleted ENI should be the same one whose permission grant failed")
}

// TestCrossAccountCreateDoesNotGrantPermissionOnCreateFailure verifies that
// when the remote CreateNetworkInterface itself fails, no permission grant is
// attempted — there is no ENI to grant permission on.
func TestCrossAccountCreateDoesNotGrantPermissionOnCreateFailure(t *testing.T) {
	remote := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, noRouteTables)
	remote.SetMockError(ec2mock.CreateNetworkInterface, errors.New("create failed"))
	tracking := &callTrackingAPI{EC2API: remote}
	local := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
	client := newTestCrossAccountClient(t, local, tracking, "111122223333")

	_, _, err := client.CreateNetworkInterface(t.Context(), 5, "subnet-remote", "test-eni", nil, false)

	require.Error(t, err)
	assert.Empty(t, tracking.permissionCalls, "no permission grant should be attempted if ENI creation failed")
	assert.Empty(t, tracking.deleteCalls)
}

// TestCrossAccountAttachUsesLocalClient verifies that AttachNetworkInterface
// operates via the local (instance-owning account) client. In production this
// is required because AttachNetworkInterface must be called in the context of
// the account that owns the target instance.
func TestCrossAccountAttachUsesLocalClient(t *testing.T) {
	ctx := t.Context()

	localMock := ec2mock.NewAPI(localSubnets, localVpcs, nil, noRouteTables)
	remoteMock := ec2mock.NewAPI(remoteSubnets, remoteVpcs, nil, noRouteTables)

	// Create an unattached ENI directly in the local mock so AttachNetworkInterface
	// has something to attach.  We also prime an instance entry so the mock
	// accepts the attach call.
	localMock.UpdateENIs(map[string]ec2mock.ENIMap{"i-local": {}})
	eniID, _, err := localMock.CreateNetworkInterface(ctx, 1, "subnet-local", "test", nil, false)
	require.NoError(t, err)
	require.NotEmpty(t, eniID)

	// Make the same ENI unavailable in remote to confirm routing.
	remoteMock.SetMockError(ec2mock.AttachNetworkInterface, errors.New("should not reach remote"))

	client := newTestCrossAccountClient(t, localMock, remoteMock, "111122223333")

	_, err = client.AttachNetworkInterface(ctx, 1, "i-local", eniID)
	require.NoError(t, err, "attach should succeed via local client")
}
