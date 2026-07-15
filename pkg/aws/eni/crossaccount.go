// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"log/slog"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// CrossAccountEC2Client splits EC2 API calls between two accounts:
//   - remote: ownwer of the VPC and pod subnets. This handles all ENI lifecycle operations
//   - local: owner of the EC2 instances. This handles all instance-level operations including attachments
//
// After CreateNetworkInterface succeeds on the remote client, a
// CreateNetworkInterfacePermission call grants the local account INSTANCE-ATTACH
// access so that AttachNetworkInterface can be called from the local account.
type CrossAccountEC2Client struct {
	logger         *slog.Logger
	local          EC2API
	remote         EC2API
	localAccountID string
}

// NewCrossAccountEC2Client constructs a CrossAccountEC2Client.
// the localAccountID is needed to setup every CreateNetworkInterfacePermission
func NewCrossAccountEC2Client(logger *slog.Logger, local, remote EC2API, localAccountID string) *CrossAccountEC2Client {
	return &CrossAccountEC2Client{
		logger:         logger,
		local:          local,
		remote:         remote,
		localAccountID: localAccountID,
	}
}

// *********************************************************************************
// --- VPC / Subnet / ENI-owner accouint operations → remote (network account) ---
// *********************************************************************************

// The vpcID passed in by InstancesManager comes from local IMDS and refers to
// the cluster-account VPC. It doesn't exist in the network account, so we drop
// it here and let the remote client rely solely on the subnet/tag filters
// configured via IPAMSubnetsTags / IPAMSubnetsIDs.
func (c *CrossAccountEC2Client) GetSubnets(ctx context.Context, _ string) (ipamTypes.SubnetMap, error) {
	return c.remote.GetSubnets(ctx, "")
}

func (c *CrossAccountEC2Client) GetVpcs(ctx context.Context, _ string) (ipamTypes.VirtualNetworkMap, error) {
	return c.remote.GetVpcs(ctx, "")
}

func (c *CrossAccountEC2Client) GetRouteTables(ctx context.Context, _ string) (ipamTypes.RouteTableMap, error) {
	return c.remote.GetRouteTables(ctx, "")
}

func (c *CrossAccountEC2Client) GetSecurityGroups(ctx context.Context, _ string) (types.SecurityGroupMap, error) {
	return c.remote.GetSecurityGroups(ctx, "")
}

func (c *CrossAccountEC2Client) GetDetachedNetworkInterfaces(ctx context.Context, tags ipamTypes.Tags, maxResults int32) ([]string, error) {
	return c.remote.GetDetachedNetworkInterfaces(ctx, tags, maxResults)
}

// CreateNetworkInterface creates the ENI in the remote account's subnet, then
// immediately grants the local account INSTANCE-ATTACH permission so that
// AttachNetworkInterface (local) can succeed.
func (c *CrossAccountEC2Client) CreateNetworkInterface(ctx context.Context, toAllocate int32, subnetID, desc string, groups []string, allocatePrefixes bool) (string, *eniTypes.ENI, error) {
	eniID, eni, err := c.remote.CreateNetworkInterface(ctx, toAllocate, subnetID, desc, groups, allocatePrefixes)
	if err != nil {
		return "", nil, err
	}

	if permErr := c.remote.CreateNetworkInterfacePermission(ctx, eniID, c.localAccountID); permErr != nil {
		// Permission grant call failed. Delete the orphaned eni and rethrow
		c.logger.Warn(
			"Failed to grant cross-account ENI attach permission. Deleting orphaned ENI",
			logfields.ENI, eniID,
			logfields.Error, permErr,
		)
		if delErr := c.remote.DeleteNetworkInterface(ctx, eniID); delErr != nil {
			//TODO: maybe make a bigger deal of this
			c.logger.Warn("Failed to delete orphaned ENI",
				logfields.ENI, eniID,
				logfields.Error, delErr,
			)
		}
		return "", nil, permErr
	}

	return eniID, eni, nil
}

func (c *CrossAccountEC2Client) CreateNetworkInterfacePermission(ctx context.Context, eniID string, accountID string) error {
	return c.remote.CreateNetworkInterfacePermission(ctx, eniID, accountID)
}

func (c *CrossAccountEC2Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	return c.remote.DeleteNetworkInterface(ctx, eniID)
}

func (c *CrossAccountEC2Client) AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int32) ([]string, error) {
	return c.remote.AssignPrivateIpAddresses(ctx, eniID, addresses)
}

func (c *CrossAccountEC2Client) UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error {
	return c.remote.UnassignPrivateIpAddresses(ctx, eniID, addresses)
}

func (c *CrossAccountEC2Client) AssignENIPrefixes(ctx context.Context, eniID string, prefixes int32) error {
	return c.remote.AssignENIPrefixes(ctx, eniID, prefixes)
}

func (c *CrossAccountEC2Client) UnassignENIPrefixes(ctx context.Context, eniID string, prefixes []string) error {
	return c.remote.UnassignENIPrefixes(ctx, eniID, prefixes)
}

// *********************************************************************************
// --- Instance-owner operations → local ---
// *********************************************************************************

func (c *CrossAccountEC2Client) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	return c.local.GetInstance(ctx, vpcs, subnets, instanceID)
}

func (c *CrossAccountEC2Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	return c.local.GetInstances(ctx, vpcs, subnets)
}

// Needed so we can get max limits by type
func (c *CrossAccountEC2Client) GetInstanceTypes(ctx context.Context) ([]ec2_types.InstanceTypeInfo, error) {
	return c.local.GetInstanceTypes(ctx)
}

func (c *CrossAccountEC2Client) AttachNetworkInterface(ctx context.Context, index int32, instanceID, eniID string) (string, error) {
	return c.local.AttachNetworkInterface(ctx, index, instanceID, eniID)
}

func (c *CrossAccountEC2Client) ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error {
	return c.local.ModifyNetworkInterface(ctx, eniID, attachmentID, deleteOnTermination)
}

func (c *CrossAccountEC2Client) AssociateEIP(ctx context.Context, eniID string, eipTags ipamTypes.Tags) (string, error) {
	return c.local.AssociateEIP(ctx, eniID, eipTags)
}
