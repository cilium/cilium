// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"errors"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	alibabaCloudMetadata "github.com/cilium/cilium/pkg/alibabacloud/metadata"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// mutateAlibabaCloudNodeResource fills in the AlibabaCloud-specific fields
// of the CiliumNode resource. It is kept in a separate file so that the
// AlibabaCloud-specific imports are not pulled in via the main
// nodediscovery.go.
func (n *NodeDiscovery) mutateAlibabaCloudNodeResource(ctx context.Context, nodeResource *ciliumv2.CiliumNode) error {
	nodeResource.Spec.AlibabaCloud = alibabaCloudTypes.Spec{}

	instanceID, err := alibabaCloudMetadata.GetInstanceID(ctx)
	if err != nil {
		logging.Fatal(n.logger, "Unable to retrieve InstanceID of own ECS instance", logfields.Error, err)
	}

	if instanceID == "" {
		return errors.New("InstanceID of own ECS instance is empty")
	}

	instanceType, err := alibabaCloudMetadata.GetInstanceType(ctx)
	if err != nil {
		logging.Fatal(n.logger, "Unable to retrieve InstanceType of own ECS instance", logfields.Error, err)
	}
	vpcID, err := alibabaCloudMetadata.GetVPCID(ctx)
	if err != nil {
		logging.Fatal(n.logger, "Unable to retrieve VPC ID of own ECS instance", logfields.Error, err)
	}
	vpcCidrBlock, err := alibabaCloudMetadata.GetVPCCIDRBlock(ctx)
	if err != nil {
		logging.Fatal(n.logger, "Unable to retrieve VPC CIDR block of own ECS instance", logfields.Error, err)
	}
	zoneID, err := alibabaCloudMetadata.GetZoneID(ctx)
	if err != nil {
		logging.Fatal(n.logger, "Unable to retrieve Zone ID of own ECS instance", logfields.Error, err)
	}
	nodeResource.Spec.InstanceID = instanceID
	nodeResource.Spec.AlibabaCloud.InstanceType = instanceType
	nodeResource.Spec.AlibabaCloud.VPCID = vpcID
	nodeResource.Spec.AlibabaCloud.CIDRBlock = vpcCidrBlock
	nodeResource.Spec.AlibabaCloud.AvailabilityZone = zoneID

	nodeResource.Spec.IPAM.PreAllocate = n.config.IPAMPreAllocate
	nodeResource.Spec.IPAM.MinAllocate = n.config.IPAMMinAllocate
	nodeResource.Spec.IPAM.MaxAllocate = n.config.IPAMMaxAllocate
	nodeResource.Spec.AlibabaCloud.VSwitches = n.config.AlibabaCloudVSwitches
	nodeResource.Spec.AlibabaCloud.VSwitchTags = n.config.AlibabaCloudVSwitchTags
	nodeResource.Spec.AlibabaCloud.SecurityGroups = n.config.AlibabaCloudSecurityGroups
	nodeResource.Spec.AlibabaCloud.SecurityGroupTags = n.config.AlibabaCloudSecurityGroupTags

	if c := n.cniConfigManager.GetCustomNetConf(); c != nil {
		if c.AlibabaCloud.VPCID != "" {
			nodeResource.Spec.AlibabaCloud.VPCID = c.AlibabaCloud.VPCID
		}
		if c.AlibabaCloud.CIDRBlock != "" {
			nodeResource.Spec.AlibabaCloud.CIDRBlock = c.AlibabaCloud.CIDRBlock
		}

		if len(c.AlibabaCloud.VSwitches) > 0 {
			nodeResource.Spec.AlibabaCloud.VSwitches = c.AlibabaCloud.VSwitches
		}

		if len(c.AlibabaCloud.VSwitchTags) > 0 {
			nodeResource.Spec.AlibabaCloud.VSwitchTags = c.AlibabaCloud.VSwitchTags
		}

		if len(c.AlibabaCloud.SecurityGroups) > 0 {
			nodeResource.Spec.AlibabaCloud.SecurityGroups = c.AlibabaCloud.SecurityGroups
		}

		if len(c.AlibabaCloud.SecurityGroupTags) > 0 {
			nodeResource.Spec.AlibabaCloud.SecurityGroupTags = c.AlibabaCloud.SecurityGroupTags
		}

		if c.IPAM.PreAllocate != 0 {
			nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
		}
	}

	return nil
}
