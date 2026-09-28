// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"

	awsMetadata "github.com/cilium/cilium/pkg/aws/metadata"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/nodediscovery"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// newENIMutator provides pkg/nodediscovery with the function populating the
// ENI-specific fields of the node's CiliumNode, backed by the instance metadata
// the cell owns.
func newENIMutator(m *instanceMetadata) nodediscovery.ENIMutator {
	return m.mutateENINode
}

// mutateENINode populates the ENI-specific fields of nodeResource using EC2
// IMDS metadata and the agent configuration carried in in.
func (m *instanceMetadata) mutateENINode(ctx context.Context, in nodediscovery.ENIMutateInputs, nodeResource *ciliumv2.CiliumNode) error {
	info, err := m.get(ctx)
	if err != nil {
		return err
	}

	applyENISpec(in, info, nodeResource)
	return nil
}

// applyENISpec writes the ENI-specific fields of nodeResource from the instance
// metadata in info and the agent configuration in in. It is separated from
// mutateENINode so that the precedence rules between the agent configuration,
// the CNI configuration file and the instance metadata are testable without an
// IMDS endpoint.
//
// Precedence is expressed as the order of the three stages below rather than
// as statement position within a single function: whatever the CNI
// configuration file sets can only reach fields written by
// applyAgentConfiguration, since applyInstanceFacts runs last and
// unconditionally. Fields describing the instance the agent runs on therefore
// belong in applyInstanceFacts, which no configuration can override.
func applyENISpec(in nodediscovery.ENIMutateInputs, info awsMetadata.MetaDataInfo, nodeResource *ciliumv2.CiliumNode) {
	applyAgentConfiguration(in, &nodeResource.Spec)
	if c := in.CNIConfigManager.GetCustomNetConf(); c != nil {
		overrideFromNetConf(in.Logger, &nodeResource.Spec, c, info)
	}
	applyInstanceFacts(&nodeResource.Spec, info)
}

// applyAgentConfiguration writes the fields chosen by the agent
// configuration, i.e. every field which the CNI configuration file is allowed
// to override.
func applyAgentConfiguration(in nodediscovery.ENIMutateInputs, spec *ciliumv2.NodeSpec) {
	spec.ENI = awsTypes.ENISpec{
		FirstInterfaceIndex:     aws.Int(in.FirstInterfaceIndex),
		UsePrimaryAddress:       aws.Bool(in.UsePrimaryAddress),
		DisablePrefixDelegation: aws.Bool(in.DisablePrefixDelegation),
		DeleteOnTermination:     aws.Bool(in.DeleteOnTermination),

		SubnetIDs:            in.SubnetIDs,
		SubnetTags:           in.SubnetTags,
		SecurityGroups:       in.SecurityGroups,
		SecurityGroupTags:    in.SecurityGroupTags,
		ExcludeInterfaceTags: in.ExcludeInterfaceTags,
	}

	spec.IPAM.MinAllocate = in.IPAMMinAllocate
	spec.IPAM.PreAllocate = in.IPAMPreAllocate
	spec.IPAM.MaxAllocate = in.IPAMMaxAllocate
}

// overrideFromNetConf applies the ENI and IPAM settings of the CNI
// configuration file c on top of the agent configuration. Settings which
// describe the instance are not applied, only reported when they disagree
// with the instance metadata in info, see warnIgnoredInstanceFact.
func overrideFromNetConf(logger *slog.Logger, spec *ciliumv2.NodeSpec, c *cnitypes.NetConf, info awsMetadata.MetaDataInfo) {
	if c.IPAM.MinAllocate != 0 {
		spec.IPAM.MinAllocate = c.IPAM.MinAllocate
	}
	if c.IPAM.PreAllocate != 0 {
		spec.IPAM.PreAllocate = c.IPAM.PreAllocate
	}
	if c.ENI.FirstInterfaceIndex != nil {
		spec.ENI.FirstInterfaceIndex = c.ENI.FirstInterfaceIndex
	}
	if len(c.ENI.SecurityGroups) > 0 {
		spec.ENI.SecurityGroups = c.ENI.SecurityGroups
	}
	if len(c.ENI.SecurityGroupTags) > 0 {
		spec.ENI.SecurityGroupTags = c.ENI.SecurityGroupTags
	}
	if len(c.ENI.SubnetIDs) > 0 {
		spec.ENI.SubnetIDs = c.ENI.SubnetIDs
	}
	if len(c.ENI.SubnetTags) > 0 {
		spec.ENI.SubnetTags = c.ENI.SubnetTags
	}
	if len(c.ENI.ExcludeInterfaceTags) > 0 {
		spec.ENI.ExcludeInterfaceTags = c.ENI.ExcludeInterfaceTags
	}
	if c.ENI.UsePrimaryAddress != nil {
		spec.ENI.UsePrimaryAddress = c.ENI.UsePrimaryAddress
	}
	if c.ENI.DisablePrefixDelegation != nil {
		spec.ENI.DisablePrefixDelegation = c.ENI.DisablePrefixDelegation
	}
	if c.ENI.DeleteOnTermination != nil {
		spec.ENI.DeleteOnTermination = c.ENI.DeleteOnTermination
	}

	warnIgnoredInstanceFact(logger, "vpc-id", c.ENI.VpcID, info.VPCID)
	warnIgnoredInstanceFact(logger, "instance-type", c.ENI.InstanceType, info.InstanceType)
	warnIgnoredInstanceFact(logger, "availability-zone", c.ENI.AvailabilityZone, info.AvailabilityZone)
	warnIgnoredInstanceFact(logger, "node-subnet-id", c.ENI.NodeSubnetID, info.SubnetID)
}

// applyInstanceFacts writes the fields describing the EC2 instance the agent
// runs on. It runs after overrideFromNetConf so that instance metadata always
// wins over configuration.
func applyInstanceFacts(spec *ciliumv2.NodeSpec, info awsMetadata.MetaDataInfo) {
	spec.InstanceID = info.InstanceID
	spec.ENI.VpcID = info.VPCID
	spec.ENI.InstanceType = info.InstanceType
	spec.ENI.AvailabilityZone = info.AvailabilityZone
	spec.ENI.NodeSubnetID = info.SubnetID
}

// warnIgnoredInstanceFact reports an ENISpec field which the CNI
// configuration file sets to something other than what EC2 instance metadata
// reports, and which is therefore ignored.
func warnIgnoredInstanceFact(logger *slog.Logger, key, confValue, imdsValue string) {
	if confValue == "" || confValue == imdsValue {
		return
	}
	logger.Warn(
		"Ignoring CNI configuration field determined by EC2 instance metadata",
		logfields.ConfigKey, key,
		logfields.Value, confValue,
		logfields.Actual, imdsValue,
	)
}
