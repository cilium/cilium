// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"

	"github.com/cilium/cilium/daemon/cmd/cni"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
)

// ENIMutateInputs carries the agent configuration needed to populate the
// ENI-specific fields of a CiliumNode resource. It deliberately uses only
// plain Go types (no AWS SDK types) so that this file does not pull in any
// AWS dependency. The actual mutator implementation, registered from
// pkg/nodediscovery/eni, is what links against the AWS SDK and the EC2 IMDS
// client.
type ENIMutateInputs struct {
	FirstInterfaceIndex     int
	UsePrimaryAddress       bool
	DisablePrefixDelegation bool
	DeleteOnTermination     bool
	SubnetIDs               []string
	SubnetTags              map[string]string
	SecurityGroups          []string
	SecurityGroupTags       map[string]string
	ExcludeInterfaceTags    map[string]string
	IPAMMinAllocate         int
	IPAMPreAllocate         int
	IPAMMaxAllocate         int
	CNIConfigManager        cni.CNIConfigManager
}

// ENIMutator populates the ENI-specific fields of nodeResource. It is
// registered from pkg/nodediscovery/eni's init() so that the AWS SDK and
// EC2 IMDS client are only linked into binaries that import that package
// (notably cilium-agent), keeping them out of cilium-operator-generic.
type ENIMutator func(ctx context.Context, in ENIMutateInputs, nodeResource *ciliumv2.CiliumNode) error

var eniMutator ENIMutator

// RegisterENIMutator installs the function used to populate the ENI fields
// of a CiliumNode. It is called from pkg/nodediscovery/eni's init().
func RegisterENIMutator(fn ENIMutator) {
	eniMutator = fn
}

// mutateENINodeResource dispatches to the registered ENIMutator. If none is
// registered (e.g. in cilium-operator-generic, which does not blank-import
// pkg/nodediscovery/eni), it fatals — ENI IPAM is only supported by the
// cilium-agent binary and the AWS-specific operator.
func (n *NodeDiscovery) mutateENINodeResource(ctx context.Context, nodeResource *ciliumv2.CiliumNode) error {
	if eniMutator == nil {
		logging.Fatal(n.logger, "ENI IPAM mode requires the cilium-agent binary; "+
			"ensure pkg/nodediscovery/eni is imported (operator binaries must use the AWS-specific operator)")
		return nil
	}
	return eniMutator(ctx, ENIMutateInputs{
		FirstInterfaceIndex:     n.config.ENIFirstInterfaceIndex,
		UsePrimaryAddress:       n.config.ENIUsePrimaryAddress,
		DisablePrefixDelegation: n.config.ENIDisablePrefixDelegation,
		DeleteOnTermination:     n.config.ENIDeleteOnTermination,
		SubnetIDs:               n.config.ENISubnetIDs,
		SubnetTags:              n.config.ENISubnetTags,
		SecurityGroups:          n.config.ENISecurityGroups,
		SecurityGroupTags:       n.config.ENISecurityGroupTags,
		ExcludeInterfaceTags:    n.config.ENIExcludeInterfaceTags,
		IPAMMinAllocate:         n.config.IPAMMinAllocate,
		IPAMPreAllocate:         n.config.IPAMPreAllocate,
		IPAMMaxAllocate:         n.config.IPAMMaxAllocate,
		CNIConfigManager:        n.cniConfigManager,
	}, nodeResource)
}
