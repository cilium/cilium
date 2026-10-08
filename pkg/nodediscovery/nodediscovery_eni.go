// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/cilium/daemon/cmd/cni"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// ENIMutateInputs carries the agent configuration needed to populate the
// ENI-specific fields of a CiliumNode resource. It deliberately uses only
// plain Go types (no AWS SDK types) so that this file does not pull in any
// AWS dependency. The actual mutator implementation, provided by
// pkg/aws/agent, is what links against the AWS SDK and the EC2 IMDS client.
type ENIMutateInputs struct {
	Logger                  *slog.Logger
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
// provided by the pkg/aws/agent cell, so that the AWS SDK and the EC2 IMDS
// client are only linked into the binaries registering that cell, and injected
// into NodeDiscovery as an optional dependency: newNodeDiscovery rejects its
// absence in ENI IPAM mode only.
type ENIMutator func(ctx context.Context, in ENIMutateInputs, nodeResource *ciliumv2.CiliumNode) error

// errNoENIMutator is returned by newNodeDiscovery when the agent runs in ENI
// IPAM mode without any cell providing an ENIMutator.
var errNoENIMutator = errors.New("ENI IPAM mode requires the AWS agent integration (pkg/aws/agent.Cell), which is not registered")

// mutateENINodeResource populates the ENI-specific fields of nodeResource
// through the injected ENIMutator, which newNodeDiscovery guarantees is set in
// ENI IPAM mode.
func (n *NodeDiscovery) mutateENINodeResource(ctx context.Context, nodeResource *ciliumv2.CiliumNode) error {
	return n.eniMutator(ctx, ENIMutateInputs{
		Logger:                  n.logger,
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
