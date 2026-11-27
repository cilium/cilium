// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var (
	_ ipam.CloudProvider           = (*provider)(nil)
	_ ipam.RoutingMetadataResolver = (*resolver)(nil)
)

// providerParams are the dependencies of the AWS IPAM provider. They are
// injected by the aws-agent cell.
type providerParams struct {
	cell.In

	Logger *slog.Logger

	JobGroup job.Group

	Node           agentK8s.LocalCiliumNodeResource
	LocalNodeStore *node.LocalNodeStore

	Conf   *option.DaemonConfig
	MTU    mtu.MTU
	Sysctl sysctl.Sysctl

	Metadata *instanceMetadata
}

// provider is the AWS customization of the agent's multi-pool allocator.
type provider struct {
	params providerParams
}

func (p *provider) Mode() string {
	return ipamOption.IPAMENI
}

func (p *provider) PoolSpecAccessors() ipam.PoolSpecAccessors {
	return poolAccessor
}

// Initialize reads the VPC CIDRs of the node from the IMDS, derives the native routing
// CIDR from them, and registers the job that configures the ENI network devices.
func (p *provider) Initialize(ctx context.Context) (ipam.RoutingMetadataResolver, error) {
	var vpcCIDRs []netip.Prefix
	if p.params.Conf.EnableIPv4 {
		var err error
		if vpcCIDRs, err = p.params.Metadata.vpcIPv4CIDRs(ctx); err != nil {
			return nil, fmt.Errorf("unable to determine the VPC IPv4 CIDRs of the node: %w", err)
		}
		if len(vpcCIDRs) == 0 {
			return nil, errors.New("no IPv4 VPC CIDRs found for the node")
		}
	}

	if err := autoDetectNativeRoutingCIDR(p.params.Logger, vpcCIDRs, p.params.LocalNodeStore, p.params.Conf); err != nil {
		return nil, err
	}

	startDeviceConfigurator(p.params.Logger, p.params.JobGroup, p.params.Node, p.params.MTU, p.params.Sysctl)

	return &resolver{}, nil
}

// WaitReady has nothing to converge on: everything the AWS provider needs
// before the first allocation is resolved synchronously by Initialize.
func (p *provider) WaitReady(_ context.Context) error {
	return nil
}

// resolver reports the ENI routing metadata of the addresses the multi-pool
// allocator hands out. It is stateless: everything it reports is derived from
// the CiliumNode it is handed on each call.
type resolver struct{}

// ResolveRoutingMetadata reports the ENI-specific routing metadata of addr by
// finding which ENI of the node owns it.
func (r *resolver) ResolveRoutingMetadata(node *ciliumv2.CiliumNode, addr netip.Addr, pool ipam.Pool) (*ipam.AllocationResult, error) {
	// The ENIs are only read here: the multi-pool manager replaces the node
	// pointer on every update and deep-copies it before any mutation, so the
	// map is effectively immutable for the duration of this call.
	var enis map[string]awsTypes.ENI
	if node != nil {
		enis = node.Status.ENI.ENIs
	}

	return allocationResult(addr, pool, enis)
}
