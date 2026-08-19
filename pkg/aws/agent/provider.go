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
	"github.com/cilium/cilium/pkg/ipmasq"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
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

	Conf        *option.DaemonConfig
	MTU         mtu.MTU
	Sysctl      sysctl.Sysctl
	IPMasqAgent *ipmasq.IPMasqAgent
}

// provider is the AWS customization of the agent's multi-pool allocator.
type provider struct {
	params providerParams

	// nativeRoutingCIDRReady is closed by the observer registered in Initialize
	// once the native routing CIDR has been determined. It is written once, by
	// Initialize, and only read afterwards by WaitReady.
	nativeRoutingCIDRReady <-chan struct{}
}

func (p *provider) Mode() string {
	return ipamOption.IPAMENI
}

func (p *provider) PoolSpecAccessors() ipam.PoolSpecAccessors {
	return poolAccessor
}

// Initialize registers the jobs that configure the ENI network devices and
// that derive the native routing CIDR from the VPC CIDRs the operator reports
// in the CiliumNode status. Neither blocks.
func (p *provider) Initialize() (ipam.RoutingMetadataResolver, error) {
	startDeviceConfigurator(p.params.Logger, p.params.JobGroup, p.params.Node, p.params.MTU, p.params.Sysctl)
	p.nativeRoutingCIDRReady = startNativeRoutingCIDRSync(p.params.Logger, p.params.JobGroup, p.params.Node, p.params.LocalNodeStore, p.params.Conf)

	return &resolver{
		logger:      p.params.Logger,
		conf:        p.params.Conf,
		ipMasqAgent: p.params.IPMasqAgent,
	}, nil
}

// WaitReady blocks until the native routing CIDR observer registered in
// Initialize has determined that CIDR, which requires the operator to have
// reported the VPC CIDRs of the node in the CiliumNode status.
func (p *provider) WaitReady(ctx context.Context) error {
	if p.nativeRoutingCIDRReady == nil {
		return errors.New("WaitReady called before Initialize")
	}

	deadline := time.After(waitForNativeRoutingCIDRTimeout)
	for {
		select {
		case <-p.nativeRoutingCIDRReady:
			return nil
		case <-deadline:
			return fmt.Errorf("timed out after %s waiting for the operator to report the VPC CIDRs of the node in Status.ENI.ENIs[].VPC. %s",
				waitForNativeRoutingCIDRTimeout, operatorHelpMessage)
		case <-ctx.Done():
			return fmt.Errorf("waiting for the operator to report the VPC CIDRs of the node in Status.ENI.ENIs[].VPC: %w", ctx.Err())
		case <-time.After(5 * time.Second):
			p.params.Logger.Info(
				"Waiting for the operator to report the VPC CIDRs of the node, needed to determine the native routing CIDR",
				logfields.HelpMessage, operatorHelpMessage,
			)
		}
	}
}

const waitForNativeRoutingCIDRTimeout = 5 * time.Minute

// operatorHelpMessage points at the operator, which is what WaitReady is
// waiting on.
const operatorHelpMessage = "Check if the cilium-operator pod is running and does not have any warnings or error messages."

// resolver reports the ENI routing metadata of the addresses the multi-pool
// allocator hands out. It is built by Initialize and never mutated afterwards,
// so it is safe for concurrent use.
type resolver struct {
	logger      *slog.Logger
	conf        *option.DaemonConfig
	ipMasqAgent *ipmasq.IPMasqAgent
}

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

	return allocationResult(r.logger, addr, pool, enis, r.conf, r.ipMasqAgent)
}
