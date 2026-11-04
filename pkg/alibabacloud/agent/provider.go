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
	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	_ ipam.CloudProvider           = (*provider)(nil)
	_ ipam.RoutingMetadataResolver = (*resolver)(nil)
)

type providerParams struct {
	cell.In

	Logger *slog.Logger

	JobGroup job.Group

	Node           agentK8s.LocalCiliumNodeResource
	LocalNodeStore *node.LocalNodeStore

	Conf *option.DaemonConfig
}

type provider struct {
	params providerParams

	nativeRoutingCIDRReady <-chan error
}

func (p *provider) Mode() string {
	return ipamOption.IPAMAlibabaCloud
}

func (p *provider) PoolSpecAccessors() ipam.PoolSpecAccessors {
	return poolAccessor
}

func (p *provider) Initialize() (ipam.RoutingMetadataResolver, error) {
	p.nativeRoutingCIDRReady = startNativeRoutingCIDRSync(
		p.params.Logger,
		p.params.JobGroup,
		p.params.Node,
		p.params.LocalNodeStore,
		p.params.Conf,
	)

	return &resolver{logger: p.params.Logger}, nil
}

func (p *provider) WaitReady(ctx context.Context) error {
	if p.nativeRoutingCIDRReady == nil {
		return errors.New("WaitReady called before Initialize")
	}

	deadline := time.After(waitForNativeRoutingCIDRTimeout)
	for {
		select {
		case err := <-p.nativeRoutingCIDRReady:
			return err
		case <-deadline:
			return fmt.Errorf("timed out after %s waiting for the operator to report the AlibabaCloud VPC CIDRs in the CiliumNode. %s",
				waitForNativeRoutingCIDRTimeout, operatorHelpMessage)
		case <-ctx.Done():
			return fmt.Errorf("waiting for the operator to report the AlibabaCloud VPC CIDRs in the CiliumNode: %w", ctx.Err())
		case <-time.After(5 * time.Second):
			p.params.Logger.Info(
				"Waiting for the operator to report the AlibabaCloud VPC CIDRs, needed to determine the native routing CIDR",
				logfields.HelpMessage, operatorHelpMessage,
			)
		}
	}
}

const waitForNativeRoutingCIDRTimeout = 5 * time.Minute

const operatorHelpMessage = "Check if the cilium-operator pod is running and does not have any warnings or error messages."

type resolver struct{ logger *slog.Logger }

func (r *resolver) ResolveRoutingMetadata(node *ciliumv2.CiliumNode, addr netip.Addr, pool ipam.Pool) (*ipam.AllocationResult, error) {
	var enis map[string]alibabaCloudTypes.ENI
	if node != nil {
		enis = node.Status.AlibabaCloud.ENIs
	}

	return allocationResult(r.logger, addr, pool, enis)
}
