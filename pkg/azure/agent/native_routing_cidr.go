// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/cilium/hive/job"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func startNativeRoutingCIDRSync(
	logger *slog.Logger,
	jg job.Group,
	nodeResource agentK8s.LocalCiliumNodeResource,
	localNodeStore *node.LocalNodeStore,
	conf *option.DaemonConfig,
) <-chan error {
	ready := make(chan error, 1)
	var once sync.Once
	jg.Add(
		job.Observer(
			"azure-native-routing-cidr-sync",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				if ev.Kind != resource.Upsert {
					return nil
				}

				subnetCIDR := deriveSubnetCIDR(ev.Object)
				if !subnetCIDR.IsValid() {
					return nil
				}

				var err error
				once.Do(func() {
					err = autoDetectNativeRoutingCIDR(logger, subnetCIDR, localNodeStore, conf)
					ready <- err
				})
				return err
			},
			nodeResource,
			job.WithObserverShutdown[resource.Event[*ciliumv2.CiliumNode]](),
		),
	)
	return ready
}

func autoDetectNativeRoutingCIDR(
	logger *slog.Logger,
	subnetCIDR netip.Prefix,
	localNodeStore *node.LocalNodeStore,
	conf *option.DaemonConfig,
) error {
	if nativeCIDR := conf.IPv4NativeRoutingCIDR; nativeCIDR.IsValid() {
		if !iputil.LaminarCIDRsOverlap(nativeCIDR, subnetCIDR) {
			return fmt.Errorf("configured --%s %s does not overlap the Azure subnet CIDR %s",
				option.IPv4NativeRoutingCIDR, nativeCIDR, subnetCIDR)
		}

		logger.Info(
			"Native routing CIDR overlaps the Azure subnet CIDR, ignoring the autodetected CIDR",
			logfields.CIDR, subnetCIDR,
			option.IPv4NativeRoutingCIDR, nativeCIDR,
		)
		return nil
	}

	logger.Info(
		"Using the autodetected Azure subnet CIDR as the native routing CIDR",
		logfields.CIDR, subnetCIDR,
	)
	localNodeStore.Update(func(n *node.LocalNode) {
		n.Local.IPv4NativeRoutingCIDR = subnetCIDR
	})
	return nil
}

func deriveSubnetCIDR(node *ciliumv2.CiliumNode) netip.Prefix {
	for _, iface := range node.Status.Azure.Interfaces {
		if iface.Subnet.CIDR.IsValid() && iface.Subnet.CIDR.Addr().Is4() {
			return iface.Subnet.CIDR.Prefix.Masked()
		}
	}
	return netip.Prefix{}
}
