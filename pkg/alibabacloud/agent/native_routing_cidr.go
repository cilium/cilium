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
	"github.com/cilium/cilium/pkg/ip"
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
			"alibabacloud-native-routing-cidr-sync",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				if ev.Kind != resource.Upsert {
					return nil
				}

				primaryCIDR, secondaryCIDRs := deriveVpcCIDRs(ev.Object)
				if !primaryCIDR.IsValid() {
					return nil
				}

				var err error
				once.Do(func() {
					err = autoDetectNativeRoutingCIDR(logger, primaryCIDR, secondaryCIDRs, localNodeStore, conf)
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

func autoDetectNativeRoutingCIDR(logger *slog.Logger, primaryCIDR netip.Prefix, secondaryCIDRs []netip.Prefix, localNodeStore *node.LocalNodeStore, conf *option.DaemonConfig) error {
	podSubnets := append([]netip.Prefix{primaryCIDR}, secondaryCIDRs...)
	autodetected := false

	if nativeCIDR := conf.IPv4NativeRoutingCIDR; nativeCIDR.IsValid() {
		found := false
		for _, vpcCIDR := range podSubnets {
			// Accept the configured native routing CIDR as long as it
			// overlaps one of the VPC CIDRs, i.e. it is a VPC CIDR, a
			// subnet of one (e.g. a single availability-zone subnet, used
			// to masquerade cross-subnet traffic), or a supernet of one.
			if !ip.LaminarCIDRsOverlap(nativeCIDR, vpcCIDR) {
				logger.Info(
					"Native routing CIDR does not overlap VPC CIDR, trying next",
					logfields.VPCCIDR, vpcCIDR,
					option.IPv4NativeRoutingCIDR, nativeCIDR,
				)
			} else {
				found = true
				logger.Info(
					"Native routing CIDR overlaps VPC CIDR, ignoring autodetected VPC CIDRs.",
					logfields.VPCCIDR, vpcCIDR,
					option.IPv4NativeRoutingCIDR, nativeCIDR,
				)
				break
			}
		}
		if !found {
			return fmt.Errorf("none of the AlibabaCloud VPC CIDRs overlaps the specified native routing CIDR %s", nativeCIDR)
		}
		// A configured native routing CIDR may be a supernet of the VPC CIDRs,
		// e.g. one covering peered VPCs. It then covers pod subnets that the
		// VPC CIDRs of this node do not.
		podSubnets = append(podSubnets, nativeCIDR)
	} else {
		logger.Info(
			"Using autodetected primary VPC CIDR.",
			logfields.VPCCIDR, primaryCIDR,
		)
		autodetected = true
	}

	// deriveVpcCIDRs only ever returns IPv4 CIDRs, so the only IPv6 pod subnet
	// that can be known is the operator-supplied one.
	if nativeCIDR := conf.IPv6NativeRoutingCIDR; nativeCIDR.IsValid() {
		podSubnets = append(podSubnets, nativeCIDR)
	}

	localNodeStore.Update(func(ln *node.LocalNode) {
		if autodetected {
			ln.Local.IPv4NativeRoutingCIDR = primaryCIDR
		}
		ln.SetPodSubnets(podSubnets)
	})
	return nil
}

func deriveVpcCIDRs(node *ciliumv2.CiliumNode) (primaryCIDR netip.Prefix, secondaryCIDRs []netip.Prefix) {
	// All ENIs belong to the same VPC. Wait for the operator to publish
	// ENI status before validating primary and secondary VPC CIDRs.
	if len(node.Status.AlibabaCloud.ENIs) > 0 {
		if p := node.Spec.AlibabaCloud.CIDRBlock; p.IsValid() {
			primaryCIDR = p.Masked()
		}
		for _, eni := range node.Status.AlibabaCloud.ENIs {
			for _, sc := range eni.VPC.SecondaryCIDRs {
				if sc.IsValid() {
					secondaryCIDRs = append(secondaryCIDRs, sc.Masked())
				}
			}
			return
		}
	}
	return
}
