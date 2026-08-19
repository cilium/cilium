// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
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

// startNativeRoutingCIDRSync starts a CiliumNode observer that auto-detects
// the IPv4 native routing CIDR from the VPC CIDR reported in the ENI status.
//
// When BPF masquerading is enabled, Cilium needs the native routing CIDR to
// know which destination CIDRs should NOT be masqueraded. Without it,
// cross-node pod-to-pod traffic gets SNAT'd to the node IP, breaking
// connectivity.
//
// If the native routing CIDR is already configured (via Helm or CLI), this
// validates that the configured value contains the VPC CIDR.
//
// The returned channel is closed once the native routing CIDR has been
// determined. Callers must wait on it before programming the datapath,
// otherwise masquerade exclusion may be configured against an empty CIDR.
//
// An unusable configuration is reported by the observer, registered with
// job.WithObserverShutdown so that it shuts the hive down cleanly.
func startNativeRoutingCIDRSync(
	logger *slog.Logger,
	jg job.Group,
	nodeResource agentK8s.LocalCiliumNodeResource,
	localNodeStore *node.LocalNodeStore,
	conf *option.DaemonConfig,
) <-chan struct{} {
	ready := make(chan struct{})
	var once sync.Once
	jg.Add(
		job.Observer(
			"eni-native-routing-cidr-sync",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				if ev.Kind != resource.Upsert {
					return nil
				}

				// Once configured, ignore further events: a regression in
				// the CN status (e.g. malformed CIDR written later) would
				// otherwise degrade cell health for an issue that no longer
				// affects the agent.
				select {
				case <-ready:
					return nil
				default:
				}

				// Each Upsert retries until the operator populates
				// Status.ENI.ENIs[].VPC.PrimaryCIDR with a valid value.
				// An invalid PrimaryCIDR (operator hasn't written yet) is
				// treated as a transient absence.
				primaryCIDR, secondaryCIDRs := deriveVPCCIDRs(ev.Object)
				if !primaryCIDR.IsValid() {
					return nil
				}

				var err error
				once.Do(func() {
					err = autoDetectNativeRoutingCIDR(logger, primaryCIDR, secondaryCIDRs, localNodeStore, conf)
					close(ready)
				})
				return err
			},
			nodeResource,
			job.WithObserverShutdown[resource.Event[*ciliumv2.CiliumNode]](),
		),
	)
	return ready
}

// autoDetectNativeRoutingCIDR either validates an existing native routing
// CIDR configuration against the given VPC CIDRs, or uses the VPC primary CIDR
// as the autodetected native routing CIDR.
//
// Returns an error if the configured native routing CIDR overlaps no VPC CIDR:
// see the masquerading note on startNativeRoutingCIDRSync.
func autoDetectNativeRoutingCIDR(
	logger *slog.Logger,
	primaryCIDR netip.Prefix,
	secondaryCIDRs []netip.Prefix,
	localNodeStore *node.LocalNodeStore,
	conf *option.DaemonConfig,
) error {
	if nativeCIDR := conf.IPv4NativeRoutingCIDR; nativeCIDR.IsValid() {
		// Accept the configured native routing CIDR as long as it overlaps the
		// VPC primary CIDR or one of the secondary CIDR associations, i.e. it is
		// a VPC CIDR, a subnet of one (e.g. a single availability-zone subnet,
		// used to masquerade cross-subnet traffic), or a supernet of one.
		overlaps := func(c netip.Prefix) bool { return iputil.LaminarCIDRsOverlap(nativeCIDR, c) }
		if !overlaps(primaryCIDR) && !slices.ContainsFunc(secondaryCIDRs, overlaps) {
			return fmt.Errorf("configured --%s %s overlaps neither the VPC primary CIDR %s nor any secondary CIDR association %v",
				option.IPv4NativeRoutingCIDR, nativeCIDR, primaryCIDR, secondaryCIDRs)
		}

		logger.Info(
			"Native routing CIDR overlaps VPC CIDR, ignoring autodetected VPC CIDR.",
			logfields.VPCCIDR, primaryCIDR,
			option.IPv4NativeRoutingCIDR, nativeCIDR,
		)
		return nil
	}

	logger.Info(
		"Using autodetected VPC primary CIDR as native routing CIDR.",
		logfields.VPCCIDR, primaryCIDR,
	)
	localNodeStore.Update(func(n *node.LocalNode) {
		n.Local.IPv4NativeRoutingCIDR = primaryCIDR
	})
	return nil
}

// deriveVPCCIDRs extracts the VPC primary CIDR and the secondary CIDR
// associations from the first ENI in the CiliumNode status. All ENIs on a node
// belong to the same VPC, so any ENI can be used.
//
// Returns the zero netip.Prefix when no ENI has populated PrimaryCIDR yet
// (transient startup state).
func deriveVPCCIDRs(node *ciliumv2.CiliumNode) (primaryCIDR netip.Prefix, secondaryCIDRs []netip.Prefix) {
	for _, eni := range node.Status.ENI.ENIs {
		if !eni.VPC.PrimaryCIDR.IsValid() {
			continue
		}
		primaryCIDR = eni.VPC.PrimaryCIDR.Masked()
		for _, c := range eni.VPC.CIDRs {
			if c.IsValid() {
				secondaryCIDRs = append(secondaryCIDRs, c.Masked())
			}
		}
		return primaryCIDR, secondaryCIDRs
	}
	return netip.Prefix{}, nil
}
