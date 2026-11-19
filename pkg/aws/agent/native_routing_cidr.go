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
// With IPsec and IPv6 enabled, it additionally waits until an IPv6 encryption
// scope is known (see ipv6EncryptionScopeReady): without it, IPsec installs no
// IPv6 OUT policies or states and remote pod IPv6 traffic is dropped.
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
	ipsecEnabled bool,
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
				vpc := deriveVPCCIDRs(ev.Object)
				if !vpc.primary.IsValid() {
					return nil
				}

				// Checked before consuming once or mutating the local node: a
				// missing IPv6 encryption scope is retried on later Upserts.
				scopeReady, err := ipv6EncryptionScopeReady(ipsecEnabled, conf, vpc)
				if err != nil {
					return err
				}
				if !scopeReady {
					return nil
				}

				if vpc.multipleVPCs {
					logger.Warn("ENIs of the node belong to several VPCs, only using the CIDRs of one of them",
						logfields.VPCCIDR, vpc.primary,
					)
				}

				once.Do(func() {
					err = autoDetectNativeRoutingCIDR(logger, vpc, localNodeStore, conf)
					if err == nil {
						close(ready)
					}
				})
				return err
			},
			nodeResource,
			job.WithObserverShutdown[resource.Event[*ciliumv2.CiliumNode]](),
		),
	)
	return ready
}

// ipv6EncryptionScopeReady reports whether the IPv6 subnets pod IPs are
// allocated from are known, which IPsec needs to build its IPv6 XFRM OUT
// policies under ENI (there is no node PodCIDR). It is always ready unless both
// IPsec and IPv6 are enabled.
//
// An explicit --ipv6-pod-subnets overrides the derived subnets and therefore
// satisfies the requirement on its own, provided all its entries are native
// IPv6 prefixes. Otherwise, a configured IPv6 native routing CIDR or the IPv6
// CIDR associations of the VPC are required.
func ipv6EncryptionScopeReady(ipsecEnabled bool, conf *option.DaemonConfig, vpc vpcCIDRs) (bool, error) {
	if !ipsecEnabled || !conf.EnableIPv6 {
		return true, nil
	}

	if len(conf.IPv6PodSubnets) > 0 {
		for _, p := range conf.IPv6PodSubnets {
			if !isNativeIPv6Prefix(p) {
				return false, fmt.Errorf("configured --%s entry %s is not a valid IPv6 prefix, but IPsec uses it as the IPv6 encryption scope",
					option.IPv6PodSubnets, p)
			}
		}
		return true, nil
	}

	return isNativeIPv6Prefix(conf.IPv6NativeRoutingCIDR) || len(vpc.ipv6) > 0, nil
}

func isNativeIPv6Prefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is6() && !p.Addr().Is4In6()
}

// autoDetectNativeRoutingCIDR either validates an existing native routing
// CIDR configuration against the given VPC CIDRs, or uses the VPC primary CIDR
// as the autodetected native routing CIDR.
//
// On both paths it also records the VPC CIDRs as the subnets pod IPs are
// allocated from: under ENI there is no node PodCIDR, so this is what IPsec
// uses to build its XFRM policies.
//
// Returns an error if the configured native routing CIDR overlaps no VPC CIDR:
// see the masquerading note on startNativeRoutingCIDRSync.
func autoDetectNativeRoutingCIDR(
	logger *slog.Logger,
	vpc vpcCIDRs,
	localNodeStore *node.LocalNodeStore,
	conf *option.DaemonConfig,
) error {
	primaryCIDR, secondaryCIDRs := vpc.primary, vpc.secondary
	podSubnets := append([]netip.Prefix{primaryCIDR}, secondaryCIDRs...)
	autodetected := false

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
		podSubnets = append(podSubnets, nativeCIDR)
	} else {
		logger.Info(
			"Using autodetected VPC primary CIDR as native routing CIDR.",
			logfields.VPCCIDR, primaryCIDR,
		)
		autodetected = true
	}

	// The IPv6 CIDR associations of the VPC are only recorded as pod subnets
	// (the IPv6 encryption scope), not as the IPv6 native routing CIDR, which
	// is never autodetected.
	if conf.EnableIPv6 {
		podSubnets = append(podSubnets, vpc.ipv6...)
	}
	if nativeCIDR := conf.IPv6NativeRoutingCIDR; nativeCIDR.IsValid() {
		podSubnets = append(podSubnets, nativeCIDR)
	}

	localNodeStore.Update(func(n *node.LocalNode) {
		if autodetected {
			n.Local.IPv4NativeRoutingCIDR = primaryCIDR
		}
		n.SetPodSubnets(podSubnets)
	})
	return nil
}

// vpcCIDRs are the CIDRs of the VPC of the node, as reported in the ENI status.
type vpcCIDRs struct {
	// primary is the VPC primary IPv4 CIDR. It is the zero prefix when no ENI
	// has populated it yet.
	primary netip.Prefix

	// secondary are the secondary IPv4 CIDR associations of the VPC.
	secondary []netip.Prefix

	// ipv6 are the IPv6 CIDR associations of the VPC, masked, deduplicated and
	// sorted.
	ipv6 []netip.Prefix

	// multipleVPCs is set when ENIs of the node report another VPC ID.
	multipleVPCs bool
}

// deriveVPCCIDRs extracts the VPC primary CIDR and the secondary CIDR
// associations from the first ENI in the CiliumNode status with a valid primary
// CIDR. All ENIs on a node are expected to belong to the same VPC, so any ENI
// can be used. The IPv6 CIDR associations are collected from all ENIs of that
// same VPC, so that an ENI whose IPv6 metadata is not populated yet does not
// hide the IPv6 associations reported on another one.
//
// Returns the zero value when no ENI has populated PrimaryCIDR yet (transient
// startup state).
func deriveVPCCIDRs(node *ciliumv2.CiliumNode) vpcCIDRs {
	var (
		res   vpcCIDRs
		vpcID string
	)
	for _, eni := range node.Status.ENI.ENIs {
		if !eni.VPC.PrimaryCIDR.IsValid() {
			continue
		}
		vpcID = eni.VPC.ID
		res.primary = eni.VPC.PrimaryCIDR.Masked()
		for _, c := range eni.VPC.CIDRs {
			if c.IsValid() {
				res.secondary = append(res.secondary, c.Masked())
			}
		}
		break
	}
	if !res.primary.IsValid() {
		return vpcCIDRs{}
	}

	for _, eni := range node.Status.ENI.ENIs {
		if eni.VPC.ID != vpcID {
			if eni.VPC.ID != "" {
				res.multipleVPCs = true
			}
			continue
		}
		for _, c := range eni.VPC.IPv6CIDRs {
			if isNativeIPv6Prefix(c.Prefix) {
				res.ipv6 = append(res.ipv6, c.Masked())
			}
		}
	}
	slices.SortFunc(res.ipv6, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	res.ipv6 = slices.Compact(res.ipv6)

	return res
}
