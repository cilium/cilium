// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"

	"github.com/cilium/hive/job"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/ipmasq"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// startENIDeviceConfigurator starts a CiliumNode observer that configures ENI
// network devices independently of the IPAM allocator. This decouples ENI
// device setup from the allocator implementation.
func startENIDeviceConfigurator(
	logger *slog.Logger,
	jg job.Group,
	nodeResource agentK8s.LocalCiliumNodeResource,
	mtuConfig MtuConfiguration,
	sysctl sysctl.Sysctl,
) {
	var prevNode *ciliumv2.CiliumNode
	jg.Add(
		job.Observer(
			"eni-device-configurator",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				if ev.Kind != resource.Upsert {
					return nil
				}

				if err := validateENIConfig(ev.Object); err != nil {
					logger.Info("ENI state is not consistent yet", logfields.Error, err)
					return nil
				}

				configureENIDevices(logger, prevNode, ev.Object, mtuConfig, sysctl)
				prevNode = ev.Object
				return nil
			},
			nodeResource,
		),
	)
}

// startENINativeRoutingCIDRSync starts a CiliumNode observer that auto-detects
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
// The returned channel is closed once the native routing CIDR has been set
// in the local node store. Callers must wait on it before programming the
// datapath, otherwise masquerade exclusion may be configured against an
// empty CIDR.
func startENINativeRoutingCIDRSync(
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
				// Status.ENI.ENIs[].VPC.PrimaryCIDR with a parseable value.
				// A non-nil error degrades cell health to surface persistent
				// malformed data, while an empty PrimaryCIDR (operator hasn't
				// written yet) is treated as a transient absence.
				primaryCIDR, err := deriveENIVpcCIDR(logger, ev.Object)
				if err != nil {
					return err
				}
				if primaryCIDR == nil {
					return nil
				}

				once.Do(func() {
					autoDetectENINativeRoutingCIDR(logger, primaryCIDR, localNodeStore, conf)
					close(ready)
				})
				return nil
			},
			nodeResource,
		),
	)
	return ready
}

// waitForENINativeRoutingCIDR blocks until the eni-native-routing-cidr-sync
// observer has populated Local.IPv4NativeRoutingCIDR in the local node store.
// Aborts the agent with a fatal log if the operator has not reported the VPC
// CIDR within waitForENINativeRoutingCIDRTimeout.
func waitForENINativeRoutingCIDR(logger *slog.Logger, ready <-chan struct{}) {
	deadline := time.After(waitForENINativeRoutingCIDRTimeout)
	for {
		select {
		case <-ready:
			return
		case <-deadline:
			logging.Fatal(logger,
				"Timed out waiting for ENI VPC CIDR to be reported in CiliumNode status",
				logfields.Duration, waitForENINativeRoutingCIDRTimeout,
			)
		case <-time.After(5 * time.Second):
			logger.Info("Waiting for ENI VPC CIDR to be reported in CiliumNode status")
		}
	}
}

const waitForENINativeRoutingCIDRTimeout = 5 * time.Minute

// autoDetectENINativeRoutingCIDR either validates an existing native routing
// CIDR configuration against the given VPC primary CIDR, or uses the VPC CIDR
// as the autodetected native routing CIDR.
func autoDetectENINativeRoutingCIDR(
	logger *slog.Logger,
	primaryCIDR *cidr.CIDR,
	localNodeStore *node.LocalNodeStore,
	conf *option.DaemonConfig,
) {
	if nativeCIDR := conf.IPv4NativeRoutingCIDR; nativeCIDR != nil {
		// Validate that the configured native routing CIDR contains the VPC CIDR.
		ranges4, _ := ip.CoalesceCIDRs([]*net.IPNet{nativeCIDR.IPNet, primaryCIDR.IPNet})
		if len(ranges4) == 1 {
			logger.Info(
				"Native routing CIDR contains VPC CIDR, ignoring autodetected VPC CIDR.",
				logfields.VPCCIDR, primaryCIDR,
				option.IPv4NativeRoutingCIDR, nativeCIDR,
			)
		} else {
			logging.Fatal(logger, "Configured native routing CIDR does not contain VPC CIDR",
				logfields.VPCCIDR, primaryCIDR,
				option.IPv4NativeRoutingCIDR, nativeCIDR,
			)
		}
		return
	}

	logger.Info(
		"Using autodetected VPC primary CIDR as native routing CIDR.",
		logfields.VPCCIDR, primaryCIDR,
	)
	localNodeStore.Update(func(n *node.LocalNode) {
		n.Local.IPv4NativeRoutingCIDR = primaryCIDR
	})
}

// deriveENIVpcCIDR extracts the VPC primary CIDR from the first ENI in the
// CiliumNode status. All ENIs on a node belong to the same VPC, so any ENI
// can be used.
//
// Returns (nil, nil) when no ENI has populated PrimaryCIDR yet (transient
// startup state) and (nil, err) when at least one ENI had a non-empty value
// that failed to parse (persistent, surfaces via cell health).
func deriveENIVpcCIDR(logger *slog.Logger, node *ciliumv2.CiliumNode) (*cidr.CIDR, error) {
	var parseErrs []error
	for _, eni := range node.Status.ENI.ENIs {
		if eni.VPC.PrimaryCIDR == "" {
			continue
		}
		c, err := cidr.ParseCIDR(eni.VPC.PrimaryCIDR)
		if err != nil {
			// Per-ENI warn keeps granularity even when another ENI
			// later in the iteration succeeds.
			logger.Warn(
				"Failed to parse VPC primary CIDR from ENI status",
				logfields.ENI, eni.ID,
				logfields.VPCCIDR, eni.VPC.PrimaryCIDR,
				logfields.Error, err,
			)
			parseErrs = append(parseErrs, fmt.Errorf("ENI %s: %w", eni.ID, err))
			continue
		}
		return c, nil
	}
	if len(parseErrs) > 0 {
		return nil, fmt.Errorf("no valid VPC primary CIDR found: %w", errors.Join(parseErrs...))
	}
	return nil, nil
}

// validateENIConfig validates the ENI configuration in the CiliumNode resource
// and returns an error if the configuration is not fully set.
func validateENIConfig(node *ciliumv2.CiliumNode) error {
	// Check if the VPC CIDR is set for all ENIs
	for _, eni := range node.Status.ENI.ENIs {
		if len(eni.VPC.PrimaryCIDR) == 0 {
			return fmt.Errorf("VPC Primary CIDR not set for ENI %s", eni.ID)
		}

		for _, c := range eni.VPC.CIDRs {
			if len(c) == 0 {
				return fmt.Errorf("VPC CIDR not set for ENI %s", eni.ID)
			}
		}
	}

	// Check if all pool resource IPs are present in the status
	eniIPMap := map[string][]string{}
	for k, v := range node.Spec.IPAM.Pool {
		eniIPMap[v.Resource] = append(eniIPMap[v.Resource], k)
	}

	for eni, addresses := range eniIPMap {
		eniFound := false
		for _, sENI := range node.Status.ENI.ENIs {
			if eni == sENI.ID {
				for _, addr := range addresses {
					if !slices.Contains(sENI.Addresses, addr) {
						return fmt.Errorf("ENI %s does not have address %s", eni, addr)
					}
				}
				eniFound = true
			}
		}

		if !eniFound {
			return fmt.Errorf("ENI %s not found in status", eni)
		}
	}

	return nil
}

type eniDeviceConfig struct {
	name         string
	ip           net.IP
	cidr         *net.IPNet
	mtu          int
	usePrimaryIP bool
}

type configMap map[string]eniDeviceConfig // by MAC addr
type linkMap map[string]netlink.Link      // by MAC addr

func configureENIDevices(logger *slog.Logger, oldNode, newNode *ciliumv2.CiliumNode, mtuConfig MtuConfiguration, sysctl sysctl.Sysctl) {
	var (
		existingENIByName map[string]eniTypes.ENI
		addedENIByMac     = configMap{}
	)

	if oldNode != nil {
		existingENIByName = oldNode.Status.ENI.ENIs
	}

	usePrimary := defaults.UseENIPrimaryAddress
	if newNode.Spec.ENI.UsePrimaryAddress != nil {
		usePrimary = *newNode.Spec.ENI.UsePrimaryAddress
	}

	for name, eni := range newNode.Status.ENI.ENIs {
		if eni.IsExcludedBySpec(newNode.Spec.ENI) {
			continue
		}

		if _, ok := existingENIByName[name]; !ok {
			cfg, err := parseENIConfig(name, &eni, mtuConfig, usePrimary)
			if err != nil {
				logger.Error(
					"Skipping invalid ENI device config",
					logfields.Error, err,
					logfields.Resource, name,
				)
				continue
			}
			addedENIByMac[eni.MAC] = cfg
		}
	}

	go setupENIDevices(logger, addedENIByMac, sysctl)
}

func setupENIDevices(logger *slog.Logger, eniConfigByMac configMap, sysctl sysctl.Sysctl) {
	// Wait for the interfaces to be attached to the local node
	eniLinkByMac, err := waitForNetlinkDevicesWithRefetch(logger, eniConfigByMac)
	if err != nil {
		attachedENIByMac := make(map[string]string, len(eniLinkByMac))
		for mac, link := range eniLinkByMac {
			attachedENIByMac[mac] = link.Attrs().Name
		}
		requiredENIByMac := make(map[string]string, len(eniConfigByMac))
		for mac, eni := range eniConfigByMac {
			requiredENIByMac[mac] = eni.name
		}

		logger.Error(
			"Timed out waiting for ENIs to be attached",
			logfields.Error, err,
			logfields.AttachedENIs, attachedENIByMac,
			logfields.ExpectedENIs, requiredENIByMac,
		)
	}

	// Configure new interfaces.
	for mac, link := range eniLinkByMac {
		cfg, ok := eniConfigByMac[mac]
		if !ok {
			logger.Warn(
				"No configuration found for ENI device",
				logfields.MACAddr, mac,
			)
			continue
		}
		err = configureENINetlinkDevice(link, cfg, sysctl)
		if err != nil {
			logger.Error(
				"Failed to configure ENI device",
				logfields.Error, err,
				logfields.MACAddr, mac,
				logfields.Resource, cfg.name,
			)
		}
	}
}

func parseENIConfig(name string, eni *eniTypes.ENI, mtuConfig MtuConfiguration, usePrimary bool) (cfg eniDeviceConfig, err error) {
	ip := net.ParseIP(eni.IP)
	if ip == nil {
		return cfg, fmt.Errorf("failed to parse eni primary ip %q", eni.IP)
	}

	_, cidr, err := net.ParseCIDR(eni.Subnet.CIDR)
	if err != nil {
		return cfg, fmt.Errorf("failed to parse eni subnet cidr %q: %w", eni.Subnet.CIDR, err)
	}

	return eniDeviceConfig{
		name:         name,
		ip:           ip,
		cidr:         cidr,
		mtu:          mtuConfig.GetDeviceMTU(),
		usePrimaryIP: usePrimary,
	}, nil
}

func waitForNetlinkDevicesWithRefetch(logger *slog.Logger, configByMac configMap) (linkMap, error) {
	// ensX interfaces are created by renaming eth0 interface.
	// There is a brief window, where we can list the interfaces by MAC address,
	// and return eth0 link, before it gets renamed to ensX.
	// However, we need correct name of interface for setting rp_filter.
	// Let's refetch the links after we found them to make sure we have correct name.

	_, err := waitForNetlinkDevices(logger, configByMac)
	if err != nil {
		return nil, err
	}

	// Give some time for renaming to happen.
	// Usually it happens under ~100 ms.
	time.Sleep(1 * time.Second)

	// Refetch links
	linkByMac, err := waitForNetlinkDevices(logger, configByMac)
	if err != nil {
		return nil, err
	}

	return linkByMac, nil
}

const (
	waitForNetlinkDevicesMaxTries         = 15
	waitForNetlinkDevicesMinRetryInterval = 100 * time.Millisecond
	waitForNetlinkDevicesMaxRetryInterval = 30 * time.Second
)

func waitForNetlinkDevices(logger *slog.Logger, configByMac configMap) (linkByMac linkMap, err error) {
	for try := range waitForNetlinkDevicesMaxTries {
		links, err := safenetlink.LinkList()
		if err != nil {
			logger.Warn("failed to obtain eni link list - retrying", logfields.Error, err)
		} else {
			linkByMac = linkMap{}
			for _, link := range links {
				mac := link.Attrs().HardwareAddr.String()
				if _, ok := configByMac[mac]; ok {
					linkByMac[mac] = link
				}
			}

			if len(linkByMac) == len(configByMac) {
				return linkByMac, nil
			}
		}

		sleep := backoff.CalculateDuration(
			waitForNetlinkDevicesMinRetryInterval,
			waitForNetlinkDevicesMaxRetryInterval,
			2.0,
			false,
			try)
		time.Sleep(sleep)
	}

	// we return the linkByMac also in the error case to allow for better logging
	return linkByMac, errors.New("timed out waiting for ENIs to be attached")
}

func configureENINetlinkDevice(link netlink.Link, cfg eniDeviceConfig, sysctl sysctl.Sysctl) error {
	if err := netlink.LinkSetMTU(link, cfg.mtu); err != nil {
		return fmt.Errorf("failed to change MTU of link %s to %d: %w", link.Attrs().Name, cfg.mtu, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to up link %s: %w", link.Attrs().Name, err)
	}

	// Set the primary IP in order for SNAT to work correctly on this ENI
	if !cfg.usePrimaryIP {
		err := netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   cfg.ip,
				Mask: cfg.cidr.Mask,
			},
		})
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("failed to set eni primary ip address %q on link %q: %w", cfg.ip, link.Attrs().Name, err)
		}

		// Remove the subnet route for this ENI if it got setup by something(like networkd),
		// as it can cause the traffic to following subnet route using secondary ENI as the outgoing interface.
		// The Cilium could consider the wrong identity for the node and might drop
		// the traffic between the host and pods when network policy is in place.
		err = netlink.RouteDel(&netlink.Route{
			Dst:   cfg.cidr,
			Src:   cfg.ip,
			Table: unix.RT_TABLE_MAIN,
			Scope: netlink.SCOPE_LINK,
		})
		if err != nil && !errors.Is(err, unix.ESRCH) {
			// We ignore ESRCH, as it means the entry was already deleted
			return fmt.Errorf("failed to delete default route %q on link %q: %w", cfg.ip, link.Attrs().Name, err)
		}

		// Disable reverse path filtering for secondary ENI interfaces. This is needed since we might
		// receive packets from world ips directly to pod IPs when an Network Load Balancer is used
		// in IP mode + preserve client IP mode. Since the default route for world IPs goes to the
		// primary ENI, the kernel will drop packets from world IPs to pod IPs if rp_filter is enabled.
		err = sysctl.Disable([]string{"net", "ipv4", "conf", link.Attrs().Name, "rp_filter"})
		if err != nil {
			return fmt.Errorf("failed to disable rp_filter on link %q: %w", link.Attrs().Name, err)
		}
	}

	return nil
}

// buildENIAllocationResult derives ENI-specific AllocationResult metadata
// (PrimaryMAC, GatewayIP, VPC CIDRs, InterfaceNumber) by finding which ENI
// owns the given IP.
func buildENIAllocationResult(
	logger *slog.Logger,
	allocatedAddr netip.Addr,
	pool Pool,
	enis map[string]eniTypes.ENI,
	conf *option.DaemonConfig,
	ipMasqAgent *ipmasq.IPMasqAgent,
) (*AllocationResult, error) {
	for _, eni := range enis {
		if !eniContainsIP(eni, allocatedAddr) {
			continue
		}

		result := &AllocationResult{
			IP:         allocatedAddr,
			IPPoolName: pool,
			PrimaryMAC: eni.MAC,
		}
		if primaryCIDR, err := netip.ParsePrefix(eni.VPC.PrimaryCIDR); err == nil {
			result.CIDRs = append(result.CIDRs, primaryCIDR)
		}
		for _, c := range eni.VPC.CIDRs {
			if p, err := netip.ParsePrefix(c); err == nil {
				result.CIDRs = append(result.CIDRs, p)
			}
		}

		// Add manually configured Native Routing CIDR
		if conf.IPv4NativeRoutingCIDR != nil {
			if p, ok := netipx.FromStdIPNet(conf.IPv4NativeRoutingCIDR.IPNet); ok {
				result.CIDRs = append(result.CIDRs, p)
			}
		}

		// If the ip-masq-agent is enabled, get the CIDRs that are not masqueraded.
		// Note that the resulting ip rules will not be dynamically regenerated if the
		// ip-masq-agent configuration changes.
		if conf.EnableIPMasqAgent {
			for _, prefix := range ipMasqAgent.NonMasqCIDRsFromConfig() {
				if allocatedAddr.Is4() && prefix.Addr().Is4() {
					result.CIDRs = append(result.CIDRs, prefix)
				} else if !allocatedAddr.Is4() && prefix.Addr().Is6() {
					result.CIDRs = append(result.CIDRs, prefix)
				}
			}
		}

		if prefix, err := netip.ParsePrefix(eni.Subnet.CIDR); err == nil {
			// AWS reserves the first subnet IP for the gateway.
			// Ref: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html
			result.GatewayIP = prefix.Addr().Next()
		}
		result.InterfaceNumber = strconv.Itoa(eni.Number)

		return result, nil
	}

	return nil, fmt.Errorf("unable to find ENI for IP %s", allocatedAddr)
}

// eniContainsIP returns true if the given IP belongs to the ENI: either as the
// primary IP, a secondary address, or within one of its delegated prefixes.
func eniContainsIP(eni eniTypes.ENI, addr netip.Addr) bool {
	addrStr := addr.String()
	if eni.IP == addrStr {
		return true
	}
	if slices.Contains(eni.Addresses, addrStr) {
		return true
	}

	for _, prefix := range eni.Prefixes {
		parsed, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue
		}
		if parsed.Contains(addr) {
			return true
		}
	}

	return false
}

// eniPoolsFromResource returns the pool specification for ENI IPAM mode.
// Unlike the standard multi-pool mode which reads Allocated CIDRs from
// Spec.IPAM.Pools.Allocated, ENI mode derives them from Status.ENI.ENIs
// which is maintained by the operator. This allows the agent to be the
// sole writer of Spec.IPAM.Pools.Allocated while reading CIDRs from a
// different source.
//
// Secondary IPs are represented as /32 CIDRs and delegated prefixes as /28 CIDRs.
func eniPoolsFromResource(node *ciliumv2.CiliumNode) *ipamTypes.IPAMPoolSpec {
	pools := &ipamTypes.IPAMPoolSpec{
		Requested: node.Spec.IPAM.Pools.Requested,
		Allocated: node.Spec.IPAM.Pools.Allocated,
	}

	if len(node.Status.ENI.ENIs) == 0 {
		return pools
	}

	var cidrs []ipamTypes.IPAMCIDR
	for _, eni := range node.Status.ENI.ENIs {
		if eni.IsExcludedBySpec(node.Spec.ENI) {
			continue
		}

		var prefixes []netip.Prefix
		for _, p := range eni.Prefixes {
			cidrs = append(cidrs, ipamTypes.IPAMCIDR(p))
			if parsed, err := netip.ParsePrefix(p); err == nil {
				prefixes = append(prefixes, parsed)
			}
		}

		// In parseENI (pkg/aws/ec2), we currently use PrefixToIps to flatten each prefixes
		// into 16 individual IPs and append those IPs to the ENI Addresses field.
		// Here we need to apply a reverse logic to only advertise as /32 CIDRs in the pool
		// regular secondary addresses (or the ENI primary IP when using UsePrimaryAddress)
		// and not addresses that are already being advertised through a /28 CIDR.
		for _, addrStr := range eni.Addresses {
			parsed, err := netip.ParseAddr(addrStr)
			if err != nil {
				continue
			}
			if addressCoveredByPrefix(parsed, prefixes) {
				continue
			}
			cidrs = append(cidrs, ipamTypes.IPAMCIDR(addrStr+"/32"))
		}
	}

	if len(cidrs) > 0 {
		pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{
				Pool:  defaults.IPAMDefaultIPPool,
				CIDRs: cidrs,
			},
		}
	}

	return pools
}

// addressCoveredByPrefix returns true if the given IP address falls
// within any of the provided prefixes.
func addressCoveredByPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// eniMultiPoolAllocator wraps multiPoolAllocator to enrich AllocationResult
// with ENI-specific metadata.
type eniMultiPoolAllocator struct {
	multiPoolAllocator
	logger      *slog.Logger
	conf        *option.DaemonConfig
	ipMasqAgent *ipmasq.IPMasqAgent
}

func (a *eniMultiPoolAllocator) enrichResult(result *AllocationResult, err error) (*AllocationResult, error) {
	if err != nil || result == nil {
		return result, err
	}

	// Take a DeepCopy of the ENIs map under the lock so buildENIAllocationResult
	// can safely iterate it without holding the mutex. Scoped to Status.ENI
	// since that's all buildENIAllocationResult reads.
	a.manager.nodeMutex.Lock()
	var enis map[string]eniTypes.ENI
	if a.manager.node != nil {
		enis = a.manager.node.Status.ENI.DeepCopy().ENIs
	}
	a.manager.nodeMutex.Unlock()

	enriched, enrichErr := buildENIAllocationResult(a.logger, result.IP, result.IPPoolName, enis, a.conf, a.ipMasqAgent)
	if enrichErr != nil {
		// The underlying Allocate* call already reserved the IP in the
		// allocator. Release it to avoid leaking the reservation when the
		// caller treats the wrapped error as an allocation failure.
		if relErr := a.multiPoolAllocator.Release(result.IP, result.IPPoolName); relErr != nil {
			return nil, errors.Join(enrichErr, fmt.Errorf("release after enrichment failure: %w", relErr))
		}
		return nil, enrichErr
	}
	return enriched, nil
}

func (a *eniMultiPoolAllocator) Allocate(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.Allocate(addr, owner, pool))
}

func (a *eniMultiPoolAllocator) AllocateWithoutSyncUpstream(addr netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.AllocateWithoutSyncUpstream(addr, owner, pool))
}

func (a *eniMultiPoolAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.AllocateNext(owner, pool))
}

func (a *eniMultiPoolAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	return a.enrichResult(a.multiPoolAllocator.AllocateNextWithoutSyncUpstream(owner, pool))
}

// ENIMultiPoolAllocatorParams contains the parameters for creating ENI
// multi-pool allocators.
type ENIMultiPoolAllocatorParams struct {
	Logger *slog.Logger

	IPv4Enabled          bool
	IPv6Enabled          bool
	CiliumNodeUpdateRate time.Duration

	Node           agentK8s.LocalCiliumNodeResource
	LocalNodeStore *node.LocalNodeStore
	CNClient       cilium_v2.CiliumNodeInterface
	JobGroup       job.Group

	Conf        *option.DaemonConfig
	IPMasqAgent *ipmasq.IPMasqAgent
}

func newENIMultiPoolAllocators(p ENIMultiPoolAllocatorParams) (Allocator, Allocator) {
	preallocMap := preAllocatePerPool{
		Pool(defaults.IPAMDefaultIPPool): defaults.IPAMPreAllocation,
	}

	mgr := newMultiPoolManager(MultiPoolManagerParams{
		Logger:               p.Logger,
		IPv4Enabled:          p.IPv4Enabled,
		IPv6Enabled:          p.IPv6Enabled,
		CiliumNodeUpdateRate: p.CiliumNodeUpdateRate,
		PreallocMap:          preallocMap,
		Node:                 p.Node,
		CNClient:             p.CNClient,
		JobGroup:             p.JobGroup,
		PoolsFromResource:    eniPoolsFromResource,
		AllowFirstLastIPs:    true,
		LinearPreAlloc:       true,
	})

	allocCIDRsReady := startLocalNodeAllocCIDRsSync(p.IPv4Enabled, p.IPv6Enabled, p.JobGroup, p.Node, p.LocalNodeStore)
	nativeRoutingCIDRReady := startENINativeRoutingCIDRSync(p.Logger, p.JobGroup, p.Node, p.LocalNodeStore, p.Conf)

	// Wait for local node to be updated to avoid propagating spurious updates.
	waitForLocalNodeUpdate(p.Logger, mgr)
	// Independently wait for the alloc-CIDR and native-routing-CIDR observers:
	// they run in separate jobs from the multi-pool manager and are not
	// synchronized with mgr.localNodeUpdated().
	waitForLocalNodeAllocCIDRs(p.Logger, allocCIDRsReady)
	waitForENINativeRoutingCIDR(p.Logger, nativeRoutingCIDRReady)

	newAllocator := func(family Family) *eniMultiPoolAllocator {
		return &eniMultiPoolAllocator{
			multiPoolAllocator: multiPoolAllocator{manager: mgr, family: family},
			logger:             p.Logger,
			conf:               p.Conf,
			ipMasqAgent:        p.IPMasqAgent,
		}
	}
	return newAllocator(IPv4), newAllocator(IPv6)
}
