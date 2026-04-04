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

	"github.com/cilium/hive/job"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/ipmasq"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	node *ciliumv2.CiliumNode,
	conf *option.DaemonConfig,
	ipMasqAgent *ipmasq.IPMasqAgent,
) (*AllocationResult, error) {
	for _, eni := range node.Status.ENI.ENIs {
		if !eniContainsIP(eni, allocatedAddr) {
			continue
		}

		result := &AllocationResult{
			IP:         allocatedAddr,
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
