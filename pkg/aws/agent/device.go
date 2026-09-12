// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/job"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/time"
)

// startDeviceConfigurator starts a CiliumNode observer that configures ENI
// network devices independently of the IPAM allocator.
func startDeviceConfigurator(
	logger *slog.Logger,
	jg job.Group,
	nodeResource agentK8s.LocalCiliumNodeResource,
	mtuConfig mtu.MTU,
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
	for _, eni := range node.Status.ENI.ENIs {
		if !eni.IP.IsValid() {
			return fmt.Errorf("primary IP not set for ENI %s", eni.ID)
		}
		if !eni.Subnet.CIDR.IsValid() {
			return fmt.Errorf("subnet CIDR not set for ENI %s", eni.ID)
		}
		if !eni.VPC.PrimaryCIDR.IsValid() {
			return fmt.Errorf("VPC Primary CIDR not set for ENI %s", eni.ID)
		}
		for _, c := range eni.VPC.CIDRs {
			if !c.IsValid() {
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
					parsed, err := netip.ParseAddr(addr)
					if err != nil {
						return fmt.Errorf("invalid address %q in pool for ENI %s: %w", addr, eni, err)
					}
					if !slices.ContainsFunc(sENI.Addresses, func(a iputil.Addr) bool { return a.Addr == parsed }) {
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
	ip           netip.Addr
	cidr         netip.Prefix
	mtu          int
	usePrimaryIP bool
}

type configMap map[mac.MAC]eniDeviceConfig
type linkMap map[mac.MAC]netlink.Link

func configureENIDevices(logger *slog.Logger, oldNode, newNode *ciliumv2.CiliumNode, mtuConfig mtu.MTU, sysctl sysctl.Sysctl) {
	var (
		existingENIByName map[string]awsTypes.ENI
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
			addedENIByMac[eni.MAC] = eniDeviceConfig{
				name:         name,
				ip:           eni.IP.Addr,
				cidr:         eni.Subnet.CIDR.Masked(),
				mtu:          mtuConfig.GetDeviceMTU(),
				usePrimaryIP: usePrimary,
			}
		}
	}

	go setupENIDevices(logger, addedENIByMac, sysctl)
}

func setupENIDevices(logger *slog.Logger, eniConfigByMac configMap, sysctl sysctl.Sysctl) {
	// Wait for the interfaces to be attached to the local node
	eniLinkByMac, err := waitForNetlinkDevicesWithRefetch(logger, eniConfigByMac)
	if err != nil {
		attachedENIByMac := make(map[mac.MAC]string, len(eniLinkByMac))
		for m, link := range eniLinkByMac {
			attachedENIByMac[m] = link.Attrs().Name
		}
		requiredENIByMac := make(map[mac.MAC]string, len(eniConfigByMac))
		for m, eni := range eniConfigByMac {
			requiredENIByMac[m] = eni.name
		}

		logger.Error(
			"Timed out waiting for ENIs to be attached",
			logfields.Error, err,
			logfields.AttachedENIs, attachedENIByMac,
			logfields.ExpectedENIs, requiredENIByMac,
		)
	}

	// Configure new interfaces.
	for m, link := range eniLinkByMac {
		cfg, ok := eniConfigByMac[m]
		if !ok {
			logger.Warn(
				"No configuration found for ENI device",
				logfields.MACAddr, m,
			)
			continue
		}
		err = configureENINetlinkDevice(link, cfg, sysctl)
		if err != nil {
			logger.Error(
				"Failed to configure ENI device",
				logfields.Error, err,
				logfields.MACAddr, m,
				logfields.Resource, cfg.name,
			)
		}
	}
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
				m, err := mac.FromHardwareAddr(link.Attrs().HardwareAddr)
				if err != nil {
					// An ENI always has a MAC, so a device without
					// one cannot be the device we are waiting for.
					continue
				}
				if _, ok := configByMac[m]; ok {
					linkByMac[m] = link
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

// configureENINetlinkDevice owns the MTU and up-state of ENI links.
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
			IPNet: netipx.PrefixIPNet(netip.PrefixFrom(cfg.ip, cfg.cidr.Bits())),
		})
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("failed to set eni primary ip address %q on link %q: %w", cfg.ip, link.Attrs().Name, err)
		}

		// Remove the subnet route for this ENI if it got setup by something(like networkd),
		// as it can cause traffic to follow the subnet route using secondary ENI as the outgoing interface.
		// The Cilium could consider the wrong identity for the node and might drop
		// the traffic between the host and pods when network policy is in place.
		err = netlink.RouteDel(&netlink.Route{
			Dst:   netipx.PrefixIPNet(cfg.cidr),
			Src:   cfg.ip.AsSlice(),
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
