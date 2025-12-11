// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/defaults"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

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
		err = configureENINetlinkDevice(logger, link, cfg, sysctl)
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

	waitRouteSetupMaxTries      = 10
	waitRouteSetupRetryInterval = 1 * time.Second
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

func configureENINetlinkDevice(logger *slog.Logger, link netlink.Link, cfg eniDeviceConfig, sysctl sysctl.Sysctl) error {
	if err := netlink.LinkSetMTU(link, cfg.mtu); err != nil {
		return fmt.Errorf("failed to change MTU of link %s to %d: %w", link.Attrs().Name, cfg.mtu, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to up link %s: %w", link.Attrs().Name, err)
	}

	// Set the primary IP in order for SNAT to work correctly on this ENI
	if !cfg.usePrimaryIP {
		isDHCP, af := checkIPDHCPStatus(logger, link, cfg.ip)
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
		// as it can cause the health check to following subnet route using secondary ENI and fail.

		if isDHCP {
			waitRouteSetup(logger, link, cfg.cidr, af)
		}
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

func checkIPDHCPStatus(logger *slog.Logger, link netlink.Link, ip net.IP) (bool, int) {
	addressFamiliy := netlink.FAMILY_V6
	isDHCP := false
	if ip.To4() != nil {
		addressFamiliy = netlink.FAMILY_V4
	}
	addrs, err := safenetlink.AddrList(link, addressFamiliy)
	if err != nil {
		logger.Info("failed to get address list for link",
			logfields.Device, link.Attrs().Name,
			logfields.Error, err,
		)
	}

	for _, addr := range addrs {
		if !addr.IP.Equal(ip) {
			continue
		}

		if (addr.Flags & unix.IFA_F_PERMANENT) == 0 {
			isDHCP = true
			logger.Warn("DHCP on secondary ENI may conflict with Cilium IPAM and cause routing issues. Please disable it.", logfields.Device, link.Attrs().Name)
		}
		break
	}
	return isDHCP, addressFamiliy
}

func waitRouteSetup(logger *slog.Logger, link netlink.Link, dst *net.IPNet, af int) {
	for i := 1; i <= waitRouteSetupMaxTries; i++ {
		routes, err := safenetlink.RouteList(link, af)
		if err != nil {
			logger.Warn("Failed to get route list for link",
				logfields.Device, link.Attrs().Name,
				logfields.Error, err,
			)
		} else {
			for _, r := range routes {
				if r.Dst == nil {
					continue
				}
				if r.Dst.IP.Equal(dst.IP) {
					logger.Info("DHCP route setup completed",
						logfields.Device, link.Attrs().Name,
						logfields.DestinationCIDR, dst,
					)
					return
				}
			}
		}

		time.Sleep(waitRouteSetupRetryInterval)
	}

	logger.Warn("Timed out waiting for DHCP route setup", logfields.Device, link.Attrs().Name)
}
