// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net"
	"time"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/defaults"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type eniDeviceConfig struct {
	name         string
	ip           net.IP
	cidr         *net.IPNet
	mtu          int
	usePrimaryIP bool
	link         netlink.Link
}

type configMap map[string]eniDeviceConfig // by MAC addr

func configureENIDevices(oldNode, newNode *ciliumv2.CiliumNode, mtuConfig MtuConfiguration) error {
	addedENIByMac := parseENIConfigs(oldNode, newNode, mtuConfig)
	go setupENIDevices(addedENIByMac)
	return nil
}

func parseENIConfigs(oldNode, newNode *ciliumv2.CiliumNode, mtuConfig MtuConfiguration) configMap {
	existingENIByName := make(map[string]eniTypes.ENI)
	addedENIByMac := make(configMap)

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
				log.WithError(err).
					WithField(logfields.Resource, name).
					Error("Skipping invalid ENI device config")
				continue
			}
			addedENIByMac[eni.MAC] = cfg
		}
	}

	return addedENIByMac
}

func setupENIDevices(eniConfigByMac configMap) {
	// Wait for the interfaces to be attached to the local node
	missingENIByMac, err := waitForNetlinkDevices(eniConfigByMac)
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.MissingENIs: missingENIByMac,
		}).Error("Timed out waiting for ENIs to be attached")
	}

	// Configure new interfaces.
	for mac, cfg := range eniConfigByMac {
		err = configureENINetlinkDevice(cfg)
		if err != nil {
			log.WithError(err).
				WithFields(logrus.Fields{
					logfields.MACAddr:  mac,
					logfields.Resource: cfg.name,
				}).
				Error("Failed to configure ENI device")
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

const (
	waitForNetlinkDevicesMaxTries         = 15
	waitForNetlinkDevicesMinRetryInterval = 100 * time.Millisecond
	waitForNetlinkDevicesMaxRetryInterval = 30 * time.Second
)

// waitForNetlinkDevices waits for all ENI devices to have their corresponding
// interface show up on the host. It also populates the eniDeviceConfig.link
// field with those netlink interfaces.
func waitForNetlinkDevices(configByMac configMap) (map[string]string, error) {
	missingENIByMac := make(map[string]string, len(configByMac))
	for mac, eni := range configByMac {
		missingENIByMac[mac] = eni.name
	}

	for try := 0; try < waitForNetlinkDevicesMaxTries; try++ {
		links, err := netlink.LinkList()
		if err != nil {
			return missingENIByMac, fmt.Errorf("failed to obtain eni link list: %w", err)
		}

		for _, link := range links {
			mac := link.Attrs().HardwareAddr.String()
			if cfg, ok := configByMac[mac]; ok {
				cfg.link = link
				configByMac[mac] = cfg
				delete(missingENIByMac, mac)
			}
		}

		if len(missingENIByMac) == 0 {
			return missingENIByMac, nil
		}

		sleep := backoff.CalculateDuration(
			waitForNetlinkDevicesMinRetryInterval,
			waitForNetlinkDevicesMaxRetryInterval,
			2.0,
			false,
			try)
		time.Sleep(sleep)
	}

	// we return the missingENIByMac map also in the error case to allow for better logging
	return missingENIByMac, errors.New("timed out waiting for ENIs to be attached")
}

func configureENINetlinkDevice(cfg eniDeviceConfig) error {
	if err := netlink.LinkSetMTU(cfg.link, cfg.mtu); err != nil {
		return fmt.Errorf("failed to change MTU of link %s to %d: %w", cfg.link.Attrs().Name, cfg.mtu, err)
	}

	if err := netlink.LinkSetUp(cfg.link); err != nil {
		return fmt.Errorf("failed to up link %s: %w", cfg.link.Attrs().Name, err)
	}

	// Set the primary IP in order for SNAT to work correctly on this ENI
	if !cfg.usePrimaryIP {
		err := netlink.AddrAdd(cfg.link, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   cfg.ip,
				Mask: cfg.cidr.Mask,
			},
		})
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("failed to set eni primary ip address %q on link %q: %w", cfg.ip, cfg.link.Attrs().Name, err)
		}

		// Remove the default route for this ENI, as it can overlap with the
		// default route of the primary ENI and therefore break node connectivity
		err = netlink.RouteDel(&netlink.Route{
			Dst:   cfg.cidr,
			Src:   cfg.ip,
			Table: unix.RT_TABLE_MAIN,
			Scope: netlink.SCOPE_LINK,
		})
		if err != nil && !errors.Is(err, unix.ESRCH) {
			// We ignore ESRCH, as it means the entry was already deleted
			return fmt.Errorf("failed to delete default route %q on link %q: %w", cfg.ip, cfg.link.Attrs().Name, err)
		}
	}

	return nil
}
