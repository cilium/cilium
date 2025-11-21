// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dra

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

func listDummyDevices(
	ctx context.Context,
	logger *slog.Logger,
	toQualifiedName func(string) resourceapi.QualifiedName,
) ([]resourceapi.Device, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to get links: %w", err)
	}

	var (
		devices []resourceapi.Device
		errs    []error
	)

	for _, link := range links {
		if link.Type() != "dummy" {
			continue
		}

		// Skip down interfaces
		if link.Attrs().Flags&net.FlagUp == 0 {
			continue
		}

		name := link.Attrs().Name
		hwAddr := link.Attrs().HardwareAddr.String()
		mtu := link.Attrs().MTU

		device := resourceapi.Device{
			Name: link.Attrs().Name,
			Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
				toQualifiedName("interface_name"): {StringValue: ptr.To(name)},
				toQualifiedName("mac_address"):    {StringValue: ptr.To(hwAddr)},
				toQualifiedName("mtu"):            {IntValue: ptr.To(int64(mtu))},
				toQualifiedName("flags"):          {StringValue: ptr.To(link.Attrs().Flags.String())},
			},
		}

		// Add IP addresses if available
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get ip addresses for link %s: %w", name, err))
			continue
		}
		ips := make([]string, 0, len(addrs))
		for i, addr := range addrs {
			ips = append(ips, addr.IPNet.String())
			attrName := fmt.Sprintf("%s/ip_address_%d", driverName, i)
			device.Attributes[toQualifiedName(attrName)] = resourceapi.DeviceAttribute{
				StringValue: ptr.To(addr.IPNet.String()),
			}
		}

		devices = append(devices, device)

		logger.InfoContext(ctx, "Discovered dummy device",
			logfields.Device, name,
			logfields.HardwareAddr, hwAddr,
			logfields.MTU, mtu,
			logfields.IPAddrs, ips,
		)
	}

	return devices, errors.Join(errs...)
}
