// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	current "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func interfaceAdd(ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf *models.DaemonConfigurationStatus) error {
	if ipam == nil {
		return fmt.Errorf("missing IPAM configuration")
	}
	// If the gateway IP is not available, it is already set up
	if !ipam.Gateway.IsValid() {
		return nil
	}

	masq := conf.MasqueradeProtocols.IPv6
	if ipConfig.Address.IP.To4() != nil {
		masq = conf.MasqueradeProtocols.IPv4
	}

	options := []linuxrouting.RoutingInfoOption{
		linuxrouting.WithMasquerade(masq),
		// Ensure CNI ADD can repair interface MTU and state after a transient
		// setup failure before installing endpoint routing state.
		linuxrouting.WithMTU(int(conf.DeviceMTU)),
		linuxrouting.WithLinkState(true),
	}
	if conf.IpamMode == ipamOption.IPAMAzure {
		options = append(options, linuxrouting.WithCompatEgressPriority())
	}

	routingInfo, err := linuxrouting.NewRoutingInfo(
		ipam.Gateway.String(),
		ipam.MasterMac,
		ipam.InterfaceNumber,
		options...,
	)
	if err != nil {
		return fmt.Errorf("unable to parse routing info: %w", err)
	}

	if err := routingInfo.Configure(
		ip.AddrFromIP(ipConfig.Address.IP),
		false,
	); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %w", err)
	}

	return nil
}
