// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

const (
	// MaxMTU is the highest MTU that can be used for devices and routes
	// handled by Cilium. It will typically be used to configure inbound
	// paths towards containers where it is guaranteed that the packet will
	// not be rerouted to another node, and therefore will not lead to
	// any form of IP fragmentation.
	// One might expect this to be 65535, however Linux seems to cap the
	// MTU of routes at 65520, so we use this value below.
	MaxMTU = 65520

	// EthernetMTU is the standard MTU for Ethernet devices. It is used
	// as the MTU for container devices when running direct routing mode.
	EthernetMTU = 1500

	// TunnelOverheadIPv{4,6} is an approximation for bytes used for tunnel
	// encapsulation. It accounts for:
	//                       IPv4  IPv6
	//    (Outer ethernet is not accounted against MTU size)
	//    Outer IPv4 header:  20B  40B
	//    Outer UDP header:    8B   8B
	//    Outer VXLAN header:  8B   8B
	//    Original Ethernet:  14B  14B
	//                        ---  ---
	//    Total extra bytes:  50B  70B
	TunnelOverheadIPv4 = 50
	TunnelOverheadIPv6 = 70

	// DsrTunnelOverhead is about the GENEVE DSR option that gets inserted
	// by the LB, when addressing a Service in hs-ipcache mode
	DsrTunnelOverhead = 12

	// EncryptionIPsecOverhead is an approximation for bytes used for
	// encryption. Depending on key size and encryption type the actual
	// size may vary here we do calculations for 128B keys and Auth. The
	// overhead is accounted for as:
	//    Outer IP header:    20B
	//    SPI:		   4B
	//    Sequece Numbers:	   4B
	//    Next Header:         1B
	//    ICV:		  16B
	//    Padding:            16B
	//    128bit Auth:        16B
	//			  ---
	//    Total extra bytes:  77B
	EncryptionIPsecOverhead = 77

	// EncryptionDefaultAuthKeyLength is 16 representing 128B key recommended
	// size for GCM(AES*) in RFC4106. Users may input other lengths via
	// key secrets.
	EncryptionDefaultAuthKeyLength = 16

	// WireguardOverhead is an approximation for the overhead of WireGuard
	// encapsulation.
	//
	// https://github.com/torvalds/linux/blob/v5.12/drivers/net/wireguard/device.c#L262:
	//      MESSAGE_MINIMUM_LENGTH:    32B
	//      Outer IPv4 or IPv6 header: 40B
	//      Outer UDP header:           8B
	//                                 ---
	//      Total extra bytes:         80B
	WireguardOverhead = 80
)

// Configuration is an MTU configuration as returned by NewConfiguration
type Configuration struct {
	authKeySize      int
	encapEnabled     bool
	encryptEnabled   bool
	wireguardEnabled bool
	tunnelOverhead   int
}

// NewConfiguration returns a new MTU configuration which is used to calculate
// MTU values from a base MTU based on the config.
func NewConfiguration(authKeySize int, encryptEnabled, encapEnabled, wireguardEnabled, vxlanOverIPv6 bool) Configuration {
	tunnelOverhead := TunnelOverheadIPv4
	if vxlanOverIPv6 {
		tunnelOverhead = TunnelOverheadIPv6
	}
	return Configuration{
		authKeySize:      authKeySize,
		encapEnabled:     encapEnabled,
		encryptEnabled:   encryptEnabled,
		wireguardEnabled: wireguardEnabled,
		tunnelOverhead:   tunnelOverhead,
	}
}

func (c Configuration) Calculate(baseMTU int) RouteMTU {
	return RouteMTU{
		DeviceMTU:           c.getDeviceMTU(baseMTU),
		RouteMTU:            c.getRouteMTU(baseMTU),
		RoutePostEncryptMTU: c.getRoutePostEncryptMTU(baseMTU),
	}
}

// GetRoutePostEncryptMTU return the MTU to be used on the encryption routing
// table. This is the MTU without encryption overhead and in the tunnel
// case accounts for the tunnel overhead.
func (c *Configuration) getRoutePostEncryptMTU(baseMTU int) int {
	if c.encapEnabled {
		postEncryptMTU := baseMTU - c.tunnelOverhead
		if postEncryptMTU == 0 {
			return EthernetMTU - c.tunnelOverhead
		}
		return postEncryptMTU

	}
	return c.getDeviceMTU(baseMTU)
}

// GetRouteMTU returns the MTU to be used on the network. When running in
// tunneling mode and/or with encryption enabled, this will have tunnel and
// encryption overhead accounted for.
func (c *Configuration) getRouteMTU(baseMTU int) int {
	if c.wireguardEnabled {
		if c.encapEnabled {
			return c.getDeviceMTU(baseMTU) - (WireguardOverhead + c.tunnelOverhead)
		}
		return c.getDeviceMTU(baseMTU) - WireguardOverhead
	}

	if !c.encapEnabled && !c.encryptEnabled {
		return c.getDeviceMTU(baseMTU)
	}

	encryptOverhead := 0

	if c.encryptEnabled {
		// Add the difference between the default and the actual key sizes here
		// to account for users specifying non-default auth key lengths.
		encryptOverhead = EncryptionIPsecOverhead + (c.authKeySize - EncryptionDefaultAuthKeyLength)
	}

	if c.encryptEnabled && !c.encapEnabled {
		preEncryptMTU := baseMTU - encryptOverhead
		if preEncryptMTU == 0 {
			return EthernetMTU - EncryptionIPsecOverhead
		}
		return preEncryptMTU
	}

	tunnelMTU := baseMTU - (c.tunnelOverhead + encryptOverhead)
	if tunnelMTU <= 0 {
		if c.encryptEnabled {
			return EthernetMTU - (c.tunnelOverhead + EncryptionIPsecOverhead)
		}
		return EthernetMTU - c.tunnelOverhead
	}

	return tunnelMTU
}

// getDeviceMTU returns the MTU to be used on workload facing devices.
func (c *Configuration) getDeviceMTU(baseMTU int) int {
	if baseMTU == 0 {
		return EthernetMTU
	}

	return baseMTU
}
