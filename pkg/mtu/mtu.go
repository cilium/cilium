// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"net"
)

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

	// TunnelOverhead is an approximation for bytes used for tunnel
	// encapsulation. It accounts for:
	//    (Outer ethernet is not accounted against MTU size)
	//    Outer IPv4 header:  20B
	//    Outer UDP header:    8B
	//    Outer VXLAN header:  8B
	//    Original Ethernet:  14B
	//                        ---
	//    Total extra bytes:  50B
	TunnelOverhead = 50

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

	// WireguardOverhead is an approximation for the overhead of wireguard
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
	// standardMTU is the regular MTU used for configuring devices and
	// routes where packets are expected to be delivered outside the node.
	//
	// Note that this is a singleton for the process including this
	// package. This means, for instance, that when using this from the
	// ``pkg/plugins/*`` sources, it will not respect the settings
	// configured inside the ``daemon/``.
	standardMTU int

	// tunnelMTU is the MTU used for configuring a tunnel mesh for
	// inter-node connectivity.
	//
	// Similar to StandardMTU, this is a singleton for the process.
	tunnelMTU int

	// preEncrypMTU is the MTU used for configurations of a encryption route.
	// If tunneling is enabled the tunnelMTU is used which will include
	// additional encryption overhead if needed.
	preEncryptMTU int

	// postEncryptMTU is the MTU used for configurations of a encryption
	// route _after_ encryption tags have been addded. These will be used
	// in the encryption routing table. The MTU accounts for the tunnel
	// overhead, if any, but assumes packets are already encrypted.
	postEncryptMTU int

	encapEnabled     bool
	encryptEnabled   bool
	wireguardEnabled bool
}

// NewConfiguration returns a new MTU configuration. The MTU can be manually
// specified, otherwise it will be automatically detected. if encapEnabled is
// true, the MTU is adjusted to account for encapsulation overhead for all
// routes involved in node to node communication.
func NewConfiguration(authKeySize int, encryptEnabled bool, encapEnabled bool, wireguardEnabled bool, mtu int, mtuDetectIP net.IP) Configuration {
	encryptOverhead := 0

	if mtu == 0 {
		var err error

		if mtuDetectIP != nil {
			mtu, err = getMTUFromIf(mtuDetectIP)
		} else {
			mtu, err = autoDetect()
		}
		if err != nil {
			log.WithError(err).Warning("Unable to automatically detect MTU")
			mtu = EthernetMTU
		}
	}

	if encryptEnabled {
		// Add the difference between the default and the actual key sizes here
		// to account for users specifying non-default auth key lengths.
		encryptOverhead = EncryptionIPsecOverhead + (authKeySize - EncryptionDefaultAuthKeyLength)
	}

	conf := Configuration{
		standardMTU:      mtu,
		tunnelMTU:        mtu - (TunnelOverhead + encryptOverhead),
		postEncryptMTU:   mtu - TunnelOverhead,
		preEncryptMTU:    mtu - encryptOverhead,
		encapEnabled:     encapEnabled,
		encryptEnabled:   encryptEnabled,
		wireguardEnabled: wireguardEnabled,
	}

	if conf.tunnelMTU < 0 {
		conf.tunnelMTU = 0
	}

	return conf
}

// GetRoutePostEncryptMTU return the MTU to be used on the encryption routing
// table. This is the MTU without encryption overhead and in the tunnel
// case accounts for the tunnel overhead.
func (c *Configuration) GetRoutePostEncryptMTU() int {
	if c.encapEnabled {
		if c.postEncryptMTU == 0 {
			return EthernetMTU - TunnelOverhead
		}
		return c.postEncryptMTU

	}
	return c.GetDeviceMTU()
}

// GetRouteMTU returns the MTU to be used on the network. When running in
// tunneling mode and/or with encryption enabled, this will have tunnel and
// encryption overhead accounted for.
func (c *Configuration) GetRouteMTU() int {
	if c.wireguardEnabled {
		return c.GetDeviceMTU() - WireguardOverhead
	}

	if !c.encapEnabled && !c.encryptEnabled {
		return c.GetDeviceMTU()
	}

	if c.encryptEnabled && !c.encapEnabled {
		if c.preEncryptMTU == 0 {
			return EthernetMTU - EncryptionIPsecOverhead
		}
		return c.preEncryptMTU
	}

	if c.tunnelMTU == 0 {
		if c.encryptEnabled {
			return EthernetMTU - (TunnelOverhead + EncryptionIPsecOverhead)
		}
		return EthernetMTU - TunnelOverhead
	}

	return c.tunnelMTU
}

// GetDeviceMTU returns the MTU to be used on workload facing devices.
func (c *Configuration) GetDeviceMTU() int {
	if c.standardMTU == 0 {
		return EthernetMTU
	}

	return c.standardMTU
}
