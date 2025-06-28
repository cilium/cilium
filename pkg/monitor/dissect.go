// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
)

type DisplayFormat bool

const (
	DisplayLabel   DisplayFormat = false
	DisplayNumeric DisplayFormat = true
)

type parserCache struct {
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	tcp     layers.TCP
	udp     layers.UDP
	sctp    layers.SCTP
	decoded []gopacket.LayerType

	overlay struct {
		vxlan   layers.VXLAN
		geneve  layers.Geneve
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		icmp4   layers.ICMPv4
		icmp6   layers.ICMPv6
		tcp     layers.TCP
		udp     layers.UDP
		sctp    layers.SCTP
		decoded []gopacket.LayerType
	}
}

type decodeOpts struct {
	IsL3Device bool
	IsIPv6     bool
	IsVXLAN    bool
	IsGeneve   bool
}

var (
	cache       *parserCache
	dissectLock lock.Mutex

	parserL2Dev *gopacket.DecodingLayerParser
	parserL3Dev struct {
		IPv4 *gopacket.DecodingLayerParser
		IPv6 *gopacket.DecodingLayerParser
	}
	parserOverlay struct {
		VXLAN  *gopacket.DecodingLayerParser
		Geneve *gopacket.DecodingLayerParser
	}
)

// getParser must be called with dissectLock held
func initParser() {
	if cache == nil {
		// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
		logging.DefaultSlogLogger.Info("Initializing dissection cache...")

		cache = &parserCache{}
		cache.decoded = []gopacket.LayerType{}
		cache.overlay.decoded = []gopacket.LayerType{}

		decoders := []gopacket.DecodingLayer{
			&cache.eth,
			&cache.ip4, &cache.ip6,
			&cache.icmp4, &cache.icmp6,
			&cache.tcp, &cache.udp, &cache.sctp,
		}
		overlayDecoders := []gopacket.DecodingLayer{
			&cache.overlay.vxlan, &cache.overlay.geneve,
			&cache.overlay.eth,
			&cache.overlay.ip4, &cache.overlay.ip6,
			&cache.overlay.icmp4, &cache.overlay.icmp6,
			&cache.overlay.tcp, &cache.overlay.udp, &cache.overlay.sctp,
		}
		parserL2Dev = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, decoders...)
		parserL3Dev.IPv4 = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, decoders...)
		parserL3Dev.IPv6 = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, decoders...)
		parserOverlay.VXLAN = gopacket.NewDecodingLayerParser(layers.LayerTypeVXLAN, overlayDecoders...)
		parserOverlay.Geneve = gopacket.NewDecodingLayerParser(layers.LayerTypeGeneve, overlayDecoders...)

		parserL2Dev.IgnoreUnsupported = true
		parserL3Dev.IPv4.IgnoreUnsupported = true
		parserL3Dev.IPv6.IgnoreUnsupported = true
		parserOverlay.VXLAN.IgnoreUnsupported = true
		parserOverlay.Geneve.IgnoreUnsupported = true
	}
}

func getTCPInfo() string {
	info := ""
	addTCPFlag := func(flag, new string) string {
		if flag == "" {
			return new
		}
		return flag + ", " + new
	}

	if cache.tcp.SYN {
		info = addTCPFlag(info, "SYN")
	}

	if cache.tcp.ACK {
		info = addTCPFlag(info, "ACK")
	}

	if cache.tcp.RST {
		info = addTCPFlag(info, "RST")
	}

	if cache.tcp.FIN {
		info = addTCPFlag(info, "FIN")
	}

	return info
}

// ConnectionInfo contains tuple information and icmp code for a connection
type ConnectionInfo struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Proto    string
	IcmpCode string
	Tunnel   *ConnectionInfo
}

// getConnectionInfoFromCache assume dissectLock is obtained at the caller and data is already
// parsed to cache.decoded
func getConnectionInfoFromCache() (c *ConnectionInfo, hasIP, hasEth bool) {
	c = &ConnectionInfo{}
	for _, typ := range cache.decoded {
		switch typ {
		case layers.LayerTypeEthernet:
			hasEth = true
		case layers.LayerTypeIPv4:
			hasIP = true
			c.SrcIP, c.DstIP = cache.ip4.SrcIP, cache.ip4.DstIP
		case layers.LayerTypeIPv6:
			hasIP = true
			c.SrcIP, c.DstIP = cache.ip6.SrcIP, cache.ip6.DstIP
		case layers.LayerTypeTCP:
			c.Proto = "tcp"
			c.SrcPort, c.DstPort = uint16(cache.tcp.SrcPort), uint16(cache.tcp.DstPort)
		case layers.LayerTypeUDP:
			c.Proto = "udp"
			c.SrcPort, c.DstPort = uint16(cache.udp.SrcPort), uint16(cache.udp.DstPort)
		case layers.LayerTypeSCTP:
			c.Proto = "sctp"
			c.SrcPort, c.DstPort = uint16(cache.sctp.SrcPort), uint16(cache.sctp.DstPort)
		case layers.LayerTypeICMPv4:
			c.Proto = "icmp"
			c.IcmpCode = cache.icmp4.TypeCode.String()
		case layers.LayerTypeICMPv6:
			c.Proto = "icmp"
			c.IcmpCode = cache.icmp6.TypeCode.String()
		}
	}

	// Return in case we have not decoded any overlay layer.
	if len(cache.overlay.decoded) == 0 {
		return
	}

	// Expect VXLAN/Geneve encap as first overlay layer, if not we bail out.
	switch cache.overlay.decoded[0] {
	case layers.LayerTypeVXLAN:
		c.Proto = "vxlan"
	case layers.LayerTypeGeneve:
		c.Proto = "geneve"
	default:
		return
	}

	// Reset return values. This ensures the resulting flow does not misrepresent
	// what is happening (e.g. same IP addresses for overlay and underlay).
	hasEth, hasIP = false, false
	c = &ConnectionInfo{Tunnel: c}

	// Parse the rest of the overlay layers as we would do for a non-encapsulated packet.
	// It is possible we're not parsing any layer here. This is because the overlay
	// decoders failed (e.g., not enough data). We would still return empty values
	// for the inner packet (ethernet, ip, l4, basically the re-init variables)
	// while returning the non-empty `tunnel` field.
	for _, typ := range cache.overlay.decoded[1:] {
		switch typ {
		case layers.LayerTypeEthernet:
			hasEth = true
		case layers.LayerTypeIPv4:
			hasIP = true
			c.SrcIP, c.DstIP = cache.overlay.ip4.SrcIP, cache.overlay.ip4.DstIP
		case layers.LayerTypeIPv6:
			hasIP = true
			c.SrcIP, c.DstIP = cache.overlay.ip6.SrcIP, cache.overlay.ip6.DstIP
		case layers.LayerTypeTCP:
			c.Proto = "tcp"
			c.SrcPort, c.DstPort = uint16(cache.overlay.tcp.SrcPort), uint16(cache.overlay.tcp.DstPort)
		case layers.LayerTypeUDP:
			c.Proto = "udp"
			c.SrcPort, c.DstPort = uint16(cache.overlay.udp.SrcPort), uint16(cache.overlay.udp.DstPort)
		case layers.LayerTypeSCTP:
			c.Proto = "sctp"
			c.SrcPort, c.DstPort = uint16(cache.overlay.sctp.SrcPort), uint16(cache.overlay.sctp.DstPort)
		case layers.LayerTypeICMPv4:
			c.Proto = "icmp"
			c.IcmpCode = cache.overlay.icmp4.TypeCode.String()
		case layers.LayerTypeICMPv6:
			c.Proto = "icmp"
			c.IcmpCode = cache.overlay.icmp6.TypeCode.String()
		}
	}

	return
}

// GetConnectionSummary decodes the data into layers and returns a connection
// summary in the format:
//
// - sIP:sPort -> dIP:dPort, e.g. 1.1.1.1:2000 -> 2.2.2.2:80
// - sIP -> dIP icmpCode, 1.1.1.1 -> 2.2.2.2 echo-request
// - <inner> [tunnel sIP:sPort -> dIP:dPort type], e.g. 1.1.1.1:2000 -> 2.2.2.2:80 [tunnel 5.5.5.5:8472 -> 6.6.6.6:32767 vxlan]
func GetConnectionSummary(data []byte, opts *decodeOpts) string {
	dissectLock.Lock()
	defer dissectLock.Unlock()

	initParser()

	// Since v1.1.18, DecodeLayers returns a non-nil error for an empty packet, see
	// https://github.com/google/gopacket/issues/846
	// TODO: reconsider this check if the issue is fixed upstream
	if len(data) == 0 {
		// Truncate layers to avoid accidental re-use.
		cache.decoded = cache.decoded[:0]
		cache.overlay.decoded = cache.overlay.decoded[:0]
		return "[unknown]"
	}

	var err error
	// Identify correct decoder. For L3 packets (no ethernet), rely on opts.IsIPv6.
	switch {
	case opts == nil || !opts.IsL3Device:
		err = parserL2Dev.DecodeLayers(data, &cache.decoded)
	case opts.IsIPv6:
		err = parserL3Dev.IPv6.DecodeLayers(data, &cache.decoded)
	default:
		err = parserL3Dev.IPv4.DecodeLayers(data, &cache.decoded)
	}

	if err != nil {
		return "[error]"
	}

	// In case of overlay, identify correct decoder and proceed from the UDP payload.
	switch {
	case opts != nil && opts.IsVXLAN:
		err = parserOverlay.VXLAN.DecodeLayers(cache.udp.Payload, &cache.overlay.decoded)
	case opts != nil && opts.IsGeneve:
		err = parserOverlay.Geneve.DecodeLayers(cache.udp.Payload, &cache.overlay.decoded)
	default:
		// Truncate layers to avoid accidental re-use.
		cache.overlay.decoded = cache.overlay.decoded[:0]
	}

	if err != nil {
		return "[error]"
	}

	var str string
	c, hasIP, hasEth := getConnectionInfoFromCache()

	// Dump the outer packet.
	switch {
	case c.Proto == "icmp":
		str += fmt.Sprintf("%s -> %s %s %s", c.SrcIP, c.DstIP, c.Proto, c.IcmpCode)
	case c.Proto != "":
		str += fmt.Sprintf("%s -> %s %s",
			net.JoinHostPort(c.SrcIP.String(), strconv.Itoa(int(c.SrcPort))),
			net.JoinHostPort(c.DstIP.String(), strconv.Itoa(int(c.DstPort))),
			c.Proto)

		if c.Proto == "tcp" {
			str += " " + getTCPInfo()
		}
	case hasIP:
		str += fmt.Sprintf("%s -> %s", c.SrcIP, c.DstIP)
	case hasEth:
		str += fmt.Sprintf("%s -> %s %s", cache.eth.SrcMAC, cache.eth.DstMAC, cache.eth.EthernetType.String())
	default:
		str += "[unknown]"
	}

	// In case of an overlay packet, dump also the tunnel.
	if c.Tunnel != nil {
		str += fmt.Sprintf(" [tunnel %s -> %s %s]",
			net.JoinHostPort(c.Tunnel.SrcIP.String(), strconv.Itoa(int(c.Tunnel.SrcPort))),
			net.JoinHostPort(c.Tunnel.DstIP.String(), strconv.Itoa(int(c.Tunnel.DstPort))),
			c.Tunnel.Proto)
	}

	return str
}

// Dissect parses and prints the provided data if dissect is set to true,
// otherwise the data is printed as HEX output
func Dissect(dissect bool, data []byte) {
	if dissect {
		dissectLock.Lock()
		defer dissectLock.Unlock()

		initParser()

		var err error
		// See comment in [GetConnectionSummary].
		if len(data) > 0 {
			err = parserL2Dev.DecodeLayers(data, &cache.decoded)
		} else {
			cache.decoded = cache.decoded[:0]
		}

		for _, typ := range cache.decoded {
			switch typ {
			case layers.LayerTypeEthernet:
				fmt.Println(gopacket.LayerString(&cache.eth))
			case layers.LayerTypeIPv4:
				fmt.Println(gopacket.LayerString(&cache.ip4))
			case layers.LayerTypeIPv6:
				fmt.Println(gopacket.LayerString(&cache.ip6))
			case layers.LayerTypeTCP:
				fmt.Println(gopacket.LayerString(&cache.tcp))
			case layers.LayerTypeUDP:
				fmt.Println(gopacket.LayerString(&cache.udp))
			case layers.LayerTypeSCTP:
				fmt.Println(gopacket.LayerString(&cache.sctp))
			case layers.LayerTypeICMPv4:
				fmt.Println(gopacket.LayerString(&cache.icmp4))
			case layers.LayerTypeICMPv6:
				fmt.Println(gopacket.LayerString(&cache.icmp6))
			default:
				fmt.Println("Unknown layer")
			}
		}
		if parserL2Dev.Truncated {
			fmt.Println("  Packet has been truncated")
		}
		if err != nil {
			fmt.Println("  Failed to decode layer:", err)
		}

	} else {
		fmt.Print(hex.Dump(data))
	}
}

// Flow contains source and destination
type Flow struct {
	Src string `json:"src"`
	Dst string `json:"dst"`
}

// DissectSummary bundles decoded layers into json-marshallable message
type DissectSummary struct {
	Ethernet string `json:"ethernet,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	TCP      string `json:"tcp,omitempty"`
	UDP      string `json:"udp,omitempty"`
	SCTP     string `json:"sctp,omitempty"`
	ICMPv4   string `json:"icmpv4,omitempty"`
	ICMPv6   string `json:"icmpv6,omitempty"`
	L2       *Flow  `json:"l2,omitempty"`
	L3       *Flow  `json:"l3,omitempty"`
	L4       *Flow  `json:"l4,omitempty"`
}

// GetDissectSummary returns DissectSummary created from data
func GetDissectSummary(data []byte) *DissectSummary {
	dissectLock.Lock()
	defer dissectLock.Unlock()

	initParser()

	// See comment in [GetConnectionSummary].
	if len(data) > 0 {
		err := parserL2Dev.DecodeLayers(data, &cache.decoded)
		if err != nil {
			return nil
		}
	} else {
		cache.decoded = cache.decoded[:0]
	}

	ret := &DissectSummary{}

	for _, typ := range cache.decoded {
		switch typ {
		case layers.LayerTypeEthernet:
			ret.Ethernet = gopacket.LayerString(&cache.eth)
			src, dst := cache.eth.LinkFlow().Endpoints()
			ret.L2 = &Flow{Src: src.String(), Dst: dst.String()}
		case layers.LayerTypeIPv4:
			ret.IPv4 = gopacket.LayerString(&cache.ip4)
			src, dst := cache.ip4.NetworkFlow().Endpoints()
			ret.L3 = &Flow{Src: src.String(), Dst: dst.String()}
		case layers.LayerTypeIPv6:
			ret.IPv6 = gopacket.LayerString(&cache.ip6)
			src, dst := cache.ip6.NetworkFlow().Endpoints()
			ret.L3 = &Flow{Src: src.String(), Dst: dst.String()}
		case layers.LayerTypeTCP:
			ret.TCP = gopacket.LayerString(&cache.tcp)
			src, dst := cache.tcp.TransportFlow().Endpoints()
			ret.L4 = &Flow{Src: src.String(), Dst: dst.String()}
		case layers.LayerTypeUDP:
			ret.UDP = gopacket.LayerString(&cache.udp)
			src, dst := cache.udp.TransportFlow().Endpoints()
			ret.L4 = &Flow{Src: src.String(), Dst: dst.String()}
		case layers.LayerTypeSCTP:
			ret.SCTP = gopacket.LayerString(&cache.sctp)
			src, dst := cache.sctp.TransportFlow().Endpoints()
			ret.L4 = &Flow{Src: src.String(), Dst: dst.String()}
		case layers.LayerTypeICMPv4:
			ret.ICMPv4 = gopacket.LayerString(&cache.icmp4)
		case layers.LayerTypeICMPv6:
			ret.ICMPv6 = gopacket.LayerString(&cache.icmp6)
		}
	}
	return ret
}
