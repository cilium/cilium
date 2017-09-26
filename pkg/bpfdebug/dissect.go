// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpfdebug

import (
	"encoding/hex"
	"fmt"
	"net"

	lockAPI "github.com/cilium/cilium/pkg/lock"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
)

var (
	eth    layers.Ethernet
	ip4    layers.IPv4
	ip6    layers.IPv6
	icmp4  layers.ICMPv4
	icmp6  layers.ICMPv6
	tcp    layers.TCP
	udp    layers.UDP
	parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &ip4, &ip6, &icmp4, &icmp6, &tcp, &udp)
	decoded = []gopacket.LayerType{}
	lock    lockAPI.Mutex
)

func getTCPInfo() string {
	info := ""
	addTCPFlag := func(flag, new string) string {
		if flag == "" {
			return new
		}
		return flag + ", " + new
	}

	if tcp.SYN {
		info = addTCPFlag(info, "SYN")
	}

	if tcp.ACK {
		info = addTCPFlag(info, "ACK")
	}

	if tcp.RST {
		info = addTCPFlag(info, "RST")
	}

	if tcp.FIN {
		info = addTCPFlag(info, "FIN")
	}

	return info
}

// GetConnectionSummary decodes the data into layers and returns a connection
// summary in the format:
//
// - sIP:sPort -> dIP:dPort, e.g. 1.1.1.1:2000 -> 2.2.2.2:80
// - sIP -> dIP icmpCode, 1.1.1.1 -> 2.2.2.2 echo-request
func GetConnectionSummary(data []byte) string {
	lock.Lock()
	defer lock.Unlock()

	parser.DecodeLayers(data, &decoded)

	var (
		srcIP, dstIP     net.IP
		srcPort, dstPort string
		icmpCode, proto  string
		hasIP, hasEth    bool
	)

	for _, typ := range decoded {
		switch typ {
		case layers.LayerTypeEthernet:
			hasEth = true
		case layers.LayerTypeIPv4:
			hasIP = true
			srcIP, dstIP = ip4.SrcIP, ip4.DstIP
		case layers.LayerTypeIPv6:
			hasIP = true
			srcIP, dstIP = ip6.SrcIP, ip6.DstIP
		case layers.LayerTypeTCP:
			proto = "tcp"
			srcPort, dstPort = strconv.Itoa(int(tcp.SrcPort)), strconv.Itoa(int(tcp.DstPort))
		case layers.LayerTypeUDP:
			proto = "udp"
			srcPort, dstPort = strconv.Itoa(int(udp.SrcPort)), strconv.Itoa(int(udp.DstPort))
		case layers.LayerTypeICMPv4:
			icmpCode = icmp4.TypeCode.String()
		case layers.LayerTypeICMPv6:
			icmpCode = icmp6.TypeCode.String()
		}
	}

	switch {
	case icmpCode != "":
		return fmt.Sprintf("%s -> %s %s", srcIP, dstIP, icmpCode)
	case proto != "":
		s := fmt.Sprintf("%s -> %s %s",
			net.JoinHostPort(srcIP.String(), srcPort),
			net.JoinHostPort(dstIP.String(), dstPort),
			proto)
		if proto == "tcp" {
			s += " " + getTCPInfo()
		}
		return s
	case hasIP:
		return fmt.Sprintf("%s -> %s", srcIP, dstIP)
	case hasEth:
		return fmt.Sprintf("%s -> %s %s", eth.SrcMAC, eth.DstMAC, eth.EthernetType.String())
	}

	return "[unknown]"
}

// Dissect parses and prints the provided data if dissect is set to true,
// otherwise the data is printed as HEX output
func Dissect(dissect bool, data []byte) {
	if dissect {
		lock.Lock()
		defer lock.Unlock()

		parser.DecodeLayers(data, &decoded)

		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeEthernet:
				fmt.Println(gopacket.LayerString(&eth))
			case layers.LayerTypeIPv4:
				fmt.Println(gopacket.LayerString(&ip4))
			case layers.LayerTypeIPv6:
				fmt.Println(gopacket.LayerString(&ip6))
			case layers.LayerTypeTCP:
				fmt.Println(gopacket.LayerString(&tcp))
			case layers.LayerTypeUDP:
				fmt.Println(gopacket.LayerString(&udp))
			case layers.LayerTypeICMPv4:
				fmt.Println(gopacket.LayerString(&icmp4))
			case layers.LayerTypeICMPv6:
				fmt.Println(gopacket.LayerString(&icmp6))
			default:
				fmt.Println("Unknown layer")
			}
		}
		if parser.Truncated {
			fmt.Println("  Packet has been truncated")
		}

	} else {
		fmt.Print(hex.Dump(data))
	}
}
