package monitor

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	lock    sync.Mutex
)

func Dissect(dissect bool, data []byte) {
	lock.Lock()
	if dissect {
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
		fmt.Println(hex.Dump(data))
	}
	lock.Unlock()
}
