package monitor

import (
	"encoding/hex"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DropNotify struct {
	Type     uint8
	SubType  uint8
	Flags    uint16
	Len      uint32
	SrcLabel uint32
	DstLabel uint32
	DstID    uint32
	Ifindex  uint32
	// data
}

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
)

func (n *DropNotify) Dump(dissect bool, data []byte) {
	fmt.Printf("Packet dropped %d->%d to container %d %d bytes (ifindex %d)\n",
		n.SrcLabel, n.DstLabel, n.DstID, n.Len, n.Ifindex)

	if dissect {
		//		s = gopacket.NewPacket(data[24:], layers.LayerTypeEthernet, gopacket.Lazy).Dump()
		parser.DecodeLayers(data[24:], &decoded)

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
			}
		}
		if parser.Truncated {
			fmt.Println("  Packet has been truncated")
		}

	} else {
		fmt.Println(hex.Dump(data[24:]))
	}

}
