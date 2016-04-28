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

func (n *DropNotify) String(dissect bool, data []byte) string {
	var s string

	if dissect {
		p := gopacket.NewPacket(data[24:], layers.LayerTypeEthernet, gopacket.NoCopy)
		s = p.Dump()
	} else {
		s = hex.Dump(data[24:])
	}

	return fmt.Sprintf("Packet dropped %d->%d to container %d %d bytes (ifindex %d)\n%s",
		n.SrcLabel, n.DstLabel, n.DstID, n.Len, n.Ifindex, s)
}
