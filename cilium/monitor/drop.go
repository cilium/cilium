package monitor

import (
	"fmt"
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

func (n *DropNotify) Dump(dissect bool, data []byte) {
	fmt.Printf("Packet dropped %d->%d to container %d %d bytes (ifindex %d)\n",
		n.SrcLabel, n.DstLabel, n.DstID, n.Len, n.Ifindex)

	Dissect(dissect, data[24:])
}
