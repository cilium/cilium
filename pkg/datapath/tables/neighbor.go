// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

const (
	neighborIndexSize = 4 /* LinkIndex */ + 16 /* IP */ + 1 /* IP bit length */
)

var (
	NeighborIDIndex = statedb.Index[*Neighbor, NeighborID]{
		Name: "ID",
		FromObject: func(n *Neighbor) index.KeySet {
			return index.NewKeySet(
				NeighborID{
					LinkIndex: n.LinkIndex,
					IPAddr:    n.IPAddr,
				}.Key(),
			)
		},
		FromKey: NeighborID.Key,
		FromString: func(key string) (index.Key, error) {
			var (
				linkIndex uint32
				ipAddr    string
			)
			n, _ := fmt.Sscanf(key, "%d:%s", &linkIndex, &ipAddr)
			if n == 0 {
				return index.Key{}, fmt.Errorf("bad key, expected \"<link>:<ip>\"")
			}
			out := make([]byte, 0, neighborIndexSize)
			if n > 0 {
				out = binary.BigEndian.AppendUint32(out, linkIndex)
				n--
			}
			if n > 0 {
				addr, err := netip.ParseAddr(ipAddr)
				if err != nil {
					return index.Key{}, err
				}
				addrBytes := addr.As16()
				out = append(out, addrBytes[:]...)
				out = append(out, byte(addr.BitLen()))
			}
			return out, nil
		},
		Unique: true,
	}

	NeighborLinkIndex = statedb.Index[*Neighbor, int]{
		Name: "LinkIndex",
		FromObject: func(n *Neighbor) index.KeySet {
			return index.NewKeySet(index.Int(n.LinkIndex))
		},
		FromKey:    index.Int,
		FromString: index.IntString,
	}

	NeighborIPAddrIndex = statedb.Index[*Neighbor, netip.Addr]{
		Name: "IPAddr",
		FromObject: func(n *Neighbor) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(n.IPAddr))
		},
		FromKey:    index.NetIPAddr,
		FromString: index.NetIPAddrString,
	}
)

func NewNeighborTable() (statedb.RWTable[*Neighbor], error) {
	return statedb.NewTable(
		"neighbors",
		NeighborIDIndex,
		NeighborLinkIndex,
		NeighborIPAddrIndex,
	)
}

type NeighborID struct {
	LinkIndex int
	IPAddr    netip.Addr
}

func (id NeighborID) Key() index.Key {
	key := make([]byte, 0, neighborIndexSize)
	key = binary.BigEndian.AppendUint32(key, uint32(id.LinkIndex))
	addrBytes := id.IPAddr.As16()
	key = append(key, addrBytes[:]...)
	key = append(key, byte(id.IPAddr.BitLen()))
	return key
}

type Neighbor struct {
	LinkIndex    int
	IPAddr       netip.Addr
	HardwareAddr HardwareAddr
	Type         NeighborType
	State        NeighborState
	Flags        NeighborFlags
	FlagsExt     NeighborFlagsExt
}

func (n *Neighbor) DeepCopy() *Neighbor {
	n2 := *n
	return &n2
}

func (n *Neighbor) String() string {
	return fmt.Sprintf("Neighbor{LinkIndex: %d, IPAddr: %s, HardwareAddr: %s, Type: %d, State: %d}",
		n.LinkIndex, n.IPAddr, n.HardwareAddr, n.Type, n.State)
}

func (*Neighbor) TableHeader() []string {
	return []string{
		"LinkIndex",
		"IPAddr",
		"HardwareAddr",
		"Type",
		"State",
		"Flags",
		"FlagsExt",
	}
}

func (n *Neighbor) TableRow() []string {
	return []string{
		fmt.Sprintf("%d", n.LinkIndex),
		n.IPAddr.String(),
		n.HardwareAddr.String(),
		fmt.Sprintf("%d", n.Type),
		fmt.Sprintf("%#x", n.State),
		fmt.Sprintf("%#x", n.Flags),
		fmt.Sprintf("%#x", n.FlagsExt),
	}
}

type (
	NeighborType     uint8  // neighbor type (NDA_*)
	NeighborState    uint16 // bit mask of neighbor states (NUD_*)
	NeighborFlags    uint8  // bit mask of neighbor flags (NTF_*)
	NeighborFlagsExt uint32 // bit mask of extended neighbor flags (NTF_EXT_*)
)

// Definitions for neighbor type, state and flags. These are repeated here
// from the unix package to keep the tables package buildable on non-Linux platforms.
const (
	NDA_UNSPEC NeighborType = iota
	NDA_DST
	NDA_LLADDR
	NDA_CACHEINFO
	NDA_PROBES
	NDA_VLAN
	NDA_PORT
	NDA_VNI
	NDA_IFINDEX
	NDA_MASTER
	NDA_LINK_NETNSID
	NDA_SRC_VNI
	NDA_PROTOCOL
	NDA_NH_ID
	NDA_FDB_EXT_ATTRS
	NDA_FLAGS_EXT

	NUD_NONE       = NeighborState(0x00)
	NUD_INCOMPLETE = NeighborState(0x01)
	NUD_REACHABLE  = NeighborState(0x02)
	NUD_STALE      = NeighborState(0x04)
	NUD_DELAY      = NeighborState(0x08)
	NUD_PROBE      = NeighborState(0x10)
	NUD_FAILED     = NeighborState(0x20)
	NUD_NOARP      = NeighborState(0x40)
	NUD_PERMANENT  = NeighborState(0x80)

	NTF_USE         = NeighborFlags(0x01)
	NTF_SELF        = NeighborFlags(0x02)
	NTF_MASTER      = NeighborFlags(0x04)
	NTF_PROXY       = NeighborFlags(0x08)
	NTF_EXT_LEARNED = NeighborFlags(0x10)
	NTF_OFFLOADED   = NeighborFlags(0x20)
	NTF_STICKY      = NeighborFlags(0x40)
	NTF_ROUTER      = NeighborFlags(0x80)

	NTF_EXT_MANAGED = NeighborFlagsExt(0x00000001)
)
