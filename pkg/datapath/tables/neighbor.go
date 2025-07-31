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

func NewNeighborTable(db *statedb.DB) (statedb.RWTable[*Neighbor], error) {
	return statedb.NewTable(
		db,
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
		n.Type.String(),
		n.State.String(),
		n.Flags.String(),
		n.FlagsExt.String(),
	}
}

type NeighborType uint8 // neighbor type (NDA_*)

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

	NDA_MAX
)

var ndaStrings = [...]string{
	"UNSPEC",
	"DST",
	"LLADDR",
	"CACHEINFO",
	"PROBES",
	"VLAN",
	"PORT",
	"VNI",
	"IFINDEX",
	"MASTER",
	"LINK_NETNSID",
	"SRC_VNI",
	"PROTOCOL",
	"NH_ID",
	"FDB_EXT_ATTRS",
	"FLAGS_EXT",
}

func (t NeighborType) String() string {
	if t >= NDA_MAX {
		return fmt.Sprintf("NDA_UNKNOWN(%d)", t)
	}

	return ndaStrings[t]
}

type NeighborState uint16 // bit mask of neighbor states (NUD_*)

const (
	NUD_NONE       NeighborState = 0x00
	NUD_INCOMPLETE               = 1 << (iota - 1)
	NUD_REACHABLE
	NUD_STALE
	NUD_DELAY
	NUD_PROBE
	NUD_FAILED
	NUD_NOARP
	NUD_PERMANENT
)

var nudStrings = [...]string{
	"INCOMPLETE",
	"REACHABLE",
	"STALE",
	"DELAY",
	"PROBE",
	"FAILED",
	"NOARP",
	"PERMANENT",
}

func (s NeighborState) String() string {
	if s == 0 {
		return "NONE"
	}

	var out string
	for i := range 16 {
		if s&(1<<i) != 0 {
			if out != "" {
				out += "|"
			}

			if i < len(nudStrings) {
				out += nudStrings[i]
			} else {
				out += fmt.Sprintf("NUD_UNKNOWN(%d)", i)
			}
		}
	}

	return out
}

type NeighborFlags uint8 // bit mask of neighbor flags (NTF_*)

const (
	NTF_USE NeighborFlags = 1 << iota
	NTF_SELF
	NTF_MASTER
	NTF_PROXY
	NTF_EXT_LEARNED
	NTF_OFFLOADED
	NTF_STICKY
	NTF_ROUTER
)

var ntfStrings = [...]string{
	"USE",
	"SELF",
	"MASTER",
	"PROXY",
	"EXT_LEARNED",
	"OFFLOADED",
	"STICKY",
	"ROUTER",
}

func (f NeighborFlags) String() string {
	if f == 0 {
		return "NONE"
	}

	var out string
	for i := range 8 {
		if f&(1<<i) != 0 {
			if out != "" {
				out += "|"
			}

			if i < len(ntfStrings) {
				out += ntfStrings[i]
			} else {
				out += fmt.Sprintf("NTF_UNKNOWN(%d)", i)
			}
		}
	}

	return out
}

type NeighborFlagsExt uint32 // bit mask of extended neighbor flags (NTF_EXT_*)

const (
	NTF_EXT_MANAGED NeighborFlagsExt = 1 << iota
)

var ntfExtStrings = [...]string{
	"EXT_MANAGED",
}

func (f NeighborFlagsExt) String() string {
	if f == 0 {
		return "NONE"
	}

	var out string
	for i := range 32 {
		if f&(1<<i) != 0 {
			if out != "" {
				out += "|"
			}

			if i < len(ntfExtStrings) {
				out += ntfExtStrings[i]
			} else {
				out += fmt.Sprintf("NTF_EXT_UNKNOWN(%d)", i)
			}
		}
	}

	return out
}
