// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"unsafe"

	. "github.com/cilium/checkmate"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Hook up gocheck into the "go test" runner.
type CTMapPrivilegedTestSuite struct{}

var _ = Suite(&CTMapPrivilegedTestSuite{})

func init() {
	InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
}

func (k *CTMapPrivilegedTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *CTMapPrivilegedTestSuite) Benchmark_MapUpdate(c *C) {
	m := newMap(MapNameTCP4Global+"_test", mapTypeIPv4TCPGlobal)
	err := m.OpenOrCreate()
	defer m.Map.Unpin()
	c.Assert(err, IsNil)

	key := &CtKey4{
		tuple.TupleKey4{
			DestAddr:   types.IPv4{0xa, 0x10, 0xc5, 0xf0},
			SourceAddr: types.IPv4{0xa, 0x10, 0x9d, 0xb3},
			DestPort:   0,
			SourcePort: 0,
			NextHeader: u8proto.TCP,
			Flags:      0,
		},
	}
	value := &CtEntry{
		RxPackets:        4,
		RxBytes:          216,
		TxPackets:        4,
		TxBytes:          216,
		Lifetime:         37459,
		Flags:            0x0011,
		RevNAT:           0,
		TxFlagsSeen:      0x02,
		RxFlagsSeen:      0x14,
		SourceSecurityID: 40653,
		LastTxReport:     15856,
		LastRxReport:     15856,
	}

	c.Assert(c.N < 0xFFFF*0xFFFF, Equals, true)
	for i := 0; i < c.N; i++ {
		key.DestPort = uint16(i % 0xFFFF)
		key.SourcePort = uint16(i / 0xFFFF)
		err := m.Map.Update(key, value)
		c.Assert(err, IsNil)
	}

	a1 := make([]CtKey, 1)
	a2 := make([]*CtEntry, 1)

	// Also account the cost of casting from MapKey to TupleKey
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(CtKey)
		value := v.(*CtEntry)
		a1[0] = key
		a2[0] = value
	}

	c.ResetTimer()
	err = m.DumpWithCallback(cb)
	c.Assert(err, IsNil)
	t := m.Flush()
	c.Assert(t, Equals, c.N)
}

// TestCtGcIcmp tests whether ICMP NAT entries are removed upon a removal of
// their CT entry (GH#12625).
func (k *CTMapPrivilegedTestSuite) TestCtGcIcmp(c *C) {
	// Init maps
	natMap := nat.NewMap("cilium_nat_any4_test", true, 1000)
	err := natMap.OpenOrCreate()
	c.Assert(err, IsNil)
	defer natMap.Map.Unpin()

	ctMapName := MapNameAny4Global + "_test"
	setupMapInfo(mapTypeIPv4AnyGlobal, ctMapName,
		&CtKey4Global{}, int(unsafe.Sizeof(CtKey4Global{})),
		100, natMap)

	ctMap := newMap(ctMapName, mapTypeIPv4AnyGlobal)
	err = ctMap.OpenOrCreate()
	c.Assert(err, IsNil)
	defer ctMap.Map.Unpin()

	// Create the following entries and check that they get GC-ed:
	//	- CT:	ICMP OUT 192.168.61.11:38193 -> 192.168.61.12:0 <..>
	//	- NAT:	ICMP IN 192.168.61.12:0 -> 192.168.61.11:38193 XLATE_DST <..>
	//	 		ICMP OUT 192.168.61.11:38193 -> 192.168.61.12:0 XLATE_SRC <..>

	ctKey := &CtKey4Global{
		tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0x3195,
				DestPort:   0,
				NextHeader: u8proto.ICMP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctVal := &CtEntry{
		TxPackets: 1,
		TxBytes:   216,
		Lifetime:  37459,
	}
	err = ctMap.Map.Update(ctKey, ctVal)
	c.Assert(err, IsNil)

	natKey := &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{192, 168, 61, 12},
				SourceAddr: types.IPv4{192, 168, 61, 11},
				DestPort:   0,
				SourcePort: 0x3195,
				NextHeader: u8proto.ICMP,
				Flags:      0,
			},
		},
	}
	natVal := &nat.NatEntry4{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv4{192, 168, 61, 11},
		Port:    0x3195,
	}
	err = natMap.Map.Update(natKey, natVal)
	c.Assert(err, IsNil)
	natKey = &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0,
				DestPort:   0x3195,
				NextHeader: u8proto.ICMP,
				Flags:      1,
			},
		},
	}
	natVal = &nat.NatEntry4{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv4{192, 168, 61, 11},
		Port:    0x3195,
	}
	err = natMap.Map.Update(natKey, natVal)
	c.Assert(err, IsNil)

	buf := make(map[string][]string)
	err = ctMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 1)

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 2)

	// GC and check whether NAT entries have been collected
	filter := &GCFilter{
		RemoveExpired: true,
		Time:          39000,
	}
	stats := doGC4(ctMap, filter)
	c.Assert(stats.aliveEntries, Equals, uint32(0))
	c.Assert(stats.deleted, Equals, uint32(1))

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 0)
}

// TestOrphanNat checks whether dangling NAT entries are GC'd (GH#12686)
func (k *CTMapPrivilegedTestSuite) TestOrphanNatGC(c *C) {
	// Init maps
	natMap := nat.NewMap("cilium_nat_any4_test", true, 1000)
	err := natMap.OpenOrCreate()
	c.Assert(err, IsNil)
	defer natMap.Map.Unpin()

	ctMapAnyName := MapNameAny4Global + "_test"
	setupMapInfo(mapTypeIPv4AnyGlobal, ctMapAnyName,
		&CtKey4Global{}, int(unsafe.Sizeof(CtKey4Global{})),
		100, natMap)
	ctMapAny := newMap(ctMapAnyName, mapTypeIPv4AnyGlobal)
	err = ctMapAny.OpenOrCreate()
	c.Assert(err, IsNil)
	defer ctMapAny.Map.Unpin()

	ctMapTCPName := MapNameTCP4Global + "_test"
	setupMapInfo(mapTypeIPv4TCPGlobal, ctMapTCPName,
		&CtKey4Global{}, int(unsafe.Sizeof(CtKey4Global{})),
		100, natMap)
	ctMapTCP := newMap(ctMapTCPName, mapTypeIPv4TCPGlobal)
	err = ctMapTCP.OpenOrCreate()
	c.Assert(err, IsNil)
	defer ctMapTCP.Map.Unpin()

	// Create the following entries and check that SNAT entries are NOT GC-ed
	// (as we have the CT entry which they belong to):
	//
	// - Host local traffic (no SNAT):
	//		CT:		UDP OUT 10.23.32.45:54864 -> 10.23.53.48:8472
	//		NAT:	UDP IN  10.23.53.48:8472 -> 10.23.32.45:54865 XLATE_DST 10.23.32.45:54864
	//	 			UDP OUT 10.23.32.45:54864 -> 10.23.53.48:8472 XLATE_SRC 10.23.32.45:54865
	//
	// The example above covers other SNAT cases. E.g. (not used in unit tests below, just
	// to show for completion):
	//
	// - NodePort request from outside (subject to NodePort SNAT):
	// 		CT: 	TCP OUT 192.168.61.1:63000 -> 10.0.1.99:80
	// 		NAT: 	TCP IN 10.0.1.99:80 -> 10.0.0.134:63000 XLATE_DST 192.168.61.1:63000
	// 		NAT: 	TCP OUT 192.168.61.1:63000 -> 10.0.1.99:80 XLATE_SRC 10.0.0.134:63000
	//
	// - Local endpoint request to outside (subject to BPF-masq):
	//		CT: 	TCP OUT 10.0.1.99:34520 -> 1.1.1.1:80
	//		NAT: 	TCP IN 1.1.1.1:80 -> 10.0.2.15:34520 XLATE_DST 10.0.1.99:34520
	//				TCP OUT 10.0.1.99:34520 -> 1.1.1.1:80 XLATE_SRC 10.0.2.15:34520

	ctKey := &CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{10, 23, 32, 45},
				SourceAddr: types.IPv4{10, 23, 53, 48},
				SourcePort: 0x50d6,
				DestPort:   0x1821,
				NextHeader: u8proto.UDP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctVal := &CtEntry{
		TxPackets: 1,
		TxBytes:   216,
		Lifetime:  37459,
	}
	err = ctMapAny.Map.Update(ctKey, ctVal)
	c.Assert(err, IsNil)

	natKey := &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{10, 23, 32, 45},
				DestAddr:   types.IPv4{10, 23, 53, 48},
				SourcePort: 0x50d6,
				DestPort:   0x1821,
				NextHeader: u8proto.UDP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	natVal := &nat.NatEntry4{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv4{10, 23, 32, 45},
		Port:    0x51d6,
	}
	err = natMap.Map.Update(natKey, natVal)
	c.Assert(err, IsNil)
	natKey = &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{10, 23, 32, 45},
				SourceAddr: types.IPv4{10, 23, 53, 48},
				DestPort:   0x51d6,
				SourcePort: 0x1821,
				NextHeader: u8proto.UDP,
				Flags:      tuple.TUPLE_F_IN,
			},
		},
	}
	natVal = &nat.NatEntry4{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv4{10, 23, 32, 45},
		Port:    0x50d6,
	}
	err = natMap.Map.Update(natKey, natVal)
	c.Assert(err, IsNil)

	stats := PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
	c.Assert(stats.IngressAlive, Equals, uint32(1))
	c.Assert(stats.IngressDeleted, Equals, uint32(0))
	c.Assert(stats.EgressAlive, Equals, uint32(1))
	c.Assert(stats.EgressDeleted, Equals, uint32(0))
	// Check that both entries haven't removed
	buf := make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 2)

	// Now remove the CT entry which should remove both NAT entries
	err = ctMapAny.Map.Delete(ctKey)
	c.Assert(err, IsNil)
	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
	c.Assert(stats.IngressDeleted, Equals, uint32(1))
	c.Assert(stats.IngressAlive, Equals, uint32(0))
	c.Assert(stats.EgressDeleted, Equals, uint32(1))
	c.Assert(stats.EgressAlive, Equals, uint32(0))
	// Check that both orphan NAT entries have been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 0)

	// Create only CT_INGRESS NAT entry which should be removed
	err = natMap.Map.Update(natKey, natVal)
	c.Assert(err, IsNil)

	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
	c.Assert(stats.IngressDeleted, Equals, uint32(1))
	c.Assert(stats.EgressDeleted, Equals, uint32(0))
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 0)

	// Test DSR (old, tracked by bpf_lxc)
	//
	// Create the following entries and check that SNAT entries are NOT GC-ed
	// (as we have the CT entry which they belong to):
	//
	//     CT:	TCP IN  10.0.2.10:50000  -> 10.20.30.40:1234
	//     NAT:	TCP OUT 10.20.30.40:1234 -> 10.0.2.10:50000 XLATE_SRC 10.0.2.20:40000

	ctKey = &CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{10, 0, 2, 10},
				SourceAddr: types.IPv4{10, 20, 30, 40},
				SourcePort: 0x50c3,
				DestPort:   0xd204,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_IN,
			},
		},
	}
	ctVal = &CtEntry{
		TxPackets: 1,
		TxBytes:   216,
		Lifetime:  37459,
	}
	err = ctMapTCP.Map.Update(ctKey, ctVal)
	c.Assert(err, IsNil)

	natKey = &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{10, 20, 30, 40},
				DestAddr:   types.IPv4{10, 0, 2, 10},
				SourcePort: 0xd204,
				DestPort:   0x50c3,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	natVal = &nat.NatEntry4{
		Created: 37400,
		Addr:    types.IPv4{10, 0, 2, 20},
		Port:    0x409c,
	}
	err = natMap.Map.Update(natKey, natVal)
	c.Assert(err, IsNil)

	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapTCP)
	c.Assert(stats.IngressAlive, Equals, uint32(0))
	c.Assert(stats.IngressDeleted, Equals, uint32(0))
	c.Assert(stats.EgressAlive, Equals, uint32(1))
	c.Assert(stats.EgressDeleted, Equals, uint32(0))
	// Check that the entry hasn't been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 1)

	// Now remove the CT entry which should remove the NAT entry
	err = ctMapTCP.Map.Delete(ctKey)
	c.Assert(err, IsNil)
	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapTCP)
	c.Assert(stats.IngressAlive, Equals, uint32(0))
	c.Assert(stats.IngressDeleted, Equals, uint32(0))
	c.Assert(stats.EgressAlive, Equals, uint32(0))
	c.Assert(stats.EgressDeleted, Equals, uint32(1))
	// Check that the orphan NAT entry has been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 0)

	// Test DSR (new, tracked by nodeport.h)
	//
	// Create the following entries and check that SNAT entries are NOT GC-ed
	// (as we have the CT entry which they belong to):
	//
	//     CT:	TCP OUT  10.0.2.10:50000  -> 10.20.30.40:1234
	//     NAT:	TCP OUT 10.20.30.40:1234 -> 10.0.2.10:50000 XLATE_SRC 10.0.2.20:40000

	ctKey = &CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{10, 0, 2, 10},
				SourceAddr: types.IPv4{10, 20, 30, 40},
				SourcePort: 0x50c3,
				DestPort:   0xd204,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctVal = &CtEntry{
		TxPackets: 1,
		TxBytes:   216,
		Lifetime:  37459,
	}
	err = ctMapTCP.Map.Update(ctKey, ctVal)
	c.Assert(err, IsNil)

	natKey = &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{10, 20, 30, 40},
				DestAddr:   types.IPv4{10, 0, 2, 10},
				SourcePort: 0xd204,
				DestPort:   0x50c3,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	natVal = &nat.NatEntry4{
		Created: 37400,
		Addr:    types.IPv4{10, 0, 2, 20},
		Port:    0x409c,
	}
	err = natMap.Map.Update(natKey, natVal)
	c.Assert(err, IsNil)

	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapTCP)
	c.Assert(stats.IngressAlive, Equals, uint32(0))
	c.Assert(stats.IngressDeleted, Equals, uint32(0))
	c.Assert(stats.EgressAlive, Equals, uint32(1))
	c.Assert(stats.EgressDeleted, Equals, uint32(0))
	// Check that the entry hasn't been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 1)

	// Now remove the CT entry which should remove the NAT entry
	err = ctMapTCP.Map.Delete(ctKey)
	c.Assert(err, IsNil)
	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapTCP)
	c.Assert(stats.IngressAlive, Equals, uint32(0))
	c.Assert(stats.IngressDeleted, Equals, uint32(0))
	c.Assert(stats.EgressAlive, Equals, uint32(0))
	c.Assert(stats.EgressDeleted, Equals, uint32(1))
	// Check that the orphan NAT entry has been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 0)

	// Let's check IPv6

	natMapV6 := nat.NewMap("cilium_nat_any6_test", false, 1000)
	err = natMapV6.OpenOrCreate()
	c.Assert(err, IsNil)
	defer natMapV6.Map.Unpin()

	ctMapAnyName = MapNameAny6Global + "_test"
	setupMapInfo(mapTypeIPv6AnyGlobal, ctMapAnyName,
		&CtKey6Global{}, int(unsafe.Sizeof(CtKey6Global{})),
		100, natMapV6)
	ctMapAnyV6 := newMap(ctMapAnyName, mapTypeIPv6AnyGlobal)
	err = ctMapAnyV6.OpenOrCreate()
	c.Assert(err, IsNil)
	defer ctMapAnyV6.Map.Unpin()

	ctMapTCPName = MapNameTCP6Global + "_test"
	setupMapInfo(mapTypeIPv6TCPGlobal, ctMapTCPName,
		&CtKey6Global{}, int(unsafe.Sizeof(CtKey6Global{})),
		100, natMapV6)
	ctMapTCPV6 := newMap(ctMapTCPName, mapTypeIPv6TCPGlobal)
	err = ctMapTCP.OpenOrCreate()
	c.Assert(err, IsNil)
	defer ctMapTCPV6.Map.Unpin()

	natKeyV6 := &nat.NatKey6{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				SourceAddr: types.IPv6{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				DestAddr:   types.IPv6{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				SourcePort: 0x50d6,
				DestPort:   0x1821,
				NextHeader: u8proto.UDP,
				Flags:      tuple.TUPLE_F_IN,
			},
		},
	}
	natValV6 := &nat.NatEntry6{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv6{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		Port:    0x51d6,
	}
	err = natMapV6.Map.Update(natKeyV6, natValV6)
	c.Assert(err, IsNil)

	stats = PurgeOrphanNATEntries(ctMapTCPV6, ctMapAnyV6)
	c.Assert(stats.IngressDeleted, Equals, uint32(1))
	c.Assert(stats.EgressDeleted, Equals, uint32(0))
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	c.Assert(err, IsNil)
	c.Assert(len(buf), Equals, 0)
}
