// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func init() {
	InitMapInfo(true, true, true)
}

func setupCTMap(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	require.Nil(tb, err)
}

func BenchmarkMapBatchLookup(b *testing.B) {
	m := newMap(MapNameTCP4Global+"_test", mapTypeIPv4TCPGlobal)
	err := m.OpenOrCreate()
	assert.NoError(b, m.Map.Unpin())
	assert.NoError(b, err)

	_ = populateFakeDataCTMap4(b, m, option.CTMapEntriesGlobalTCPDefault)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count, err := m.Count()
		assert.NoError(b, err)
		assert.Greater(b, count, option.CTMapEntriesGlobalAnyDefault)
	}
}

func Benchmark_MapUpdate(b *testing.B) {
	setupCTMap(b)

	m := newMap(MapNameTCP4Global+"_test", mapTypeIPv4TCPGlobal)
	err := m.OpenOrCreate()
	defer m.Map.Unpin()
	require.Nil(b, err)

	key := &CtKey4{
		tuple.TupleKey4{
			DestAddr:   types.IPv4{0xa, 0x10, 0xc5, 0xf0},
			SourceAddr: types.IPv4{0xa, 0x10, 0x9d, 0xb3},
			DestPort:   0,
			SourcePort: 0,
			NextHeader: u8proto.TCP,
			Flags:      tuple.TUPLE_F_OUT,
		},
	}
	value := &CtEntry{
		Packets:          4 + 4,
		Bytes:            216 + 216,
		Lifetime:         37459,
		Flags:            SeenNonSyn | RxClosing,
		RevNAT:           0,
		TxFlagsSeen:      0x02,
		RxFlagsSeen:      0x14,
		SourceSecurityID: 40653,
		LastTxReport:     15856,
		LastRxReport:     15856,
	}

	require.Equal(b, true, b.N < 0xFFFF*0xFFFF)
	for i := 0; i < b.N; i++ {
		key.DestPort = uint16(i % 0xFFFF)
		key.SourcePort = uint16(i / 0xFFFF)
		err := m.Map.Update(key, value)
		require.Nil(b, err)
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

	b.ResetTimer()
	err = m.DumpWithCallback(cb)
	require.Nil(b, err)
	t := m.Flush()
	require.Equal(b, b.N, t)
}

// TestCtGcIcmp tests whether ICMP NAT entries are removed upon a removal of
// their CT entry (GH#12625).
func TestCtGcIcmp(t *testing.T) {
	setupCTMap(t)

	// Init maps
	natMap := nat.NewMap("cilium_nat_any4_test", nat.IPv4, 1000)
	err := natMap.OpenOrCreate()
	require.Nil(t, err)
	defer natMap.Map.Unpin()

	ctMapName := MapNameAny4Global + "_test"
	mapInfo[mapTypeIPv4AnyGlobal] = mapAttributes{
		natMap: natMap, natMapLock: mapInfo[mapTypeIPv4AnyGlobal].natMapLock,
	}

	ctMap := newMap(ctMapName, mapTypeIPv4AnyGlobal)
	err = ctMap.OpenOrCreate()
	require.Nil(t, err)
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
		Packets:  1,
		Bytes:    216,
		Lifetime: 37459,
	}
	err = ctMap.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

	natKey := &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{192, 168, 61, 12},
				SourceAddr: types.IPv4{192, 168, 61, 11},
				DestPort:   0,
				SourcePort: 0x3195,
				NextHeader: u8proto.ICMP,
				Flags:      tuple.TUPLE_F_OUT,
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
	require.Nil(t, err)
	natKey = &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0,
				DestPort:   0x3195,
				NextHeader: u8proto.ICMP,
				Flags:      tuple.TUPLE_F_IN,
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
	require.Nil(t, err)

	buf := make(map[string][]string)
	err = ctMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 2, len(buf))

	// GC and check whether NAT entries have been collected
	filter := GCFilter{
		RemoveExpired: true,
		Time:          39000,
	}
	stats := doGC4(ctMap, filter)
	require.Equal(t, uint32(0), stats.aliveEntries)
	require.Equal(t, uint32(1), stats.deleted)

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))
}

// TestCtGcTcp tests whether TCP SNAT entries are removed upon a removal of
// their CT entry.
func TestCtGcTcp(t *testing.T) {
	setupCTMap(t)
	// Init maps
	natMap := nat.NewMap("cilium_nat_any4_test", nat.IPv4, 1000)
	err := natMap.OpenOrCreate()
	require.Nil(t, err)
	defer natMap.Map.Unpin()

	ctMapName := MapNameTCP4Global + "_test"
	mapInfo[mapTypeIPv4TCPGlobal] = mapAttributes{
		natMap: natMap, natMapLock: mapInfo[mapTypeIPv4TCPGlobal].natMapLock,
	}

	ctMap := newMap(ctMapName, mapTypeIPv4TCPGlobal)
	err = ctMap.OpenOrCreate()
	require.Nil(t, err)
	defer ctMap.Map.Unpin()

	// Create the following entries and check that they get GC-ed:
	//	- CT:	TCP OUT 192.168.61.11:38193 -> 192.168.61.12:80 <..>
	//	- NAT: 	TCP OUT 192.168.61.11:38193 -> 192.168.61.12:80 XLATE_SRC 192.168.61.11:38194
	//		TCP IN 192.168.61.12:80 -> 192.168.61.11:38194 XLATE_DST 192.168.61.11:38193

	ctKey := &CtKey4Global{
		tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0x3195,
				DestPort:   0x50,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctVal := &CtEntry{
		Packets:  1,
		Bytes:    216,
		Lifetime: 37459,
	}
	err = ctMap.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

	natKey := &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{192, 168, 61, 12},
				SourceAddr: types.IPv4{192, 168, 61, 11},
				DestPort:   0x50,
				SourcePort: 0x3195,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	natVal := &nat.NatEntry4{
		Created: 37400,
		NeedsCT: 1,
		Addr:    types.IPv4{192, 168, 61, 11},
		Port:    0x3295,
	}
	err = natMap.Map.Update(natKey, natVal)
	require.Nil(t, err)
	natKey = &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 12},
				DestAddr:   types.IPv4{192, 168, 61, 11},
				SourcePort: 0x50,
				DestPort:   0x3295,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_IN,
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
	require.Nil(t, err)

	buf := make(map[string][]string)
	err = ctMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 2, len(buf))

	// GC and check whether NAT entries have been collected
	filter := GCFilter{
		RemoveExpired: true,
		Time:          39000,
	}
	stats := doGC4(ctMap, filter)
	require.Equal(t, uint32(0), stats.aliveEntries)
	require.Equal(t, uint32(1), stats.deleted)

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))
}

// TestCtGcDsr tests whether DSR NAT entries are removed upon a removal of
// their CT entry (== CT_EGRESS).
func TestCtGcDsr(t *testing.T) {
	setupCTMap(t)

	// Init maps
	natMap := nat.NewMap("cilium_nat_any4_test", nat.IPv4, 1000)
	err := natMap.OpenOrCreate()
	require.Nil(t, err)
	defer natMap.Map.Unpin()

	ctMapName := MapNameTCP4Global + "_test"
	mapInfo[mapTypeIPv4TCPGlobal] = mapAttributes{
		natMap: natMap, natMapLock: mapInfo[mapTypeIPv4TCPGlobal].natMapLock,
	}

	ctMap := newMap(ctMapName, mapTypeIPv4TCPGlobal)
	err = ctMap.OpenOrCreate()
	require.Nil(t, err)
	defer ctMap.Map.Unpin()

	// Create the following entries and check that they get GC-ed:
	//	- CT:	TCP OUT 1.1.1.1:1111 -> 192.168.61.11:8080 <..>
	//	- NAT: 	TCP OUT 192.168.61.11:8080 -> 1.1.1.1:1111 XLATE_SRC 2.2.2.2:80

	ctKey := &CtKey4Global{
		tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 61, 11},
				DestAddr:   types.IPv4{1, 1, 1, 1},
				SourcePort: 0x5704,
				DestPort:   0x901f,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	ctVal := &CtEntry{
		Packets:  1,
		Bytes:    216,
		Lifetime: 37459,
		Flags:    DSRInternal,
	}
	err = ctMap.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

	natKey := &nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{1, 1, 1, 1},
				SourceAddr: types.IPv4{192, 168, 61, 11},
				DestPort:   0x5704,
				SourcePort: 0x901f,
				NextHeader: u8proto.TCP,
				Flags:      tuple.TUPLE_F_OUT,
			},
		},
	}
	natVal := &nat.NatEntry4{
		Created: 37400,
		Addr:    types.IPv4{2, 2, 2, 2},
		Port:    0x50,
	}
	err = natMap.Map.Update(natKey, natVal)
	require.Nil(t, err)

	buf := make(map[string][]string)
	err = ctMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	// GC and check whether NAT entry has been collected
	filter := GCFilter{
		RemoveExpired: true,
		Time:          39000,
	}
	stats := doGC4(ctMap, filter)
	require.Equal(t, uint32(0), stats.aliveEntries)
	require.Equal(t, uint32(1), stats.deleted)

	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))
}

// TestOrphanNat checks whether dangling NAT entries are GC'd (GH#12686)
func TestOrphanNatGC(t *testing.T) {
	setupCTMap(t)

	// Init maps
	natMap := nat.NewMap("cilium_nat_any4_test", nat.IPv4, 1000)
	err := natMap.OpenOrCreate()
	require.Nil(t, err)
	defer natMap.Map.Unpin()

	ctMapAnyName := MapNameAny4Global + "_test"
	mapInfo[mapTypeIPv4AnyGlobal] = mapAttributes{
		natMap: natMap, natMapLock: mapInfo[mapTypeIPv4AnyGlobal].natMapLock,
	}
	ctMapAny := newMap(ctMapAnyName, mapTypeIPv4AnyGlobal)
	err = ctMapAny.OpenOrCreate()
	require.Nil(t, err)
	defer ctMapAny.Map.Unpin()

	ctMapTCPName := MapNameTCP4Global + "_test"
	mapInfo[mapTypeIPv4TCPGlobal] = mapAttributes{
		natMap: natMap, natMapLock: mapInfo[mapTypeIPv4TCPGlobal].natMapLock,
	}
	ctMapTCP := newMap(ctMapTCPName, mapTypeIPv4TCPGlobal)
	err = ctMapTCP.OpenOrCreate()
	require.Nil(t, err)
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
		Packets:  1,
		Bytes:    216,
		Lifetime: 37459,
	}
	err = ctMapAny.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

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
	require.Nil(t, err)
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
	require.Nil(t, err)

	stats := PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
	require.Equal(t, uint32(1), stats.IngressAlive)
	require.Equal(t, uint32(0), stats.IngressDeleted)
	require.Equal(t, uint32(1), stats.EgressAlive)
	require.Equal(t, uint32(0), stats.EgressDeleted)
	// Check that both entries haven't removed
	buf := make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 2, len(buf))

	// Now remove the CT entry which should remove both NAT entries
	err = ctMapAny.Map.Delete(ctKey)
	require.Nil(t, err)
	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
	require.Equal(t, uint32(1), stats.IngressDeleted)
	require.Equal(t, uint32(0), stats.IngressAlive)
	require.Equal(t, uint32(1), stats.EgressDeleted)
	require.Equal(t, uint32(0), stats.EgressAlive)
	// Check that both orphan NAT entries have been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))

	// Create only CT_INGRESS NAT entry which should be removed
	err = natMap.Map.Update(natKey, natVal)
	require.Nil(t, err)

	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
	require.Equal(t, uint32(1), stats.IngressDeleted)
	require.Equal(t, uint32(0), stats.EgressDeleted)
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))

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
		Packets:  1,
		Bytes:    216,
		Lifetime: 37459,
		Flags:    DSRInternal,
	}
	err = ctMapTCP.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

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
	require.Nil(t, err)

	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapTCP)
	require.Equal(t, uint32(0), stats.IngressAlive)
	require.Equal(t, uint32(0), stats.IngressDeleted)
	require.Equal(t, uint32(1), stats.EgressAlive)
	require.Equal(t, uint32(0), stats.EgressDeleted)
	// Check that the entry hasn't been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 1, len(buf))

	// Now remove the CT entry which should remove the NAT entry
	err = ctMapTCP.Map.Delete(ctKey)
	require.Nil(t, err)
	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapTCP)
	require.Equal(t, uint32(0), stats.IngressAlive)
	require.Equal(t, uint32(0), stats.IngressDeleted)
	require.Equal(t, uint32(0), stats.EgressAlive)
	require.Equal(t, uint32(1), stats.EgressDeleted)
	// Check that the orphan NAT entry has been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))

	// When a connection is re-opened and switches from DSR to local-backend,
	// its CT entry gets re-created but uses the same CT tuple as key.
	//
	// Validate that we clean up the stale DSR NAT entry in such a case.
	ctVal.Flags = 0

	err = ctMapTCP.Map.Update(ctKey, ctVal)
	require.Nil(t, err)

	err = natMap.Map.Update(natKey, natVal)
	require.Nil(t, err)

	stats = PurgeOrphanNATEntries(ctMapTCP, ctMapTCP)
	require.Equal(t, uint32(0), stats.IngressAlive)
	require.Equal(t, uint32(0), stats.IngressDeleted)
	require.Equal(t, uint32(0), stats.EgressAlive)
	require.Equal(t, uint32(1), stats.EgressDeleted)
	// Check that the orphan NAT entry has been removed
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))

	// Let's check IPv6

	natMapV6 := nat.NewMap("cilium_nat_any6_test", nat.IPv6, 1000)
	err = natMapV6.OpenOrCreate()
	require.Nil(t, err)
	defer natMapV6.Map.Unpin()

	ctMapAnyName = MapNameAny6Global + "_test"
	mapInfo[mapTypeIPv6AnyGlobal] = mapAttributes{
		natMap: natMapV6, natMapLock: mapInfo[mapTypeIPv6AnyGlobal].natMapLock,
	}
	ctMapAnyV6 := newMap(ctMapAnyName, mapTypeIPv6AnyGlobal)
	err = ctMapAnyV6.OpenOrCreate()
	require.Nil(t, err)
	defer ctMapAnyV6.Map.Unpin()

	ctMapTCPName = MapNameTCP6Global + "_test"
	mapInfo[mapTypeIPv6TCPGlobal] = mapAttributes{
		natMap: natMapV6, natMapLock: mapInfo[mapTypeIPv6TCPGlobal].natMapLock,
	}
	ctMapTCPV6 := newMap(ctMapTCPName, mapTypeIPv6TCPGlobal)
	err = ctMapTCP.OpenOrCreate()
	require.Nil(t, err)
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
	require.Nil(t, err)

	stats = PurgeOrphanNATEntries(ctMapTCPV6, ctMapAnyV6)
	require.Equal(t, uint32(1), stats.IngressDeleted)
	require.Equal(t, uint32(0), stats.EgressDeleted)
	buf = make(map[string][]string)
	err = natMap.Map.Dump(buf)
	require.Nil(t, err)
	require.Equal(t, 0, len(buf))
}

// TestCount checks whether the CT map batch lookup dumps the count of the
// entire map.
func TestCount(t *testing.T) {
	testutils.PrivilegedTest(t)

	// Set the max size of the map explicitly so we can provide enough buffer
	// for the LRU map to avoid eviction that makes the assertions within this
	// test indeterministic and consequently cause flakes.
	prev := option.Config.CTMapEntriesGlobalTCP
	defer func() { option.Config.CTMapEntriesGlobalTCP = prev }()
	option.Config.CTMapEntriesGlobalTCP = 524288
	size := 8192 // choose a reasonbly large map that does not make test time too long.

	m := newMap(MapNameTCP4Global+"_test", mapTypeIPv4TCPGlobal)
	err := m.OpenOrCreate()
	assert.NoError(t, err)
	assert.NoError(t, m.Map.Unpin())

	cache := populateFakeDataCTMap4(t, m, size)
	initial := len(cache)

	batchCount, err := m.Count()
	assert.Equal(t, initial, batchCount)
	assert.NoError(t, err)

	toDelete := size / 4
	for k := range cache {
		if err := m.Delete(k); err != nil {
			t.Fatal(err)
		}
		delete(cache, k)

		batchCount, err := m.Count()
		assert.Equal(t, len(cache), batchCount)
		assert.NoError(t, err)

		toDelete--
		if toDelete <= 0 {
			break
		}
	}

	batchCount, err = m.Count()
	assert.Equal(t, len(cache), batchCount)
	assert.NoError(t, err)

	var count int
	assert.NoError(t, m.DumpWithCallback(func(_ bpf.MapKey, _ bpf.MapValue) { count++ }))
	assert.Equal(t, count, batchCount)
	assert.Equal(t, len(cache), batchCount)
}

func populateFakeDataCTMap4(tb testing.TB, m CtMap, size int) map[*CtKey4Global]struct{} {
	tb.Helper()

	protos := []int{int(u8proto.ANY), int(u8proto.ICMP), int(u8proto.TCP), int(u8proto.UDP), int(u8proto.ICMPv6), int(u8proto.SCTP)}
	flags := []int{tuple.TUPLE_F_IN, tuple.TUPLE_F_OUT, tuple.TUPLE_F_RELATED, tuple.TUPLE_F_SERVICE}
	genKey := func() *CtKey4Global {
		return &CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: tuple.TupleKey4{
					DestAddr:   netip.MustParseAddr(fake.IP(fake.WithIPv4())).As4(),
					SourceAddr: netip.MustParseAddr(fake.IP(fake.WithIPv4())).As4(),
					DestPort:   uint16(fake.Port()),
					SourcePort: uint16(fake.Port()),
					NextHeader: u8proto.U8proto(protos[rand.IntN(len(protos))]),
					Flags:      uint8(flags[rand.IntN(len(flags))]),
				},
			},
		}
	}
	value := &CtEntry{
		Packets:          4 + 4,
		Bytes:            216 + 216,
		Lifetime:         37459,
		Flags:            SeenNonSyn | RxClosing,
		RevNAT:           0,
		TxFlagsSeen:      0x02,
		RxFlagsSeen:      0x14,
		SourceSecurityID: 40653,
		LastTxReport:     15856,
		LastRxReport:     15856,
	}

	cache := make(map[*CtKey4Global]struct{}, size)
	for len(cache) < size {
		key := genKey()
		if _, needGenerate := cache[key]; needGenerate {
			continue
		}
		if err := m.Update(key, value); err != nil {
			tb.Fatal(err)
		}
		cache[key] = struct{}{}
	}

	return cache
}
