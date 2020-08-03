// Copyright 2016-2019 Authors of Cilium
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

// +build privileged_tests

package ctmap

import (
	"testing"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type CTMapTestSuite struct{}

var _ = Suite(&CTMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *CTMapTestSuite) Benchmark_MapUpdate(c *C) {
	m := newMap(MapNameTCP4Global+"_test", mapTypeIPv4TCPGlobal)
	_, err := m.OpenOrCreate()
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
		err := bpf.UpdateElement(m.Map.GetFd(), unsafe.Pointer(key), unsafe.Pointer(value), 0)
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
func (k *CTMapTestSuite) TestCtGcIcmp(c *C) {
	bpf.CheckOrMountFS("", false)
	err := bpf.ConfigureResourceLimits()
	c.Assert(err, IsNil)

	// Init maps
	natMap := nat.NewMap("cilium_nat_any4_test", true, 1000)
	_, err = natMap.OpenOrCreate()
	c.Assert(err, IsNil)
	defer natMap.Map.Unpin()

	ctMapName := MapNameAny4Global + "_test"
	setupMapInfo(mapTypeIPv4AnyGlobal, ctMapName,
		&CtKey4Global{}, int(unsafe.Sizeof(CtKey4Global{})),
		100, natMap)

	ctMap := newMap(ctMapName, mapTypeIPv4AnyGlobal)
	_, err = ctMap.OpenOrCreate()
	c.Assert(err, IsNil)
	defer ctMap.Map.Unpin()

	// Create the following entries and check that they get GC-ed:
	//	- CT:	ICMP OUT 192.168.34.11:38193 -> 192.168.34.12:0 <..>
	//	- NAT:	ICMP IN 192.168.34.12:0 -> 192.168.34.11:38193 XLATE_DST <..>
	//	 		ICMP OUT 192.168.34.11:38193 -> 192.168.34.12:0 XLATE_SRC <..>

	ctKey := &CtKey4Global{
		tuple.TupleKey4Global{
			tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 34, 12},
				DestAddr:   types.IPv4{192, 168, 34, 11},
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
	err = bpf.UpdateElement(ctMap.Map.GetFd(), unsafe.Pointer(ctKey),
		unsafe.Pointer(ctVal), 0)
	c.Assert(err, IsNil)

	natKey := &nat.NatKey4{
		tuple.TupleKey4Global{
			tuple.TupleKey4{
				DestAddr:   types.IPv4{192, 168, 34, 12},
				SourceAddr: types.IPv4{192, 168, 34, 11},
				DestPort:   0,
				SourcePort: 0x3195,
				NextHeader: u8proto.ICMP,
				Flags:      0,
			},
		},
	}
	natVal := &nat.NatEntry4{
		Created:   37400,
		HostLocal: 1,
		Addr:      types.IPv4{192, 168, 34, 11},
		Port:      0x3195,
	}
	err = bpf.UpdateElement(natMap.Map.GetFd(), unsafe.Pointer(natKey),
		unsafe.Pointer(natVal), 0)
	c.Assert(err, IsNil)
	natKey = &nat.NatKey4{
		tuple.TupleKey4Global{
			tuple.TupleKey4{
				SourceAddr: types.IPv4{192, 168, 34, 12},
				DestAddr:   types.IPv4{192, 168, 34, 11},
				SourcePort: 0,
				DestPort:   0x3195,
				NextHeader: u8proto.ICMP,
				Flags:      1,
			},
		},
	}
	natVal = &nat.NatEntry4{
		Created:   37400,
		HostLocal: 1,
		Addr:      types.IPv4{192, 168, 34, 11},
		Port:      0x3195,
	}
	err = bpf.UpdateElement(natMap.Map.GetFd(), unsafe.Pointer(natKey),
		unsafe.Pointer(natVal), 0)
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
