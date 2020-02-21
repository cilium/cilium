// Copyright 2016-2020 Authors of Cilium
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

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/tuple"
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
	m := newMap(MapNameTCP4Global+"_test", MapTypeIPv4TCPGlobal, true)
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

	a1 := make([]tuple.TupleKey, 1)
	a2 := make([]*CtEntry, 1)

	// Also account the cost of casting from MapKey to TupleKey
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(tuple.TupleKey)
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
