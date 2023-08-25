// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
)

type BPFNatListSuite struct{}

var _ = Suite(&BPFNatListSuite{})

var (
	natKey4 = nat.NatKey4{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{10, 10, 10, 1},
				SourceAddr: types.IPv4{10, 10, 10, 2},
				DestPort:   byteorder.HostToNetwork16(80),
				SourcePort: byteorder.HostToNetwork16(13579),
				NextHeader: 6,
				Flags:      123,
			},
		},
	}
	natKey6 = nat.NatKey6{
		TupleKey6Global: tuple.TupleKey6Global{
			TupleKey6: tuple.TupleKey6{
				DestAddr:   types.IPv6{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				SourceAddr: types.IPv6{1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61},
				DestPort:   byteorder.HostToNetwork16(443),
				SourcePort: byteorder.HostToNetwork16(7878),
				NextHeader: 17,
				Flags:      31,
			},
		},
	}
	natValue4 = nat.NatEntry4{
		Created: 12345,
		NeedsCT: 6789,
		Addr:    types.IPv4{10, 10, 10, 3},
		Port:    byteorder.HostToNetwork16(53),
	}
	natValue6 = nat.NatEntry6{
		Created: 12345,
		NeedsCT: 6789,
		Addr:    types.IPv6{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53},
		Port:    byteorder.HostToNetwork16(53),
	}
)

type natRecord4 struct {
	Key   tuple.TupleKey4
	Value *nat.NatEntry4
}

type natRecord6 struct {
	Key   tuple.TupleKey6
	Value *nat.NatEntry6
}

func (s *BPFNatListSuite) TestDumpNat4(c *C) {

	natMaps := [2]nat.NatMap{
		mockmaps.NewNatMockMap(
			[]nat.NatMapRecord{
				{
					Key:   &natKey4,
					Value: &natValue4,
				},
				{
					Key:   &natKey4,
					Value: &natValue4,
				},
			},
		),
		mockmaps.NewNatMockMap(
			[]nat.NatMapRecord{
				{
					Key:   &natKey4,
					Value: &natValue4,
				},
			},
		),
	}

	maps := make([]interface{}, len(natMaps))
	for i, m := range natMaps {
		maps[i] = m
	}
	rawDump := dumpAndRead(maps, dumpNat, c)

	var natDump []natRecord4
	err := json.Unmarshal([]byte(rawDump), &natDump)
	c.Assert(err, IsNil, Commentf("invalid JSON output: '%s', '%s'", err, rawDump))

	// JSON output may reorder the entries, but in our case they are all
	// the same.
	natRecordDump := nat.NatMapRecord{
		Key:   &nat.NatKey4{TupleKey4Global: tuple.TupleKey4Global{TupleKey4: natDump[0].Key}},
		Value: natDump[0].Value,
	}
	c.Assert(natRecordDump, checker.DeepEquals, natMaps[0].(*mockmaps.NatMockMap).Entries[0])
}

func (s *BPFNatListSuite) TestDumpNat6(c *C) {

	natMaps := [2]nat.NatMap{
		mockmaps.NewNatMockMap(
			[]nat.NatMapRecord{
				{
					Key:   &natKey6,
					Value: &natValue6,
				},
				{
					Key:   &natKey6,
					Value: &natValue6,
				},
			},
		),
		mockmaps.NewNatMockMap(
			[]nat.NatMapRecord{
				{
					Key:   &natKey6,
					Value: &natValue6,
				},
			},
		),
	}

	maps := make([]interface{}, len(natMaps))
	for i, m := range natMaps {
		maps[i] = m
	}
	rawDump := dumpAndRead(maps, dumpNat, c)

	var natDump []natRecord6
	err := json.Unmarshal([]byte(rawDump), &natDump)
	c.Assert(err, IsNil, Commentf("invalid JSON output: '%s', '%s'", err, rawDump))

	// JSON output may reorder the entries, but in our case they are all
	// the same.
	natRecordDump := nat.NatMapRecord{
		Key:   &nat.NatKey6{TupleKey6Global: tuple.TupleKey6Global{TupleKey6: natDump[0].Key}},
		Value: natDump[0].Value,
	}
	c.Assert(natRecordDump, checker.DeepEquals, natMaps[0].(*mockmaps.NatMockMap).Entries[0])
}
