// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package rib

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"

	"github.com/stretchr/testify/require"
)

type fixture struct {
	hive *hive.Hive
	db   *statedb.DB
	rib  RIB
	fib  FIB
}

type nextHopA struct{}

func (n *nextHopA) Kind() NextHopKind { return nexthopAKind }
func (n *nextHopA) Name() string      { return "NextHopA" }

type nextHopB struct{}

func (n *nextHopB) Kind() NextHopKind { return nexthopBKind }
func (n *nextHopB) Name() string      { return "NextHopB" }

const (
	nexthopAKind NextHopKind = iota
	nexthopBKind
)

var (
	ownerA       = Owner{ID: 1, Name: "OwnerA"}
	ownerB       = Owner{ID: 2, Name: "OwnerB"}
	ownerC       = Owner{ID: 3, Name: "OwnerC"}
	protoA       = Proto{Kind: 1, Name: "ProtoA", Distance: 100}
	protoB       = Proto{Kind: 2, Name: "ProtoB", Distance: 200}
	protoC       = Proto{Kind: 3, Name: "ProtoC", Distance: 300}
	rt1VRFPrefix = VRFPrefix{
		VRF:    1,
		Prefix: netip.MustParsePrefix("10.0.0.0/24"),
	}
	rt2VRFPrefix = VRFPrefix{
		VRF:    1,
		Prefix: netip.MustParsePrefix("10.0.1.0/24"),
	}
	rt3VRFPrefix = VRFPrefix{
		VRF:    1,
		Prefix: netip.MustParsePrefix("10.0.2.0/24"),
	}
	rt1OwnerAProtoA = Route{
		VRF:     rt1VRFPrefix.VRF,
		Prefix:  rt1VRFPrefix.Prefix,
		Owner:   ownerA,
		NextHop: &nextHopA{},
		Proto:   protoA,
	}
	rt1OwnerBProtoB = Route{
		VRF:     rt1VRFPrefix.VRF,
		Prefix:  rt1VRFPrefix.Prefix,
		Owner:   ownerB,
		NextHop: &nextHopA{},
		Proto:   protoB,
	}
	rt1OwnerCProtoC = Route{
		VRF:     rt3VRFPrefix.VRF,
		Prefix:  rt3VRFPrefix.Prefix,
		Owner:   ownerC,
		NextHop: &nextHopA{},
		Proto:   protoC,
	}
	rt2OwnerAProtoA = Route{
		VRF:     rt2VRFPrefix.VRF,
		Prefix:  rt2VRFPrefix.Prefix,
		Owner:   ownerA,
		NextHop: &nextHopB{},
		Proto:   protoA,
	}
	rt2OwnerBProtoB = Route{
		VRF:     rt2VRFPrefix.VRF,
		Prefix:  rt2VRFPrefix.Prefix,
		Owner:   ownerB,
		NextHop: &nextHopB{},
		Proto:   protoB,
	}
)

func newFixture() *fixture {
	f := &fixture{}
	h := hive.New(
		job.Cell,
		statedb.Cell,
		Cell,
		cell.Invoke(func(db *statedb.DB, rib RIB, fib FIB) {
			f.db = db
			f.rib = rib
			f.fib = fib
		}),
	)
	f.hive = h
	return f
}

func TestRIBInsert(t *testing.T) {
	tests := []struct {
		name     string
		insert   []Route
		expected []Route
	}{
		{
			name:     "vrf + prefix can be duplicated",
			insert:   []Route{rt1OwnerAProtoA, rt1OwnerBProtoB},
			expected: []Route{rt1OwnerAProtoA, rt1OwnerBProtoB},
		},
		{
			name:     "vrf + prefix + owner can't be duplicated",
			insert:   []Route{rt1OwnerAProtoA, rt1OwnerAProtoA},
			expected: []Route{rt1OwnerAProtoA},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			r.NoError(f.hive.Populate())

			wtxn := f.db.WriteTxn(f.rib)
			for _, rt := range test.insert {
				_, _, err := f.rib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			rtxn := f.db.ReadTxn()
			it, _ := f.rib.All(rtxn)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

func TestRIBLookup(t *testing.T) {
	tests := []struct {
		name     string
		insert   []Route
		query    statedb.Query[Route]
		expected []Route
	}{
		{
			name:     "lookup by owner",
			insert:   []Route{rt1OwnerAProtoA, rt1OwnerBProtoB},
			query:    RIBOwnerIndex.Query(ownerA),
			expected: []Route{rt1OwnerAProtoA},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			r.NoError(f.hive.Populate())

			wtxn := f.db.WriteTxn(f.rib)
			for _, rt := range test.insert {
				_, _, err := f.rib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			rtxn := f.db.ReadTxn()
			it, _ := f.rib.Get(rtxn, test.query)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

// Ensures each writers (route owners) can read/write routes individually
func TestRIBMultiWriterEvent(t *testing.T) {
	tests := []struct {
		name         string
		insert       Route
		expectEventA bool
		expectEventB bool
	}{
		{
			name:         "insertion of A doesn't notify B",
			insert:       rt2OwnerAProtoA,
			expectEventA: true,
			expectEventB: false,
		},
		{
			name:         "insertion of B doesn't notify A",
			insert:       rt2OwnerBProtoB,
			expectEventA: false,
			expectEventB: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			r.NoError(f.hive.Populate())

			// Initialize table
			wtxn := f.db.WriteTxn(f.rib)
			_, _, err := f.rib.Insert(wtxn, rt1OwnerAProtoA)
			r.NoError(err)
			_, _, err = f.rib.Insert(wtxn, rt1OwnerBProtoB)
			r.NoError(err)
			wtxn.Commit()

			// Owner A
			rtxnA := f.db.ReadTxn()
			it, watchA := f.rib.Get(rtxnA, RIBOwnerIndex.Query(ownerA))
			r.ElementsMatch(statedb.Collect(it), []Route{rt1OwnerAProtoA})

			// Owner B
			rtxnB := f.db.ReadTxn()
			it, watchB := f.rib.Get(rtxnB, RIBOwnerIndex.Query(ownerB))
			r.ElementsMatch(statedb.Collect(it), []Route{rt1OwnerBProtoB})

			// Insert new Route
			wtxn = f.db.WriteTxn(f.rib)
			_, hadOld, err := f.rib.Insert(wtxn, test.insert)
			r.False(hadOld)
			r.NoError(err)
			wtxn.Commit()

			// Check event occurence
			select {
			case <-watchA:
				if !test.expectEventA {
					r.FailNow("unexpected event occured for A")
				}
			default:
				if test.expectEventA {
					r.FailNow("expected event for A, but didn't get it")
				}
			}

			// Check event occurence
			select {
			case <-watchB:
				if !test.expectEventB {
					r.FailNow("unexpected event occured for B")
				}
			default:
				if test.expectEventB {
					r.FailNow("expected event for B, but didn't get it")
				}
			}
		})
	}
}

func TestFIBInsert(t *testing.T) {
	tests := []struct {
		name     string
		insert   []Route
		expected []Route
	}{
		{
			name:     "vrf + prefix can't be duplicated",
			insert:   []Route{rt1OwnerAProtoA, rt1OwnerBProtoB},
			expected: []Route{rt1OwnerBProtoB},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			r.NoError(f.hive.Populate())

			wtxn := f.db.WriteTxn(f.fib)
			for _, rt := range test.insert {
				_, _, err := f.fib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			rtxn := f.db.ReadTxn()
			it, _ := f.fib.All(rtxn)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

func TestFIBLookup(t *testing.T) {
	tests := []struct {
		name     string
		insert   []Route
		query    statedb.Query[Route]
		expected []Route
	}{
		{
			name:     "lookup by nexthop",
			insert:   []Route{rt1OwnerAProtoA, rt2OwnerAProtoA},
			query:    FIBNextHopIndex.Query(nexthopAKind),
			expected: []Route{rt1OwnerAProtoA},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := require.New(t)

			f := newFixture()
			r.NoError(f.hive.Populate())

			wtxn := f.db.WriteTxn(f.fib)
			for _, rt := range test.insert {
				_, _, err := f.fib.Insert(wtxn, rt)
				r.NoError(err)
			}
			wtxn.Commit()

			rtxn := f.db.ReadTxn()
			it, _ := f.fib.Get(rtxn, test.query)
			r.ElementsMatch(statedb.Collect(it), test.expected)
		})
	}
}

func TestBestPathSelection(t *testing.T) {
	steps := []struct {
		name     string
		insert   *Route
		del      *Route
		bestPath Route
	}{
		{
			name:     "init",
			insert:   &rt1OwnerBProtoB,
			bestPath: rt1OwnerBProtoB,
		},
		{
			name:     "shoter distance protocol inserted",
			insert:   &rt1OwnerAProtoA,
			bestPath: rt1OwnerAProtoA,
		},
		{
			name:     "delete shorter distance protocol, another route promotes to the best path",
			del:      &rt1OwnerAProtoA,
			bestPath: rt1OwnerBProtoB,
		},
		{
			name:     "new route inserted, but no best path update",
			insert:   &rt1OwnerCProtoC,
			bestPath: rt1OwnerBProtoB,
		},
	}

	r := require.New(t)

	f := newFixture()
	r.NoError(f.hive.Start(context.TODO()))
	defer f.hive.Stop(context.TODO())

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			r := require.New(t)

			rtxn := f.db.ReadTxn()
			_, ribWatch := f.rib.All(rtxn)
			_, fibWatch := f.fib.All(rtxn)

			wtxn := f.db.WriteTxn(f.rib)

			if step.insert != nil {
				_, _, err := f.rib.Insert(wtxn, *step.insert)
				r.NoError(err)
			}

			if step.del != nil {
				_, _, err := f.rib.Delete(wtxn, *step.del)
				r.NoError(err)
			}

			wtxn.Commit()

			<-ribWatch
			<-fibWatch

			bestPath, _, found := f.fib.First(f.db.ReadTxn(), FIBIDIndex.Query(rt1VRFPrefix))
			r.True(found)
			r.Equal(bestPath, step.bestPath)
		})
	}
}
