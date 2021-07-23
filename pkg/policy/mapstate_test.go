// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2020 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package policy

import (
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"

	"gopkg.in/check.v1"
)

// WithOwners replaces owners of 'e' with 'owners'.
// No owners is represented with a 'nil' map.
func (e MapStateEntry) WithOwners(owners ...MapStateOwner) MapStateEntry {
	e.owners = make(map[MapStateOwner]struct{}, len(owners))
	for _, cs := range owners {
		e.owners[cs] = struct{}{}
	}
	return e
}

// WithoutOwners clears the 'owners' of 'e'.
// Note: This is used only in unit tests and helps test readability.
func (e MapStateEntry) WithoutOwners() MapStateEntry {
	e.owners = nil
	return e
}

// WithDependents 'e' adds 'keys' to 'e.dependents'.
func (e MapStateEntry) WithDependents(keys ...Key) MapStateEntry {
	if len(keys) > 0 {
		for _, key := range keys {
			e.AddDependent(key)
		}
	}
	return e
}

func (ds *PolicyTestSuite) TestPolicyKeyTrafficDirection(c *check.C) {
	k := Key{TrafficDirection: trafficdirection.Ingress.Uint8()}
	c.Assert(k.IsIngress(), check.Equals, true)
	c.Assert(k.IsEgress(), check.Equals, false)

	k = Key{TrafficDirection: trafficdirection.Egress.Uint8()}
	c.Assert(k.IsIngress(), check.Equals, false)
	c.Assert(k.IsEgress(), check.Equals, true)
}

func (ds *PolicyTestSuite) TestMapState_DenyPreferredInsert(c *check.C) {
	type args struct {
		key   Key
		entry MapStateEntry
	}
	tests := []struct {
		name       string
		keys, want MapState
		args       args
	}{
		{
			name: "test-1 - no KV added, map should remain the same",
			keys: MapState{
				Key{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: 0,
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			args: args{
				key:   Key{},
				entry: MapStateEntry{},
			},
			want: MapState{
				Key{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: 0,
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-2 - L3 allow KV should not overwrite deny entry",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-3 - L3-L4 allow KV should not overwrite deny entry",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-4 - L3-L4 deny KV should overwrite allow entry",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-5 - L3 deny KV should overwrite all L3-L4 allow and L3 allow entries for the same L3",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				Key{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-6 - L3 egress deny KV should not overwrite any existing ingress allow",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				Key{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-7 - L3 ingress deny KV should not be overwritten by a L3-L4 ingress allow",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-8 - L3 ingress deny KV should not be overwritten by a L3-L4-L7 ingress allow",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-9 - L3 ingress deny KV should overwrite by a L3-L4-L7 ingress allow",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-10 - L3 ingress deny KV should overwrite by a L3-L4-L7 ingress allow and a L3-L4 deny",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			args: args{
				key: Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-11 - L3 ingress allow should not be allowed if there is a L3 'all' deny",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			args: args{
				key: Key{
					Identity:         100,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		}, {
			name: "test-12 - inserting a L3 'all' deny should delete all entries for that direction",
			keys: MapState{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         1,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				Key{
					Identity:         100,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			args: args{
				key: Key{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				},
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: MapState{
				Key{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				Key{
					Identity:         100,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: MapStateEntry{
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
	}
	for _, tt := range tests {
		tt.keys.DenyPreferredInsert(tt.args.key, tt.args.entry)
		c.Assert(tt.keys, checker.DeepEquals, tt.want, check.Commentf(tt.name))
	}
}

func testKey(id int, port uint16, proto uint8, direction trafficdirection.TrafficDirection) Key {
	return Key{
		Identity:         uint32(id),
		DestPort:         port,
		Nexthdr:          proto,
		TrafficDirection: direction.Uint8(),
	}
}

func testIngressKey(id int, port uint16, proto uint8) Key {
	return testKey(id, port, proto, trafficdirection.Ingress)
}

func testEgressKey(id int, port uint16, proto uint8) Key {
	return testKey(id, port, proto, trafficdirection.Egress)
}

func DNSUDPEgressKey(id int) Key {
	return testEgressKey(id, 53, 17)
}

func DNSTCPEgressKey(id int) Key {
	return testEgressKey(id, 53, 6)
}

func HostIngressKey() Key {
	return testIngressKey(1, 0, 0)
}

func AnyIngressKey() Key {
	return testIngressKey(0, 0, 0)
}

func AnyEgressKey() Key {
	return testEgressKey(0, 0, 0)
}

func HttpIngressKey(id int) Key {
	return testIngressKey(id, 80, 6)
}

func HttpEgressKey(id int) Key {
	return testEgressKey(id, 80, 6)
}

func testEntry(proxyPort uint16, deny bool, owners ...MapStateOwner) MapStateEntry {
	entry := MapStateEntry{
		ProxyPort: proxyPort,
		IsDeny:    deny,
	}
	if len(owners) > 0 {
		entry.owners = make(map[MapStateOwner]struct{}, len(owners))
	}
	for _, owner := range owners {
		entry.owners[owner] = struct{}{}
	}
	return entry
}

func testEntryD(proxyPort uint16, deny bool, derivedFrom labels.LabelArrayList, owners ...MapStateOwner) MapStateEntry {
	entry := testEntry(proxyPort, deny, owners...)
	entry.DerivedFromRules = derivedFrom
	return entry
}

func (ds *PolicyTestSuite) TestMapState_AccumulateMapChangesDeny(c *check.C) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    uint8
		ingress  bool
		redirect bool
		deny     bool
	}
	tests := []struct {
		continued bool // Start from the end state of the previous test
		name      string
		setup     MapState
		args      []args // changes applied, in order
		state     MapState
		adds      MapState
		deletes   MapState
	}{{
		name: "test-1a - Adding identity to an existing state",
		setup: MapState{
			AnyIngressKey():   testEntry(0, false),
			HttpIngressKey(0): testEntry(12345, false, nil),
		},
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			AnyIngressKey():          testEntry(0, false),
			testIngressKey(41, 0, 0): testEntry(0, true, csFoo).WithDependents(HttpIngressKey(41)),
			HttpIngressKey(0):        testEntry(12345, false, nil),
			HttpIngressKey(41):       testEntry(0, true).WithOwners(testIngressKey(41, 0, 0)),
		},
		adds: MapState{
			testIngressKey(41, 0, 0): testEntry(0, true),
			HttpIngressKey(41):       testEntry(0, true),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-1b - Adding 2nd identity",
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			AnyIngressKey():          testEntry(0, false),
			testIngressKey(41, 0, 0): testEntry(0, true, csFoo).WithDependents(HttpIngressKey(41)),
			testIngressKey(42, 0, 0): testEntry(0, true, csFoo).WithDependents(HttpIngressKey(42)),
			HttpIngressKey(0):        testEntry(12345, false, nil),
			HttpIngressKey(41):       testEntry(0, true).WithOwners(testIngressKey(41, 0, 0)),
			HttpIngressKey(42):       testEntry(0, true).WithOwners(testIngressKey(42, 0, 0)),
		},
		adds: MapState{
			testIngressKey(42, 0, 0): testEntry(0, true),
			HttpIngressKey(42):       testEntry(0, true),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-1c - Removing the same key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{42}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			AnyIngressKey():          testEntry(0, false),
			testIngressKey(41, 0, 0): testEntry(0, true, csFoo).WithDependents(HttpIngressKey(41)),
			HttpIngressKey(0):        testEntry(12345, false, nil),
			HttpIngressKey(41):       testEntry(0, true).WithOwners(testIngressKey(41, 0, 0)),
		},
		adds: MapState{},
		deletes: MapState{
			testIngressKey(42, 0, 0): testEntry(0, true), // removed key
			HttpIngressKey(42):       testEntry(0, true), // removed dependent key
		},
	}, {
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, true, csFoo),
			HttpIngressKey(43): testEntry(0, true, csFoo),
		},
		adds: MapState{
			HttpIngressKey(42): testEntry(0, true),
			HttpIngressKey(43): testEntry(0, true),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-2b - Adding Bar also selecting 42",
		args: []args{
			{cs: csBar, adds: []int{42, 44}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, true, csFoo, csBar),
			HttpIngressKey(43): testEntry(0, true, csFoo),
			HttpIngressKey(44): testEntry(0, true, csBar),
		},
		adds: MapState{
			HttpIngressKey(44): testEntry(0, true),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-2c - Deleting 42 from Foo, remains on Bar and no deletes",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, true, csBar),
			HttpIngressKey(43): testEntry(0, true, csFoo),
			HttpIngressKey(44): testEntry(0, true, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-2d - Deleting 42 from Foo again, not deleted",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, true, csBar),
			HttpIngressKey(43): testEntry(0, true, csFoo),
			HttpIngressKey(44): testEntry(0, true, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-2e - Deleting 42 from Bar, deleted",
		args: []args{
			{cs: csBar, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			HttpIngressKey(43): testEntry(0, true, csFoo),
			HttpIngressKey(44): testEntry(0, true, csBar),
		},
		adds: MapState{},
		deletes: MapState{
			HttpIngressKey(42): testEntry(0, true),
		},
	}, {
		continued: true,
		name:      "test-2f - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: MapState{
			HttpIngressKey(43): testEntry(0, true, csFoo),
			HttpIngressKey(44): testEntry(0, true, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: false,
		name:      "test-3a - egress allow with deny-L3",
		setup: MapState{
			AnyIngressKey():         testEntry(0, false),
			HostIngressKey():        testEntry(0, false),
			testEgressKey(42, 0, 0): testEntry(0, true, csFoo),
		},
		args: []args{
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: MapState{
			AnyIngressKey():         testEntry(0, false),
			HostIngressKey():        testEntry(0, false),
			testEgressKey(42, 0, 0): testEntry(0, true, csFoo),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-3b - egress allow DNS on another ID with deny-L3",
		args: []args{
			{cs: csBar, adds: []int{43}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{43}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: MapState{
			AnyIngressKey():         testEntry(0, false),
			HostIngressKey():        testEntry(0, false),
			testEgressKey(42, 0, 0): testEntry(0, true, csFoo),
			DNSUDPEgressKey(43):     testEntry(0, false, csBar),
			DNSTCPEgressKey(43):     testEntry(0, false, csBar),
		},
		adds: MapState{
			DNSUDPEgressKey(43): testEntry(0, false),
			DNSTCPEgressKey(43): testEntry(0, false),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-3c - egress allow HTTP proxy with deny-L3",
		args: []args{
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: MapState{
			AnyIngressKey():         testEntry(0, false),
			HostIngressKey():        testEntry(0, false),
			testEgressKey(42, 0, 0): testEntry(0, true, csFoo),
			DNSUDPEgressKey(43):     testEntry(0, false, csBar),
			DNSTCPEgressKey(43):     testEntry(0, false, csBar),
			HttpEgressKey(43):       testEntry(1, false, csFoo),
		},
		adds: MapState{
			HttpEgressKey(43): testEntry(1, false),
		},
		deletes: MapState{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			//HttpIngressKey(42): testEntry(0, false, csFoo),
		},
		adds: MapState{
			//HttpIngressKey(42): testEntry(0, false),
		},
		deletes: MapState{
			//HttpIngressKey(43): testEntry(0, false),
		},
	},
	}

	policyMapState := MapState{}

	for _, tt := range tests {
		policyMaps := MapChanges{}
		if !tt.continued {
			if tt.setup != nil {
				policyMapState = tt.setup
			} else {
				policyMapState = MapState{}
			}
		}
		for _, x := range tt.args {
			dir := trafficdirection.Egress
			if x.ingress {
				dir = trafficdirection.Ingress
			}
			adds := x.cs.addSelections(x.adds...)
			deletes := x.cs.deleteSelections(x.deletes...)
			var cs CachedSelector
			if x.cs != nil {
				cs = x.cs
			}
			policyMaps.AccumulateMapChanges(cs, adds, deletes, x.port, x.proto, dir, x.redirect, x.deny, nil)
		}
		adds, deletes := policyMaps.consumeMapChanges(policyMapState)
		c.Assert(policyMapState, checker.DeepEquals, tt.state, check.Commentf(tt.name+" (MapState)"))
		c.Assert(adds, checker.DeepEquals, tt.adds, check.Commentf(tt.name+" (adds)"))
		c.Assert(deletes, checker.DeepEquals, tt.deletes, check.Commentf(tt.name+" (deletes)"))
	}
}

func (ds *PolicyTestSuite) TestMapState_AccumulateMapChanges(c *check.C) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    uint8
		ingress  bool
		redirect bool
		deny     bool
	}
	tests := []struct {
		continued bool // Start from the end state of the previous test
		name      string
		args      []args // changes applied, in order
		state     MapState
		adds      MapState
		deletes   MapState
	}{{
		name: "test-1 - Adding identity to an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, false, csFoo),
		},
		adds: MapState{
			HttpIngressKey(42): testEntry(0, false),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-2 - Removing the sole key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{},
		adds:  MapState{},
		deletes: MapState{
			HttpIngressKey(42): testEntry(0, false),
		},
	}, {
		name: "test-3 - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, false, csFoo),
			HttpIngressKey(43): testEntry(0, false, csFoo),
		},
		adds: MapState{
			HttpIngressKey(42): testEntry(0, false),
			HttpIngressKey(43): testEntry(0, false),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-4 - Adding Bar also selecting 42",
		args: []args{
			{cs: csBar, adds: []int{42, 44}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, false, csFoo, csBar),
			HttpIngressKey(43): testEntry(0, false, csFoo),
			HttpIngressKey(44): testEntry(0, false, csBar),
		},
		adds: MapState{
			HttpIngressKey(44): testEntry(0, false),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-5 - Deleting 42 from Foo, remains on Bar and no deletes",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, false, csBar),
			HttpIngressKey(43): testEntry(0, false, csFoo),
			HttpIngressKey(44): testEntry(0, false, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-5b - Deleting 42 from Foo again, not deleted",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			HttpIngressKey(42): testEntry(0, false, csBar),
			HttpIngressKey(43): testEntry(0, false, csFoo),
			HttpIngressKey(44): testEntry(0, false, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-6 - Deleting 42 from Bar, deleted",
		args: []args{
			{cs: csBar, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			HttpIngressKey(43): testEntry(0, false, csFoo),
			HttpIngressKey(44): testEntry(0, false, csBar),
		},
		adds: MapState{},
		deletes: MapState{
			HttpIngressKey(42): testEntry(0, false),
		},
	}, {
		continued: true,
		name:      "test-6b - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			HttpIngressKey(43): testEntry(0, false, csFoo),
			HttpIngressKey(44): testEntry(0, false, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: false,
		name:      "test-7a - egress HTTP proxy (setup)",
		args: []args{
			{cs: nil, adds: []int{0}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
			{cs: nil, adds: []int{1}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: MapState{
			AnyIngressKey():     testEntry(0, false, nil),
			HostIngressKey():    testEntry(0, false, nil),
			DNSUDPEgressKey(42): testEntry(0, false, csBar),
			DNSTCPEgressKey(42): testEntry(0, false, csBar),
		},
		adds: MapState{
			AnyIngressKey():     testEntry(0, false),
			HostIngressKey():    testEntry(0, false),
			DNSUDPEgressKey(42): testEntry(0, false),
			DNSTCPEgressKey(42): testEntry(0, false),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-7b - egress HTTP proxy (incremental update)",
		args: []args{
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: MapState{
			AnyIngressKey():     testEntry(0, false, nil),
			HostIngressKey():    testEntry(0, false, nil),
			DNSUDPEgressKey(42): testEntry(0, false, csBar),
			DNSTCPEgressKey(42): testEntry(0, false, csBar),
			HttpEgressKey(43):   testEntry(1, false, csFoo),
		},
		adds: MapState{
			HttpEgressKey(43): testEntry(1, false),
		},
		deletes: MapState{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: MapState{
			//HttpIngressKey(42): testEntry(0, false, csFoo),
		},
		adds: MapState{
			//HttpIngressKey(42): testEntry(0, false),
		},
		deletes: MapState{
			//HttpIngressKey(43): testEntry(0, false),
		},
	},
	}

	policyMapState := MapState{}

	for _, tt := range tests {
		policyMaps := MapChanges{}
		if !tt.continued {
			policyMapState = MapState{}
		}
		for _, x := range tt.args {
			dir := trafficdirection.Egress
			if x.ingress {
				dir = trafficdirection.Ingress
			}
			adds := x.cs.addSelections(x.adds...)
			deletes := x.cs.deleteSelections(x.deletes...)
			var cs CachedSelector
			if x.cs != nil {
				cs = x.cs
			}
			policyMaps.AccumulateMapChanges(cs, adds, deletes, x.port, x.proto, dir, x.redirect, x.deny, nil)
		}
		adds, deletes := policyMaps.consumeMapChanges(policyMapState)
		c.Assert(policyMapState, checker.DeepEquals, tt.state, check.Commentf(tt.name+" (MapState)"))
		c.Assert(adds, checker.DeepEquals, tt.adds, check.Commentf(tt.name+" (adds)"))
		c.Assert(deletes, checker.DeepEquals, tt.deletes, check.Commentf(tt.name+" (deletes)"))
	}
}
