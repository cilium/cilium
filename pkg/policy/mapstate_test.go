// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package policy

import (
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"

	"gopkg.in/check.v1"
)

// WithSelectors returns a copy of 'e', but selectors replaced with 'selectors'. 'e' is not modified.
// No selectors is represented with a 'nil' map.
func (e MapStateEntry) WithSelectors(selectors ...CachedSelector) MapStateEntry {
	mse := e
	mse.selectors = make(map[CachedSelector]struct{}, len(selectors))
	for _, cs := range selectors {
		mse.selectors[cs] = struct{}{}
	}
	return mse
}

// WithoutSelectors returns a copy of 'e', but selectors replaced with 'nil'. 'e' is not modified.
// Note: This is used only in unit tests and helps test readability.
func (e MapStateEntry) WithoutSelectors() MapStateEntry {
	return e.WithSelectors()
}

func (ds *PolicyTestSuite) TestPolicyKeyTrafficDirection(c *check.C) {
	k := Key{TrafficDirection: trafficdirection.Ingress.Uint8()}
	c.Assert(k.IsIngress(), check.Equals, true)
	c.Assert(k.IsEgress(), check.Equals, false)

	k = Key{TrafficDirection: trafficdirection.Egress.Uint8()}
	c.Assert(k.IsIngress(), check.Equals, false)
	c.Assert(k.IsEgress(), check.Equals, true)
}

func (ds *PolicyTestSuite) TestMapState_AccumulateMapChanges(c *check.C) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	TestKey := func(id int, port uint16, proto uint8, direction trafficdirection.TrafficDirection) Key {
		return Key{
			Identity:         uint32(id),
			DestPort:         port,
			Nexthdr:          proto,
			TrafficDirection: direction.Uint8(),
		}
	}
	TestIngressKey := func(id int, port uint16, proto uint8) Key {
		return TestKey(id, port, proto, trafficdirection.Ingress)
	}
	TestEgressKey := func(id int, port uint16, proto uint8) Key {
		return TestKey(id, port, proto, trafficdirection.Egress)
	}
	DNSUDPEgressKey := func(id int) Key {
		return TestEgressKey(id, 53, 17)
	}
	DNSTCPEgressKey := func(id int) Key {
		return TestEgressKey(id, 53, 6)
	}
	HostIngressKey := func() Key {
		return TestIngressKey(1, 0, 0)
	}
	AnyIngressKey := func() Key {
		return TestIngressKey(0, 0, 0)
	}
	//AnyEgressKey := func() Key {
	//	return TestEgressKey(0, 0, 0)
	//}
	HttpIngressKey := func(id int) Key {
		return TestIngressKey(id, 80, 6)
	}
	HttpEgressKey := func(id int) Key {
		return TestEgressKey(id, 80, 6)
	}

	TestEntry := func(proxyPort uint16, selectors ...CachedSelector) MapStateEntry {
		entry := MapStateEntry{
			ProxyPort: proxyPort,
		}
		entry.selectors = make(map[CachedSelector]struct{}, len(selectors))
		for _, cs := range selectors {
			entry.selectors[cs] = struct{}{}
		}
		return entry
	}

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    uint8
		ingress  bool
		redirect bool
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
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			HttpIngressKey(42): TestEntry(0, csFoo),
		},
		adds: MapState{
			HttpIngressKey(42): TestEntry(0, csFoo),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-2 - Removing the sole key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{},
		adds:  MapState{},
		deletes: MapState{
			HttpIngressKey(42): TestEntry(0),
		},
	}, {
		name: "test-3 - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			HttpIngressKey(42): TestEntry(0, csFoo),
			HttpIngressKey(43): TestEntry(0, csFoo),
		},
		adds: MapState{
			HttpIngressKey(42): TestEntry(0, csFoo),
			HttpIngressKey(43): TestEntry(0, csFoo),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-4 - Adding Bar also selecting 42",
		args: []args{
			{cs: csBar, adds: []int{42, 44}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			HttpIngressKey(42): TestEntry(0, csFoo, csBar),
			HttpIngressKey(43): TestEntry(0, csFoo),
			HttpIngressKey(44): TestEntry(0, csBar),
		},
		adds: MapState{
			HttpIngressKey(44): TestEntry(0, csBar),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-5 - Deleting 42 from Foo, remains on Bar and no deletes",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			HttpIngressKey(42): TestEntry(0, csBar),
			HttpIngressKey(43): TestEntry(0, csFoo),
			HttpIngressKey(44): TestEntry(0, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-5b - Deleting 42 from Foo again, not deleted",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			HttpIngressKey(42): TestEntry(0, csBar),
			HttpIngressKey(43): TestEntry(0, csFoo),
			HttpIngressKey(44): TestEntry(0, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-6 - Deleting 42 from Bar, deleted",
		args: []args{
			{cs: csBar, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			HttpIngressKey(43): TestEntry(0, csFoo),
			HttpIngressKey(44): TestEntry(0, csBar),
		},
		adds: MapState{},
		deletes: MapState{
			HttpIngressKey(42): TestEntry(0),
		},
	}, {
		continued: true,
		name:      "test-6b - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			HttpIngressKey(43): TestEntry(0, csFoo),
			HttpIngressKey(44): TestEntry(0, csBar),
		},
		adds:    MapState{},
		deletes: MapState{},
	}, {
		continued: false,
		name:      "test-7a - egress HTTP proxy (setup)",
		args: []args{
			{cs: nil, adds: []int{0}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false},
			{cs: nil, adds: []int{1}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false},
		},
		state: MapState{
			AnyIngressKey():     TestEntry(0, nil),
			HostIngressKey():    TestEntry(0, nil),
			DNSUDPEgressKey(42): TestEntry(0, csBar),
			DNSTCPEgressKey(42): TestEntry(0, csBar),
		},
		adds: MapState{
			AnyIngressKey():     TestEntry(0, nil),
			HostIngressKey():    TestEntry(0, nil),
			DNSUDPEgressKey(42): TestEntry(0, csBar),
			DNSTCPEgressKey(42): TestEntry(0, csBar),
		},
		deletes: MapState{},
	}, {
		continued: true,
		name:      "test-7b - egress HTTP proxy (incremental update)",
		args: []args{
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true},
		},
		state: MapState{
			AnyIngressKey():     TestEntry(0, nil),
			HostIngressKey():    TestEntry(0, nil),
			DNSUDPEgressKey(42): TestEntry(0, csBar),
			DNSTCPEgressKey(42): TestEntry(0, csBar),
			HttpEgressKey(43):   TestEntry(1, csFoo),
		},
		adds: MapState{
			HttpEgressKey(43): TestEntry(1, csFoo),
		},
		deletes: MapState{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false},
		},
		state: MapState{
			//HttpIngressKey(42): TestEntry(0, csFoo),
		},
		adds: MapState{
			//HttpIngressKey(42): TestEntry(0),
		},
		deletes: MapState{
			//HttpIngressKey(43): TestEntry(0),
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
			policyMaps.AccumulateMapChanges(cs, adds, deletes, x.port, x.proto, dir, x.redirect, nil)
		}
		adds, deletes := policyMaps.consumeMapChanges(policyMapState)
		c.Assert(policyMapState, checker.DeepEquals, tt.state, check.Commentf(tt.name+" (MapState)"))
		c.Assert(adds, checker.DeepEquals, tt.adds, check.Commentf(tt.name+" (adds)"))
		c.Assert(deletes, checker.DeepEquals, tt.deletes, check.Commentf(tt.name+" (deletes)"))
	}
}
