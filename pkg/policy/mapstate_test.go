// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"testing"

	check "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

func Test_IsSuperSetOf(t *testing.T) {
	tests := []struct {
		superSet Key
		subSet   Key
		res      int
	}{
		{Key{}, Key{}, 0},
		{Key{0, 0, 0, 0}, Key{42, 0, 6, 0}, 1},
		{Key{0, 0, 0, 0}, Key{42, 80, 6, 0}, 1},
		{Key{0, 0, 0, 0}, Key{42, 0, 0, 0}, 1},
		{Key{0, 0, 6, 0}, Key{42, 0, 6, 0}, 2},
		{Key{0, 0, 6, 0}, Key{42, 80, 6, 0}, 2},
		{Key{0, 80, 6, 0}, Key{42, 80, 6, 0}, 3},
		{Key{0, 80, 6, 0}, Key{42, 80, 17, 0}, 0},  // proto is different
		{Key{2, 80, 6, 0}, Key{42, 80, 6, 0}, 0},   // id is different
		{Key{0, 8080, 6, 0}, Key{42, 80, 6, 0}, 0}, // port is different
		{Key{42, 0, 0, 0}, Key{42, 0, 0, 0}, 0},    // same key
		{Key{42, 0, 0, 0}, Key{42, 0, 6, 0}, 4},
		{Key{42, 0, 0, 0}, Key{42, 80, 6, 0}, 4},
		{Key{42, 0, 0, 0}, Key{42, 0, 17, 0}, 4},
		{Key{42, 0, 0, 0}, Key{42, 80, 17, 0}, 4},
		{Key{42, 0, 6, 0}, Key{42, 0, 6, 0}, 0}, // same key
		{Key{42, 0, 6, 0}, Key{42, 80, 6, 0}, 5},
		{Key{42, 0, 6, 0}, Key{42, 8080, 6, 0}, 5},
		{Key{42, 80, 6, 0}, Key{42, 80, 6, 0}, 0},    // same key
		{Key{42, 80, 6, 0}, Key{42, 8080, 6, 0}, 0},  // different port
		{Key{42, 80, 6, 0}, Key{42, 80, 17, 0}, 0},   // different proto
		{Key{42, 80, 6, 0}, Key{42, 8080, 17, 0}, 0}, // different port and proto

		// increasing specificity for a L3/L4 key
		{Key{0, 0, 0, 0}, Key{42, 80, 6, 0}, 1},
		{Key{0, 0, 6, 0}, Key{42, 80, 6, 0}, 2},
		{Key{0, 80, 6, 0}, Key{42, 80, 6, 0}, 3},
		{Key{42, 0, 0, 0}, Key{42, 80, 6, 0}, 4},
		{Key{42, 0, 6, 0}, Key{42, 80, 6, 0}, 5},
		{Key{42, 80, 6, 0}, Key{42, 80, 6, 0}, 0}, // same key

		// increasing specificity for a L3-only key
		{Key{0, 0, 0, 0}, Key{42, 0, 0, 0}, 1},
		{Key{0, 0, 6, 0}, Key{42, 0, 0, 0}, 0},   // not a superset
		{Key{0, 80, 6, 0}, Key{42, 0, 0, 0}, 0},  // not a superset
		{Key{42, 0, 0, 0}, Key{42, 0, 0, 0}, 0},  // same key
		{Key{42, 0, 6, 0}, Key{42, 0, 0, 0}, 0},  // not a superset
		{Key{42, 80, 6, 0}, Key{42, 0, 0, 0}, 0}, // not a superset

		// increasing specificity for a L3/proto key
		{Key{0, 0, 0, 0}, Key{42, 0, 6, 0}, 1},
		{Key{0, 0, 6, 0}, Key{42, 0, 6, 0}, 2},
		{Key{0, 80, 6, 0}, Key{42, 0, 6, 0}, 0}, // not a superset
		{Key{42, 0, 0, 0}, Key{42, 0, 6, 0}, 4},
		{Key{42, 0, 6, 0}, Key{42, 0, 6, 0}, 0},  // same key
		{Key{42, 80, 6, 0}, Key{42, 0, 6, 0}, 0}, // not a superset

		// increasing specificity for a proto-only key
		{Key{0, 0, 0, 0}, Key{0, 0, 6, 0}, 1},
		{Key{0, 0, 6, 0}, Key{0, 0, 6, 0}, 0},   // same key
		{Key{0, 80, 6, 0}, Key{0, 0, 6, 0}, 0},  // not a superset
		{Key{42, 0, 0, 0}, Key{0, 0, 6, 0}, 0},  // not a superset
		{Key{42, 0, 6, 0}, Key{0, 0, 6, 0}, 0},  // not a superset
		{Key{42, 80, 6, 0}, Key{0, 0, 6, 0}, 0}, // not a superset

		// increasing specificity for a L4-only key
		{Key{0, 0, 0, 0}, Key{0, 80, 6, 0}, 1},
		{Key{0, 0, 6, 0}, Key{0, 80, 6, 0}, 2},
		{Key{0, 80, 6, 0}, Key{0, 80, 6, 0}, 0},  // same key
		{Key{42, 0, 0, 0}, Key{0, 80, 6, 0}, 0},  // not a superset
		{Key{42, 0, 6, 0}, Key{0, 80, 6, 0}, 0},  // not a superset
		{Key{42, 80, 6, 0}, Key{0, 80, 6, 0}, 0}, // not a superset

	}
	for i, tt := range tests {
		assert.Equal(t, tt.res, tt.superSet.IsSuperSetOf(tt.subSet), fmt.Sprintf("IsSuperSetOf failed on round %d", i+1))
		if tt.res != 0 {
			assert.Equal(t, 0, tt.subSet.IsSuperSetOf(tt.superSet), fmt.Sprintf("Reverse IsSuperSetOf succeeded on round %d", i+1))
		}
	}
}

// WithOwners replaces owners of 'e' with 'owners'.
// No owners is represented with a 'nil' map.
func (e MapStateEntry) WithOwners(owners ...MapStateOwner) MapStateEntry {
	e.owners = make(map[MapStateOwner]struct{}, len(owners))
	for _, cs := range owners {
		e.owners[cs] = struct{}{}
	}
	return e
}

// WithAuthType sets auth type field as indicated.
func (e MapStateEntry) WithAuthType(authType AuthType) MapStateEntry {
	e.hasAuthType = ExplicitAuthType
	e.AuthType = authType
	return e
}

// WithoutOwners empties the 'owners' of 'e'.
// Note: This is used only in unit tests and helps test readability.
func (e MapStateEntry) WithoutOwners() MapStateEntry {
	e.owners = make(map[MapStateOwner]struct{})
	return e
}

// WithDependents 'e' adds 'keys' to 'e.dependents'.
func (e MapStateEntry) WithDependents(keys ...Key) MapStateEntry {
	if e.dependents == nil {
		e.dependents = make(map[Key]struct{})
	}
	for _, key := range keys {
		e.AddDependent(key)
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

// validatePortProto makes sure each Key in MapState abides by the contract that protocol/nexthdr
// can only be wildcarded if the destination port is also wildcarded.
func (ms *mapState) validatePortProto(c *check.C) {
	ms.ForEach(func(k Key, _ MapStateEntry) bool {
		if k.Nexthdr == 0 {
			c.Assert(k.DestPort, check.Equals, uint16(0))
		}
		return true
	})
}

func (ds *PolicyTestSuite) TestMapState_denyPreferredInsertWithChanges(c *check.C) {
	type args struct {
		key   Key
		entry MapStateEntry
	}
	tests := []struct {
		name                  string
		ms, want              *mapState
		wantAdds, wantDeletes Keys
		wantOldValues         *mapState
		args                  args
	}{
		{
			name: "test-1 - no KV added, map should remain the same",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: 0,
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key:   Key{},
				entry: MapStateEntry{},
			},
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: 0,
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds:      Keys{},
			wantDeletes:   Keys{},
			wantOldValues: newMapState(nil),
		},
		{
			name: "test-2 - L3 allow KV should not overwrite deny entry",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantDeletes:   Keys{},
			wantOldValues: newMapState(nil),
		},
		{
			name: "test-3 - L3-L4 allow KV should not overwrite deny entry",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:      Keys{},
			wantDeletes:   Keys{},
			wantOldValues: newMapState(nil),
		},
		{
			name: "test-4 - L3-L4 deny KV should overwrite allow entry",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantDeletes: Keys{},
			wantOldValues: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
		},
		{
			name: "test-5 - L3 deny KV should overwrite all L3-L4 allow and L3 allow entries for the same L3",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds: Keys{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantDeletes: Keys{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantOldValues: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
		},
		{
			name: "test-6 - L3 egress deny KV should not overwrite any existing ingress allow",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				{
					Identity:         2,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         2,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds: Keys{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: struct{}{},
			},
			wantDeletes:   Keys{},
			wantOldValues: newMapState(nil),
		},
		{
			name: "test-7 - L3 ingress deny KV should not be overwritten by a L3-L4 ingress allow",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:      Keys{},
			wantDeletes:   Keys{},
			wantOldValues: newMapState(nil),
		},
		{
			name: "test-8 - L3 ingress deny KV should not be overwritten by a L3-L4-L7 ingress allow",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:      Keys{},
			wantDeletes:   Keys{},
			wantOldValues: newMapState(nil),
		},
		{
			name: "test-9 - L3 ingress deny KV should overwrite a L3-L4-L7 ingress allow",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantDeletes: Keys{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantOldValues: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
		},
		{
			name: "test-10 - L3 ingress deny KV should overwrite a L3-L4-L7 ingress allow and a L3-L4 deny",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				Key{
					Identity:         1,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantDeletes: Keys{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantOldValues: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
		},
		{
			name: "test-11 - L3 ingress allow should not be allowed if there is a L3 'all' deny",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:      Keys{},
			wantDeletes:   Keys{},
			wantOldValues: newMapState(nil),
		}, {
			name: "test-12 - inserting a L3 'all' deny should delete all entries for that direction",
			ms: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         100,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
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
			want: newMapState(map[Key]MapStateEntry{
				{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				{
					Identity:         100,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Egress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				Key{
					Identity:         0,
					DestPort:         0,
					Nexthdr:          0,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantDeletes: Keys{
				Key{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
				Key{
					Identity:         1,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: struct{}{},
			},
			wantOldValues: newMapState(map[Key]MapStateEntry{
				{
					Identity:         1,
					DestPort:         80,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				{
					Identity:         1,
					DestPort:         5,
					Nexthdr:          3,
					TrafficDirection: trafficdirection.Ingress.Uint8(),
				}: {
					ProxyPort:        8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
		},
	}
	for _, tt := range tests {
		changes := ChangeState{
			Adds:    make(Keys),
			Deletes: make(Keys),
			Old:     newMapState(nil),
		}
		// copy the starging point
		ms := newMapState(make(map[Key]MapStateEntry, tt.ms.Len()))
		tt.ms.ForEach(func(k Key, v MapStateEntry) bool {
			ms.Insert(k, v)
			return true
		})

		ms.denyPreferredInsertWithChanges(tt.args.key, tt.args.entry, nil, denyRules, changes)
		ms.validatePortProto(c)
		c.Assert(ms.allows, checker.DeepEquals, tt.want.allows, check.Commentf("%s: MapState mismatch allows", tt.name))
		c.Assert(ms.denies, checker.DeepEquals, tt.want.denies, check.Commentf("%s: MapState mismatch denies", tt.name))
		c.Assert(changes.Adds, checker.DeepEquals, tt.wantAdds, check.Commentf("%s: Adds mismatch", tt.name))
		c.Assert(changes.Deletes, checker.DeepEquals, tt.wantDeletes, check.Commentf("%s: Deletes mismatch", tt.name))
		oldMap, ok := changes.Old.(*mapState)
		if !ok {
			c.Fatal("Failed to coerce \"changes.Old\" to \"*mapState\"")
		}
		c.Assert(oldMap.allows, checker.DeepEquals, tt.wantOldValues.allows, check.Commentf("%s: OldValues mismatch allows", tt.name))
		c.Assert(oldMap.denies, checker.DeepEquals, tt.wantOldValues.denies, check.Commentf("%s: OldValues mismatch denies", tt.name))

		// Revert changes and check that we get the original mapstate
		ms.RevertChanges(changes)
		c.Assert(ms.allows, checker.DeepEquals, tt.ms.allows, check.Commentf("%s: Revert mismatch allows", tt.name))
		c.Assert(ms.denies, checker.DeepEquals, tt.ms.denies, check.Commentf("%s: Revert mismatch denies", tt.name))
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

func allowEntry(proxyPort uint16, owners ...MapStateOwner) MapStateEntry {
	return testEntry(proxyPort, false, AuthTypeDisabled, owners...)
}

func denyEntry(proxyPort uint16, owners ...MapStateOwner) MapStateEntry {
	return testEntry(proxyPort, true, AuthTypeDisabled, owners...)
}

func testEntry(proxyPort uint16, deny bool, authType AuthType, owners ...MapStateOwner) MapStateEntry {
	entry := MapStateEntry{
		ProxyPort: proxyPort,
		AuthType:  authType,
		IsDeny:    deny,
	}
	entry.owners = make(map[MapStateOwner]struct{}, len(owners))
	for _, owner := range owners {
		entry.owners[owner] = struct{}{}
	}
	return entry
}

func allowEntryD(proxyPort uint16, derivedFrom labels.LabelArrayList, owners ...MapStateOwner) MapStateEntry {
	return testEntryD(proxyPort, false, AuthTypeDisabled, derivedFrom, owners...)
}

func testEntryD(proxyPort uint16, deny bool, authType AuthType, derivedFrom labels.LabelArrayList, owners ...MapStateOwner) MapStateEntry {
	entry := testEntry(proxyPort, deny, authType, owners...)
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
		setup     *mapState
		args      []args // changes applied, in order
		state     MapState
		adds      Keys
		deletes   Keys
	}{{
		name: "test-1a - Adding L3-deny to an existing allow-all with L4-only allow redirect map state entries",
		setup: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():   allowEntry(0),
			HttpIngressKey(0): allowEntry(12345, nil),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():          allowEntry(0),
			testIngressKey(41, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(41)),
			HttpIngressKey(0):        allowEntry(12345, nil),
			HttpIngressKey(41):       denyEntry(0).WithOwners(testIngressKey(41, 0, 0)),
		}),
		adds: Keys{
			testIngressKey(41, 0, 0): {},
			HttpIngressKey(41):       {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1b - Adding 2nd identity",
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():          allowEntry(0),
			testIngressKey(41, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(41)),
			testIngressKey(42, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(42)),
			HttpIngressKey(0):        allowEntry(12345, nil),
			HttpIngressKey(41):       denyEntry(0).WithOwners(testIngressKey(41, 0, 0)),
			HttpIngressKey(42):       denyEntry(0).WithOwners(testIngressKey(42, 0, 0)),
		}),
		adds: Keys{
			testIngressKey(42, 0, 0): {},
			HttpIngressKey(42):       {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1c - Removing the same key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{42}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():          allowEntry(0),
			testIngressKey(41, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(41)),
			HttpIngressKey(0):        allowEntry(12345, nil),
			HttpIngressKey(41):       denyEntry(0).WithOwners(testIngressKey(41, 0, 0)),
		}),
		adds: Keys{},
		deletes: Keys{
			testIngressKey(42, 0, 0): {},
			HttpIngressKey(42):       {},
		},
	}, {
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): denyEntry(0, csFoo),
			HttpIngressKey(43): denyEntry(0, csFoo),
		}),
		adds: Keys{
			HttpIngressKey(42): {},
			HttpIngressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2b - Adding Bar also selecting 42",
		args: []args{
			{cs: csBar, adds: []int{42, 44}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): denyEntry(0, csFoo, csBar),
			HttpIngressKey(43): denyEntry(0, csFoo),
			HttpIngressKey(44): denyEntry(0, csBar),
		}),
		adds: Keys{
			HttpIngressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2c - Deleting 42 from Foo, remains on Bar and no deletes",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): denyEntry(0, csBar),
			HttpIngressKey(43): denyEntry(0, csFoo),
			HttpIngressKey(44): denyEntry(0, csBar),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2d - Deleting 42 from Foo again, not deleted",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): denyEntry(0, csBar),
			HttpIngressKey(43): denyEntry(0, csFoo),
			HttpIngressKey(44): denyEntry(0, csBar),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2e - Deleting 42 from Bar, deleted",
		args: []args{
			{cs: csBar, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(43): denyEntry(0, csFoo),
			HttpIngressKey(44): denyEntry(0, csBar),
		}),
		adds: Keys{},
		deletes: Keys{
			HttpIngressKey(42): {},
		},
	}, {
		continued: true,
		name:      "test-2f - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(43): denyEntry(0, csFoo),
			HttpIngressKey(44): denyEntry(0, csBar),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-3a - egress allow with deny-L3",
		setup: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():         allowEntry(0),
			HostIngressKey():        allowEntry(0),
			testEgressKey(42, 0, 0): denyEntry(0, csFoo),
		}),
		args: []args{
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():         allowEntry(0),
			HostIngressKey():        allowEntry(0),
			testEgressKey(42, 0, 0): denyEntry(0, csFoo),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-3b - egress allow DNS on another ID with deny-L3",
		args: []args{
			{cs: csBar, adds: []int{43}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{43}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():         allowEntry(0),
			HostIngressKey():        allowEntry(0),
			testEgressKey(42, 0, 0): denyEntry(0, csFoo),
			DNSUDPEgressKey(43):     allowEntry(0, csBar),
			DNSTCPEgressKey(43):     allowEntry(0, csBar),
		}),
		adds: Keys{
			DNSUDPEgressKey(43): {},
			DNSTCPEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-3c - egress allow HTTP proxy with deny-L3",
		args: []args{
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():         allowEntry(0),
			HostIngressKey():        allowEntry(0),
			testEgressKey(42, 0, 0): denyEntry(0, csFoo),
			DNSUDPEgressKey(43):     allowEntry(0, csBar),
			DNSTCPEgressKey(43):     allowEntry(0, csBar),
			HttpEgressKey(43):       allowEntry(1, csFoo),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-4a - Add L7 skipped due to covering L3 deny",
		setup: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():         allowEntry(0),
			HostIngressKey():        allowEntry(0),
			testEgressKey(42, 0, 0): denyEntry(0, csFoo),
		}),
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():         allowEntry(0),
			HostIngressKey():        allowEntry(0),
			testEgressKey(42, 0, 0): denyEntry(0, csFoo),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-4b - Add & delete L7 skipped due to covering L3 deny",
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():         allowEntry(0),
			HostIngressKey():        allowEntry(0),
			testEgressKey(42, 0, 0): denyEntry(0, csFoo),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		name: "test-5 - Adding L3-deny to an existing allow-all",
		setup: newMapState(map[Key]MapStateEntry{
			AnyIngressKey(): allowEntry(0),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():          allowEntry(0),
			testIngressKey(41, 0, 0): denyEntry(0, csFoo),
		}),
		adds: Keys{
			testIngressKey(41, 0, 0): {},
		},
		deletes: Keys{},
	}, {
		name: "test-6 - Multiple dependent entries",
		setup: newMapState(map[Key]MapStateEntry{
			AnyEgressKey():     allowEntry(0),
			HttpEgressKey(0):   allowEntry(12345, nil),
			DNSUDPEgressKey(0): allowEntry(12346, nil),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: false, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyEgressKey():          allowEntry(0),
			testEgressKey(41, 0, 0): denyEntry(0, csFoo).WithDependents(HttpEgressKey(41), DNSUDPEgressKey(41)),
			HttpEgressKey(0):        allowEntry(12345, nil),
			HttpEgressKey(41):       denyEntry(0).WithOwners(testEgressKey(41, 0, 0)),
			DNSUDPEgressKey(0):      allowEntry(12346, nil),
			DNSUDPEgressKey(41):     denyEntry(0).WithOwners(testEgressKey(41, 0, 0)),
		}),
		adds: Keys{
			testEgressKey(41, 0, 0): {},
			HttpEgressKey(41):       {},
			DNSUDPEgressKey(41):     {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(nil),
		adds:  Keys{
			//HttpIngressKey(42): allowEntry(0),
		},
		deletes: Keys{
			//HttpIngressKey(43): allowEntry(0),
		},
	},
	}

	policyMapState := newMapState(nil)

	for _, tt := range tests {
		policyMaps := MapChanges{}
		if !tt.continued {
			if tt.setup != nil {
				policyMapState = tt.setup
			} else {
				policyMapState = newMapState(nil)
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
			key := Key{DestPort: x.port, Nexthdr: x.proto, TrafficDirection: dir.Uint8()}
			value := NewMapStateEntry(cs, nil, x.redirect, x.deny, DefaultAuthType, AuthTypeDisabled)
			policyMaps.AccumulateMapChanges(cs, adds, deletes, key, value)
		}
		adds, deletes := policyMaps.consumeMapChanges(policyMapState, denyRules, nil)
		policyMapState.validatePortProto(c)
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
		hasAuth  HasAuthType
		authType AuthType
	}
	tests := []struct {
		continued bool // Start from the end state of the previous test
		name      string
		args      []args // changes applied, in order
		state     MapState
		adds      Keys
		deletes   Keys
	}{{
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): allowEntry(0, csFoo),
			HttpIngressKey(43): allowEntry(0, csFoo),
		}),
		adds: Keys{
			HttpIngressKey(42): {},
			HttpIngressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2b - Adding Bar also selecting 42",
		args: []args{
			{cs: csBar, adds: []int{42, 44}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): allowEntry(0, csFoo, csBar),
			HttpIngressKey(43): allowEntry(0, csFoo),
			HttpIngressKey(44): allowEntry(0, csBar),
		}),
		adds: Keys{
			HttpIngressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2c - Deleting 42 from Foo, remains on Bar and no deletes",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): allowEntry(0, csBar),
			HttpIngressKey(43): allowEntry(0, csFoo),
			HttpIngressKey(44): allowEntry(0, csBar),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2d - Deleting 42 from Foo again, not deleted",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(42): allowEntry(0, csBar),
			HttpIngressKey(43): allowEntry(0, csFoo),
			HttpIngressKey(44): allowEntry(0, csBar),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2e - Deleting 42 from Bar, deleted",
		args: []args{
			{cs: csBar, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(43): allowEntry(0, csFoo),
			HttpIngressKey(44): allowEntry(0, csBar),
		}),
		adds: Keys{},
		deletes: Keys{
			HttpIngressKey(42): {},
		},
	}, {
		continued: true,
		name:      "test-2f - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpIngressKey(43): allowEntry(0, csFoo),
			HttpIngressKey(44): allowEntry(0, csBar),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-3a - egress HTTP proxy (setup)",
		args: []args{
			{cs: nil, adds: []int{0}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
			{cs: nil, adds: []int{1}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():     allowEntry(0, nil),
			HostIngressKey():    allowEntry(0, nil),
			DNSUDPEgressKey(42): allowEntry(0, csBar),
			DNSTCPEgressKey(42): allowEntry(0, csBar),
		}),
		adds: Keys{
			AnyIngressKey():     {},
			HostIngressKey():    {},
			DNSUDPEgressKey(42): {},
			DNSTCPEgressKey(42): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-3b - egress HTTP proxy (incremental update)",
		args: []args{
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():     allowEntry(0, nil),
			HostIngressKey():    allowEntry(0, nil),
			DNSUDPEgressKey(42): allowEntry(0, csBar),
			DNSTCPEgressKey(42): allowEntry(0, csBar),
			HttpEgressKey(43):   allowEntry(1, csFoo),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-4a - Add & delete; delete cancels the add in reply",
		args: []args{
			{cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
			{cs: csFoo, adds: []int{}, deletes: []int{44}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: newMapState(nil),
		adds:  Keys{},
		deletes: Keys{
			// Delete of the key is recoded as the key may have existed already in the (bpf) map
			HttpEgressKey(44): {},
		},
	}, {
		continued: true,
		name:      "test-4b - Add, delete, & add; delete suppressed",
		args: []args{
			{cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
			{cs: csFoo, adds: []int{}, deletes: []int{44}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
			{cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			HttpEgressKey(44): allowEntry(1, csFoo),
		}),
		adds: Keys{
			HttpEgressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(nil),
		adds:  Keys{
			//HttpIngressKey(42): allowEntry(0),
		},
		deletes: Keys{
			//HttpIngressKey(43): allowEntry(0),
		},
	},
	}

	policyMapState := newMapState(nil)

	for _, tt := range tests {
		policyMaps := MapChanges{}
		if !tt.continued {
			policyMapState = newMapState(nil)
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
			key := Key{DestPort: x.port, Nexthdr: x.proto, TrafficDirection: dir.Uint8()}
			value := NewMapStateEntry(cs, nil, x.redirect, x.deny, x.hasAuth, x.authType)
			policyMaps.AccumulateMapChanges(cs, adds, deletes, key, value)
		}
		adds, deletes := policyMaps.consumeMapChanges(policyMapState, policyFeatures(0), nil)
		policyMapState.validatePortProto(c)
		c.Assert(policyMapState, checker.DeepEquals, tt.state, check.Commentf(tt.name+" (MapState)"))
		c.Assert(adds, checker.DeepEquals, tt.adds, check.Commentf(tt.name+" (adds)"))
		c.Assert(deletes, checker.DeepEquals, tt.deletes, check.Commentf(tt.name+" (deletes)"))
	}
}

var testLabels = labels.LabelArray{
	labels.NewLabel("test", "ing", labels.LabelSourceReserved),
}

func (ds *PolicyTestSuite) TestMapState_AddVisibilityKeys(c *check.C) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	type args struct {
		redirectPort uint16
		visMeta      VisibilityMetadata
	}
	tests := []struct {
		name     string
		ms, want *mapState
		args     args
	}{
		{
			name: "test-1 - Add HTTP ingress visibility - allow-all",
			ms: newMapState(map[Key]MapStateEntry{
				AnyIngressKey(): allowEntry(0),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				AnyIngressKey():   allowEntry(0),
				HttpIngressKey(0): allowEntryD(12345, visibilityDerivedFrom, nil),
			}),
		},
		{
			name: "test-2 - Add HTTP ingress visibility - no allow-all",
			ms:   newMapState(nil),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(nil),
		},
		{
			name: "test-3 - Add HTTP ingress visibility - L4-allow",
			ms: newMapState(map[Key]MapStateEntry{
				HttpIngressKey(0): allowEntryD(0, labels.LabelArrayList{testLabels}),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				HttpIngressKey(0): allowEntryD(12345, labels.LabelArrayList{visibilityDerivedFromLabels, testLabels}, nil),
			}),
		},
		{
			name: "test-4 - Add HTTP ingress visibility - L3/L4-allow",
			ms: newMapState(map[Key]MapStateEntry{
				HttpIngressKey(123): allowEntryD(0, labels.LabelArrayList{testLabels}, csBar),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				HttpIngressKey(123): allowEntryD(12345, labels.LabelArrayList{visibilityDerivedFromLabels, testLabels}, csBar),
			}),
		},
		{
			name: "test-5 - Add HTTP ingress visibility - L3-allow (host)",
			ms: newMapState(map[Key]MapStateEntry{
				HostIngressKey(): allowEntry(0),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				HostIngressKey():  allowEntry(0).WithDependents(HttpIngressKey(1)),
				HttpIngressKey(1): allowEntryD(12345, labels.LabelArrayList{visibilityDerivedFromLabels}).WithOwners(HostIngressKey()),
			}),
		},
		{
			name: "test-6 - Add HTTP ingress visibility - L3/L4-allow on different port",
			ms: newMapState(map[Key]MapStateEntry{
				testIngressKey(123, 88, 6): allowEntryD(0, labels.LabelArrayList{testLabels}, csBar),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				testIngressKey(123, 88, 6): allowEntryD(0, labels.LabelArrayList{testLabels}, csBar),
			}),
		},
		{
			name: "test-7 - Add HTTP ingress visibility - allow-all + L4-deny (no change)",
			ms: newMapState(map[Key]MapStateEntry{
				AnyIngressKey():   allowEntry(0),
				HttpIngressKey(0): denyEntry(0),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				AnyIngressKey():   allowEntry(0),
				HttpIngressKey(0): denyEntry(0),
			}),
		},
		{
			name: "test-8 - Add HTTP ingress visibility - allow-all + L3-deny",
			ms: newMapState(map[Key]MapStateEntry{
				AnyIngressKey():           allowEntry(0),
				testIngressKey(234, 0, 0): denyEntry(0, csFoo),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				AnyIngressKey():           allowEntry(0),
				testIngressKey(234, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(234)),
				HttpIngressKey(0):         allowEntryD(12345, visibilityDerivedFrom, nil),
				HttpIngressKey(234):       denyEntry(0, csFoo).WithOwners(testIngressKey(234, 0, 0)),
			}),
		},
		{
			name: "test-9 - Add HTTP ingress visibility - allow-all + L3/L4-deny",
			ms: newMapState(map[Key]MapStateEntry{
				AnyIngressKey():     allowEntry(0),
				HttpIngressKey(132): denyEntry(0, csBar),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				AnyIngressKey():     allowEntry(0),
				HttpIngressKey(132): denyEntry(0, csBar),
				HttpIngressKey(0):   allowEntryD(12345, visibilityDerivedFrom, nil),
			}),
		},
		{
			name: "test-10 - Add HTTP egress visibility",
			ms: newMapState(map[Key]MapStateEntry{
				AnyEgressKey(): allowEntry(0),
			}),
			args: args{
				redirectPort: 12346,
				visMeta:      VisibilityMetadata{Ingress: false, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(map[Key]MapStateEntry{
				AnyEgressKey():   allowEntry(0),
				HttpEgressKey(0): allowEntryD(12346, visibilityDerivedFrom, nil),
			}),
		},
	}
	for _, tt := range tests {
		old := newMapState(nil)
		tt.ms.ForEach(func(k Key, v MapStateEntry) bool {
			old.InsertIfNotExists(k, v)
			return true
		})
		changes := ChangeState{
			Adds: make(Keys),
			Old:  newMapState(nil),
		}
		tt.ms.AddVisibilityKeys(DummyOwner{}, tt.args.redirectPort, &tt.args.visMeta, changes)
		tt.ms.validatePortProto(c)
		c.Assert(tt.ms.allows, checker.DeepEquals, tt.want.allows, check.Commentf(tt.name))
		c.Assert(tt.ms.denies, checker.DeepEquals, tt.want.denies, check.Commentf(tt.name))
		// Find new and updated entries
		wantAdds := make(Keys)
		wantOld := newMapState(nil)

		old.ForEach(func(k Key, v MapStateEntry) bool {
			if _, ok := tt.ms.Get(k); !ok {
				wantOld.Insert(k, v)
			}
			return true
		})
		tt.ms.ForEach(func(k Key, v MapStateEntry) bool {
			if v2, ok := old.Get(k); ok {
				if equals, _ := checker.DeepEqual(v2, v); !equals {
					wantOld.Insert(k, v2)
				}
			} else {
				wantAdds[k] = struct{}{}
			}
			return true
		})
		c.Assert(changes.Adds, checker.DeepEquals, wantAdds, check.Commentf(tt.name))
		c.Assert(changes.Old, checker.DeepEquals, wantOld, check.Commentf(tt.name))
	}
}

func (ds *PolicyTestSuite) TestMapState_AccumulateMapChangesOnVisibilityKeys(c *check.C) {
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
	type visArgs struct {
		redirectPort uint16
		visMeta      VisibilityMetadata
	}
	tests := []struct {
		continued bool // Start from the end state of the previous test
		name      string
		setup     *mapState
		visArgs   []visArgs
		visAdds   Keys
		visOld    MapState
		args      []args // changes applied, in order
		state     MapState
		adds      Keys
		deletes   Keys
	}{{
		name: "test-1a - Adding identity to deny with visibilty",
		setup: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():           allowEntry(0),
			testIngressKey(234, 0, 0): denyEntry(0, csFoo),
		}),
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		visAdds: Keys{
			HttpIngressKey(0):   {},
			HttpIngressKey(234): {},
		},
		visOld: newMapState(map[Key]MapStateEntry{
			testIngressKey(234, 0, 0): denyEntry(0, csFoo),
		}),
		args: []args{
			{cs: csFoo, adds: []int{235}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():           allowEntry(0),
			testIngressKey(234, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(234)),
			testIngressKey(235, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(235)),
			HttpIngressKey(0):         allowEntryD(12345, visibilityDerivedFrom, nil),
			HttpIngressKey(234):       denyEntry(0).WithOwners(testIngressKey(234, 0, 0)),
			HttpIngressKey(235):       denyEntry(0).WithOwners(testIngressKey(235, 0, 0)),
		}),
		adds: Keys{
			testIngressKey(235, 0, 0): {},
			HttpIngressKey(235):       {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1b - Removing the sole key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{235}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():           allowEntry(0),
			testIngressKey(234, 0, 0): denyEntry(0, csFoo).WithDependents(HttpIngressKey(234)),
			HttpIngressKey(0):         allowEntryD(12345, visibilityDerivedFrom, nil),
			HttpIngressKey(234):       denyEntry(0).WithOwners(testIngressKey(234, 0, 0)),
		}),
		adds: Keys{},
		deletes: Keys{
			testIngressKey(235, 0, 0): {},
			HttpIngressKey(235):       {},
		},
	}, {
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{235, 236}, deletes: []int{50}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: newMapState(map[Key]MapStateEntry{
			testIngressKey(235, 0, 0): allowEntry(0, csFoo).WithDependents(HttpIngressKey(235)),
			testIngressKey(236, 0, 0): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(235, 0, 0)),
			HttpIngressKey(236):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(236, 0, 0)),
		}),
		adds: Keys{
			testIngressKey(235, 0, 0): {},
			HttpIngressKey(235):       {},
			testIngressKey(236, 0, 0): {},
			HttpIngressKey(236):       {},
		},
		deletes: Keys{
			testIngressKey(235, 0, 0): {}, // changed dependents
			testIngressKey(236, 0, 0): {}, // changed dependents
		},
	}, {
		continued: true,
		name:      "test-2b - Adding Bar also selecting 235",
		args: []args{
			{cs: csBar, adds: []int{235, 237}, deletes: []int{50}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: newMapState(map[Key]MapStateEntry{
			testIngressKey(235, 0, 0): allowEntry(0, csFoo, csBar).WithDependents(HttpIngressKey(235)),
			testIngressKey(236, 0, 0): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(235, 0, 0)),
			HttpIngressKey(236):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(236, 0, 0)),
			testIngressKey(237, 0, 0): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(237, 0, 0)),
		}),
		adds: Keys{
			testIngressKey(237, 0, 0): {},
			HttpIngressKey(237):       {},
		},
		deletes: Keys{
			testIngressKey(237, 0, 0): {}, // changed dependents
		},
	}, {
		continued: true,
		name:      "test-2c - Deleting 235 from Foo, remains on Bar and no deletes",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{235}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: newMapState(map[Key]MapStateEntry{
			testIngressKey(235, 0, 0): allowEntry(0, csBar).WithDependents(HttpIngressKey(235)),
			testIngressKey(236, 0, 0): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(235, 0, 0)),
			HttpIngressKey(236):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(236, 0, 0)),
			testIngressKey(237, 0, 0): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(237, 0, 0)),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2d - Deleting 235 from Foo again, not deleted",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{235}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: newMapState(map[Key]MapStateEntry{
			testIngressKey(235, 0, 0): allowEntry(0, csBar).WithDependents(HttpIngressKey(235)),
			testIngressKey(236, 0, 0): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(235, 0, 0)),
			HttpIngressKey(236):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(236, 0, 0)),
			testIngressKey(237, 0, 0): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(237, 0, 0)),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2e - Deleting 235 from Bar, deleted",
		args: []args{
			{cs: csBar, adds: []int{}, deletes: []int{235}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: newMapState(map[Key]MapStateEntry{
			testIngressKey(236, 0, 0): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(236):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(236, 0, 0)),
			testIngressKey(237, 0, 0): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(237, 0, 0)),
		}),
		adds: Keys{},
		deletes: Keys{
			testIngressKey(235, 0, 0): {},
			HttpIngressKey(235):       {},
		},
	}, {
		continued: true,
		name:      "test-2f - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{237}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: newMapState(map[Key]MapStateEntry{
			testIngressKey(236, 0, 0): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(236):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(236, 0, 0)),
			testIngressKey(237, 0, 0): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):       allowEntryD(12345, visibilityDerivedFrom).WithOwners(testIngressKey(237, 0, 0)),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-3a - egress HTTP proxy (setup)",
		setup: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():  allowEntry(0),
			HostIngressKey(): allowEntry(0),
			HttpEgressKey(0): allowEntry(0),
		}),
		visArgs: []visArgs{
			{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12346,
				visMeta:      VisibilityMetadata{Ingress: false, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12347,
				visMeta:      VisibilityMetadata{Ingress: false, Port: 53, Proto: u8proto.UDP},
			},
		},
		visAdds: Keys{
			HttpIngressKey(0): {},
		},
		visOld: newMapState(map[Key]MapStateEntry{
			// Old value for the modified entry
			HttpEgressKey(0): allowEntry(0),
		}),
		args: []args{
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():  allowEntry(0),
			HostIngressKey(): allowEntry(0),
			// Entry added solely due to visibility annotation has a 'nil' owner
			HttpIngressKey(0): allowEntryD(12345, visibilityDerivedFrom).WithOwners(nil),
			// Entries modified due to visibility annotation keep their existing owners (here none)
			HttpEgressKey(0):    allowEntryD(12346, visibilityDerivedFrom, nil),
			DNSUDPEgressKey(42): allowEntryD(12347, visibilityDerivedFrom, csBar),
			DNSTCPEgressKey(42): allowEntry(0, csBar),
		}),
		adds: Keys{
			DNSUDPEgressKey(42): {},
			DNSTCPEgressKey(42): {},
		},
		deletes: Keys{
			// AddVisibilityKeys() returns overwritten entries in 'deletes'
			DNSUDPEgressKey(42): {},
		},
	}, {
		continued: true,
		name:      "test-3b - egress HTTP proxy (incremental update)",
		args: []args{
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		visArgs: []visArgs{
			{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12346,
				visMeta:      VisibilityMetadata{Ingress: false, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12347,
				visMeta:      VisibilityMetadata{Ingress: false, Port: 53, Proto: u8proto.UDP},
			},
		},
		state: newMapState(map[Key]MapStateEntry{
			AnyIngressKey():     allowEntry(0),
			HostIngressKey():    allowEntry(0),
			HttpIngressKey(0):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(nil),
			HttpEgressKey(0):    allowEntryD(12346, visibilityDerivedFrom, nil),
			DNSUDPEgressKey(42): allowEntryD(12347, visibilityDerivedFrom, csBar),
			DNSTCPEgressKey(42): allowEntry(0, csBar),
			// Redirect entries are not modified by visibility annotations
			HttpEgressKey(43): allowEntry(1, csFoo),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(nil),
		adds:  Keys{
			//HttpIngressKey(42): {},
		},
		deletes: Keys{
			//HttpIngressKey(43): {},
		},
	},
	}

	policyMapState := newMapState(nil)

	for _, tt := range tests {
		// Allow omit empty maps
		if tt.visAdds == nil {
			tt.visAdds = make(Keys)
		}
		if tt.visOld == nil {
			tt.visOld = newMapState(nil)
		}
		if tt.adds == nil {
			tt.adds = make(Keys)
		}
		if tt.deletes == nil {
			tt.deletes = make(Keys)
		}
		policyMaps := MapChanges{}
		if !tt.continued {
			if tt.setup != nil {
				policyMapState = tt.setup
			} else {
				policyMapState = newMapState(nil)
			}
		}
		changes := ChangeState{
			Adds:    make(Keys),
			Deletes: make(Keys),
			Old:     newMapState(nil),
		}
		for _, arg := range tt.visArgs {
			policyMapState.AddVisibilityKeys(DummyOwner{}, arg.redirectPort, &arg.visMeta, changes)
		}
		c.Assert(changes.Adds, checker.DeepEquals, tt.visAdds, check.Commentf(tt.name+" (visAdds)"))
		c.Assert(changes.Old, checker.DeepEquals, tt.visOld, check.Commentf(tt.name+" (visOld)"))

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
			key := Key{DestPort: x.port, Nexthdr: x.proto, TrafficDirection: dir.Uint8()}
			value := NewMapStateEntry(cs, nil, x.redirect, x.deny, DefaultAuthType, AuthTypeDisabled)
			policyMaps.AccumulateMapChanges(cs, adds, deletes, key, value)
		}
		adds, deletes := policyMaps.consumeMapChanges(policyMapState, denyRules, nil)
		changes = ChangeState{
			Adds:    adds,
			Deletes: deletes,
			Old:     newMapState(nil),
		}

		// Visibilty redirects need to be re-applied after consumeMapChanges()
		for _, arg := range tt.visArgs {
			policyMapState.AddVisibilityKeys(DummyOwner{}, arg.redirectPort, &arg.visMeta, changes)
		}
		changes.Old.ForEach(func(k Key, _ MapStateEntry) bool {
			changes.Deletes[k] = struct{}{}
			return true
		})
		policyMapState.validatePortProto(c)
		c.Assert(policyMapState, checker.DeepEquals, tt.state, check.Commentf(tt.name+" (MapState)"))
		c.Assert(changes.Adds, checker.DeepEquals, tt.adds, check.Commentf(tt.name+" (adds)"))
		c.Assert(changes.Deletes, checker.DeepEquals, tt.deletes, check.Commentf(tt.name+" (deletes)"))
	}
}

func (ds *PolicyTestSuite) TestMapState_denyPreferredInsertWithSubnets(c *check.C) {
	identityCache := cache.IdentityCache{
		identity.ReservedIdentityWorld: labels.LabelWorld.LabelArray(),
		worldIPIdentity:                lblWorldIP,                  // "192.0.2.3/32"
		worldSubnetIdentity:            lblWorldSubnet.LabelArray(), // "192.0.2.0/24"
	}

	reservedWorldID := identity.ReservedIdentityWorld.Uint32()
	worldIPID := worldIPIdentity.Uint32()
	worldSubnetID := worldSubnetIdentity.Uint32()
	selectorCache := testNewSelectorCache(identityCache)
	type action uint16
	const (
		noAction = action(iota)
		insertA  = action(1 << iota)
		insertB
		insertAWithBProto
		insertBWithAProto

		insertBoth            = insertA | insertB
		canDeleteAInsertsBoth = insertBoth
		canDeleteBInsertsBoth = insertBoth
	)
	// these tests are based on the sheet https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw#gid=2109052536
	tests := []struct {
		name                 string
		aIdentity, bIdentity uint32
		aIsDeny, bIsDeny     bool
		aPort                uint16
		aProto               uint8
		bPort                uint16
		bProto               uint8
		outcome              action
	}{
		// deny-allow insertions
		{"deny-allow: a superset a|b L3-only", reservedWorldID, worldSubnetID, true, false, 0, 0, 0, 0, insertA},
		{"deny-allow: b superset a|b L3-only", worldIPID, worldSubnetID, true, false, 0, 0, 0, 0, insertBoth},
		{"deny-allow: a superset a L3-only, b L4", reservedWorldID, worldSubnetID, true, false, 0, 0, 0, 6, insertA},
		{"deny-allow: b superset a L3-only, b L4", worldIPID, worldSubnetID, true, false, 0, 0, 0, 6, insertBoth | insertAWithBProto},
		{"deny-allow: a superset a L3-only, b L3L4", reservedWorldID, worldSubnetID, true, false, 0, 0, 80, 6, insertA},
		{"deny-allow: b superset a L3-only, b L3L4", worldIPID, worldSubnetID, true, false, 0, 0, 80, 6, insertBoth | insertAWithBProto},
		{"deny-allow: a superset a L4, b L3-only", reservedWorldID, worldSubnetID, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: b superset a L4, b L3-only", worldIPID, worldSubnetID, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L4, b L4", reservedWorldID, worldSubnetID, true, false, 0, 6, 0, 6, insertA},
		{"deny-allow: b superset a L4, b L4", worldIPID, worldSubnetID, true, false, 0, 6, 0, 6, insertBoth},
		{"deny-allow: a superset a L4, b L3L4", reservedWorldID, worldSubnetID, true, false, 0, 6, 80, 6, insertA},
		{"deny-allow: b superset a L4, b L3L4", worldIPID, worldSubnetID, true, false, 0, 6, 80, 6, insertBoth | insertAWithBProto},
		{"deny-allow: a superset a L3L4, b L3-only", reservedWorldID, worldSubnetID, true, false, 80, 6, 0, 0, insertBoth},
		{"deny-allow: b superset a L3L4, b L3-only", worldIPID, worldSubnetID, true, false, 80, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L3L4, b L4", reservedWorldID, worldSubnetID, true, false, 80, 6, 0, 6, insertBoth},
		{"deny-allow: b superset a L3L4, b L4", worldIPID, worldSubnetID, true, false, 80, 6, 0, 6, insertBoth},
		{"deny-allow: a superset a L3L4, b L3L4", reservedWorldID, worldSubnetID, true, false, 80, 6, 80, 6, insertA},
		{"deny-allow: b superset a L3L4, b L3L4", worldIPID, worldSubnetID, true, false, 80, 6, 80, 6, insertBoth},

		// deny-deny insertions: Note: We do not delete all redundant deny-deny insertions that we could.
		// We only delete entries redundant to L3-only port protocols, all other port-protocol supersets
		// *do not* have this effect.
		{"deny-deny: a superset a|b L3-only", worldSubnetID, worldIPID, true, true, 0, 0, 0, 0, insertA},
		{"deny-deny: b superset a|b L3-only", worldSubnetID, reservedWorldID, true, true, 0, 0, 0, 0, insertB},
		{"deny-deny: a superset a L3-only, b L4", worldSubnetID, worldIPID, true, true, 0, 0, 0, 6, insertA},
		{"deny-deny: b superset a L3-only, b L4", worldSubnetID, reservedWorldID, true, true, 0, 0, 0, 6, insertBoth},
		{"deny-deny: a superset a L3-only, b L3L4", worldSubnetID, worldIPID, true, true, 0, 0, 80, 6, insertA},
		{"deny-deny: b superset a L3-only, b L3L4", worldSubnetID, reservedWorldID, true, true, 0, 0, 80, 6, insertBoth},
		{"deny-deny: a superset a L4, b L3-only", worldSubnetID, worldIPID, true, true, 0, 6, 0, 0, insertBoth},
		{"deny-deny: b superset a L4, b L3-only", worldSubnetID, reservedWorldID, true, true, 0, 6, 0, 0, insertB},
		{"deny-deny: a superset a L4, b L4", worldSubnetID, worldIPID, true, true, 0, 6, 0, 6, canDeleteBInsertsBoth},
		{"deny-deny: b superset a L4, b L4", worldSubnetID, reservedWorldID, true, true, 0, 6, 0, 6, canDeleteAInsertsBoth},
		{"deny-deny: a superset a L4, b L3L4", worldSubnetID, worldIPID, true, true, 0, 6, 80, 6, canDeleteBInsertsBoth},
		{"deny-deny: b superset a L4, b L3L4", worldSubnetID, reservedWorldID, true, true, 0, 6, 80, 6, insertBoth},
		{"deny-deny: a superset a L3L4, b L3-only", worldSubnetID, worldIPID, true, true, 80, 6, 0, 0, insertBoth},
		{"deny-deny: b superset a L3L4, b L3-only", worldSubnetID, reservedWorldID, true, true, 80, 6, 0, 0, insertB},
		{"deny-deny: a superset a L3L4, b L4", worldSubnetID, worldIPID, true, true, 80, 6, 0, 6, insertBoth},
		{"deny-deny: b superset a L3L4, b L4", worldSubnetID, reservedWorldID, true, true, 80, 6, 0, 6, canDeleteAInsertsBoth},
		{"deny-deny: a superset a L3L4, b L3L4", worldSubnetID, worldIPID, true, true, 80, 6, 80, 6, canDeleteBInsertsBoth},
		{"deny-deny: b superset a L3L4, b L3L4", worldSubnetID, reservedWorldID, true, true, 80, 6, 80, 6, canDeleteAInsertsBoth},
		// allow-allow insertions do not need to be tests as they will all be inserted
	}
	for _, tt := range tests {
		aKey := Key{Identity: tt.aIdentity, DestPort: tt.aPort, Nexthdr: tt.aProto}
		aEntry := MapStateEntry{IsDeny: tt.aIsDeny}
		bKey := Key{Identity: tt.bIdentity, DestPort: tt.bPort, Nexthdr: tt.bProto}
		bEntry := MapStateEntry{IsDeny: tt.bIsDeny}
		expectedKeys := newMapState(nil)
		if tt.outcome&insertA > 0 {
			if tt.aIsDeny {
				expectedKeys.denies[aKey] = aEntry
			} else {
				expectedKeys.allows[aKey] = aEntry
			}
		}
		if tt.outcome&insertB > 0 {
			if tt.bIsDeny {
				expectedKeys.denies[bKey] = bEntry
			} else {
				expectedKeys.allows[bKey] = bEntry
			}
		}
		if tt.outcome&insertAWithBProto > 0 {
			aKeyWithBProto := Key{Identity: tt.aIdentity, DestPort: tt.bPort, Nexthdr: tt.bProto}
			aEntryCpy := MapStateEntry{IsDeny: tt.aIsDeny}
			aEntryCpy.owners = map[MapStateOwner]struct{}{aKey: {}}
			aEntry.AddDependent(aKeyWithBProto)
			if tt.aIsDeny {
				expectedKeys.denies[aKey] = aEntry
				expectedKeys.denies[aKeyWithBProto] = aEntryCpy
			} else {
				expectedKeys.allows[aKey] = aEntry
				expectedKeys.allows[aKeyWithBProto] = aEntryCpy
			}
		}
		if tt.outcome&insertBWithAProto > 0 {
			bKeyWithBProto := Key{Identity: tt.bIdentity, DestPort: tt.aPort, Nexthdr: tt.aProto}
			bEntryCpy := MapStateEntry{IsDeny: tt.bIsDeny}
			bEntryCpy.owners = map[MapStateOwner]struct{}{bKey: {}}
			bEntry.AddDependent(bKeyWithBProto)
			if tt.bIsDeny {
				expectedKeys.denies[bKey] = bEntry
				expectedKeys.denies[bKeyWithBProto] = bEntryCpy
			} else {
				expectedKeys.allows[bKey] = bEntry
				expectedKeys.allows[bKeyWithBProto] = bEntryCpy
			}
		}
		outcomeKeys := newMapState(nil)
		outcomeKeys.denyPreferredInsert(aKey, aEntry, selectorCache, allFeatures)
		outcomeKeys.denyPreferredInsert(bKey, bEntry, selectorCache, allFeatures)
		outcomeKeys.validatePortProto(c)
		c.Assert(outcomeKeys, checker.DeepEquals, expectedKeys, check.Commentf(tt.name))
	}
	// Now test all cases with different traffic directions.
	// This should result in both entries being inserted with
	// no changes, as they do not affect one another anymore.
	for _, tt := range tests {
		aKey := Key{Identity: tt.aIdentity, DestPort: tt.aPort, Nexthdr: tt.aProto}
		aEntry := MapStateEntry{IsDeny: tt.aIsDeny}
		bKey := Key{Identity: tt.bIdentity, DestPort: tt.bPort, Nexthdr: tt.bProto, TrafficDirection: 1}
		bEntry := MapStateEntry{IsDeny: tt.bIsDeny}
		expectedKeys := newMapState(nil)
		if tt.aIsDeny {
			expectedKeys.denies[aKey] = aEntry
		} else {
			expectedKeys.allows[aKey] = aEntry
		}
		if tt.bIsDeny {
			expectedKeys.denies[bKey] = bEntry
		} else {
			expectedKeys.allows[bKey] = bEntry
		}
		outcomeKeys := newMapState(nil)
		outcomeKeys.denyPreferredInsert(aKey, aEntry, selectorCache, allFeatures)
		outcomeKeys.denyPreferredInsert(bKey, bEntry, selectorCache, allFeatures)
		outcomeKeys.validatePortProto(c)
		c.Assert(outcomeKeys, checker.DeepEquals, expectedKeys, check.Commentf("different traffic directions %s", tt.name))
	}
}
