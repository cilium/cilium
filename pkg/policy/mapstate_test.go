// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

func ingressKey(identity identity.NumericIdentity, proto u8proto.U8proto, port uint16, prefixLen uint8) Key {
	return IngressKey().WithIdentity(identity).WithPortProtoPrefix(proto, port, prefixLen)
}

func ingressL3OnlyKey(identity identity.NumericIdentity) Key {
	return IngressKey().WithIdentity(identity)
}

func egressKey(identity identity.NumericIdentity, proto u8proto.U8proto, port uint16, prefixLen uint8) Key {
	return EgressKey().WithIdentity(identity).WithPortProtoPrefix(proto, port, prefixLen)
}

func egressL3OnlyKey(identity identity.NumericIdentity) Key {
	return EgressKey().WithIdentity(identity)
}

func Test_IsSuperSetOf(t *testing.T) {
	tests := []struct {
		superSet Key
		subSet   Key
		res      int
	}{
		{ingressKey(0, 0, 0, 0), ingressKey(0, 0, 0, 0), 0},
		{ingressKey(0, 0, 0, 0), ingressKey(42, 6, 0, 0), 1},
		{ingressKey(0, 0, 0, 0), ingressKey(42, 6, 80, 0), 1},
		{ingressKey(0, 0, 0, 0), ingressKey(42, 0, 0, 0), 1},
		{ingressKey(0, 6, 0, 0), ingressKey(42, 6, 0, 0), 3}, // port is the same
		{ingressKey(0, 6, 0, 0), ingressKey(42, 6, 80, 0), 2},
		{ingressKey(0, 6, 64, 10), ingressKey(42, 6, 80, 0), 2}, // port range 64-127,80
		{ingressKey(0, 6, 80, 0), ingressKey(42, 6, 80, 0), 3},
		{ingressKey(0, 6, 64, 10), ingressKey(42, 6, 64, 10), 3},  // port ranges are the same
		{ingressKey(0, 6, 80, 0), ingressKey(42, 17, 80, 0), 0},   // proto is different
		{ingressKey(2, 6, 80, 0), ingressKey(42, 6, 80, 0), 0},    // id is different
		{ingressKey(0, 6, 8080, 0), ingressKey(42, 6, 80, 0), 0},  // port is different
		{ingressKey(0, 6, 64, 10), ingressKey(42, 6, 8080, 0), 0}, // port range is different from port
		{ingressKey(42, 0, 0, 0), ingressKey(42, 0, 0, 0), 0},     // same key
		{ingressKey(42, 0, 0, 0), ingressKey(42, 6, 0, 0), 4},
		{ingressKey(42, 0, 0, 0), ingressKey(42, 6, 80, 0), 4},
		{ingressKey(42, 0, 64, 10), ingressKey(42, 6, 80, 0), 4}, // port range 64-127,80
		{ingressKey(42, 0, 0, 0), ingressKey(42, 17, 0, 0), 4},
		{ingressKey(42, 0, 0, 0), ingressKey(42, 17, 80, 0), 4},
		{ingressKey(42, 0, 64, 10), ingressKey(42, 17, 80, 0), 4},
		{ingressKey(42, 6, 0, 0), ingressKey(42, 6, 0, 0), 0}, // same key
		{ingressKey(42, 6, 0, 0), ingressKey(42, 6, 80, 0), 5},
		{ingressKey(42, 6, 64, 10), ingressKey(42, 6, 80, 0), 5},
		{ingressKey(42, 6, 0, 0), ingressKey(42, 6, 8080, 0), 5},
		{ingressKey(42, 6, 80, 0), ingressKey(42, 6, 80, 0), 0},    // same key
		{ingressKey(42, 6, 64, 10), ingressKey(42, 6, 64, 10), 0},  // same key
		{ingressKey(42, 6, 80, 0), ingressKey(42, 6, 8080, 0), 0},  // different port
		{ingressKey(42, 6, 64, 10), ingressKey(42, 6, 128, 10), 0}, // different port ranges
		{ingressKey(42, 6, 80, 0), ingressKey(42, 17, 80, 0), 0},   // different proto
		{ingressKey(42, 6, 80, 0), ingressKey(42, 17, 8080, 0), 0}, // different port and proto

		// increasing specificity for a L3/L4 key
		{ingressKey(0, 0, 0, 0), ingressKey(42, 6, 80, 0), 1},
		{ingressKey(0, 0, 64, 10), ingressKey(42, 6, 80, 0), 1},
		{ingressKey(0, 6, 0, 0), ingressKey(42, 6, 80, 0), 2},
		{ingressKey(0, 6, 64, 10), ingressKey(42, 6, 80, 0), 2},
		{ingressKey(0, 6, 80, 0), ingressKey(42, 6, 80, 0), 3},
		{ingressKey(0, 6, 64, 10), ingressKey(42, 6, 64, 10), 3},
		{ingressKey(42, 0, 0, 0), ingressKey(42, 6, 80, 0), 4},
		{ingressKey(42, 0, 64, 10), ingressKey(42, 6, 80, 0), 4},
		{ingressKey(42, 6, 0, 0), ingressKey(42, 6, 80, 0), 5},
		{ingressKey(42, 6, 64, 10), ingressKey(42, 6, 80, 0), 5},
		{ingressKey(42, 6, 80, 0), ingressKey(42, 6, 80, 0), 0},   // same key
		{ingressKey(42, 6, 64, 10), ingressKey(42, 6, 64, 10), 0}, // same key

		// increasing specificity for a L3-only key
		{ingressKey(0, 0, 0, 0), ingressKey(42, 0, 0, 0), 1},
		{ingressKey(0, 0, 64, 10), ingressKey(42, 0, 0, 0), 1},
		{ingressKey(0, 6, 0, 0), ingressKey(42, 0, 0, 0), 0},      // not a superset
		{ingressKey(0, 6, 80, 0), ingressKey(42, 0, 0, 0), 0},     // not a superset
		{ingressKey(0, 6, 64, 10), ingressKey(42, 0, 0, 0), 0},    // not a superset
		{ingressKey(42, 0, 0, 0), ingressKey(42, 0, 0, 0), 0},     // same key
		{ingressKey(42, 6, 0, 0), ingressKey(42, 0, 0, 0), 0},     // not a superset
		{ingressKey(42, 6, 64, 10), ingressKey(42, 0, 64, 10), 0}, // not a superset
		{ingressKey(42, 6, 80, 0), ingressKey(42, 0, 0, 0), 0},    // not a superset
		{ingressKey(42, 6, 64, 10), ingressKey(42, 0, 0, 0), 0},   // not a superset

		// increasing specificity for a L3/proto key
		{ingressKey(0, 0, 0, 0), ingressKey(42, 6, 0, 0), 1}, // wildcard
		{ingressKey(0, 0, 64, 10), ingressKey(42, 6, 64, 10), 1},
		{ingressKey(0, 6, 0, 0), ingressKey(42, 6, 0, 0), 3},     // ports are the same
		{ingressKey(0, 6, 64, 10), ingressKey(42, 6, 64, 10), 3}, // port ranges are the same
		{ingressKey(0, 6, 80, 0), ingressKey(42, 6, 0, 0), 0},    // not a superset
		{ingressKey(0, 6, 80, 0), ingressKey(42, 6, 64, 10), 0},  // not a superset
		{ingressKey(42, 0, 0, 0), ingressKey(42, 6, 0, 0), 4},
		{ingressKey(42, 0, 64, 10), ingressKey(42, 6, 64, 10), 4},
		{ingressKey(42, 6, 0, 0), ingressKey(42, 6, 0, 0), 0},     // same key
		{ingressKey(42, 6, 64, 10), ingressKey(42, 6, 64, 10), 0}, // same key
		{ingressKey(42, 6, 80, 0), ingressKey(42, 6, 0, 0), 0},    // not a superset
		{ingressKey(42, 6, 80, 0), ingressKey(42, 6, 64, 10), 0},  // not a superset

		// increasing specificity for a proto-only key
		{ingressKey(0, 0, 0, 0), ingressKey(0, 6, 0, 0), 1},
		{ingressKey(0, 0, 64, 10), ingressKey(0, 6, 64, 10), 1},
		{ingressKey(0, 6, 0, 0), ingressKey(0, 6, 0, 0), 0},      // same key
		{ingressKey(0, 6, 64, 10), ingressKey(0, 6, 64, 10), 0},  // same key
		{ingressKey(0, 6, 80, 0), ingressKey(0, 6, 0, 0), 0},     // not a superset
		{ingressKey(0, 6, 80, 0), ingressKey(0, 6, 64, 10), 0},   // not a superset
		{ingressKey(42, 0, 0, 0), ingressKey(0, 6, 0, 0), 0},     // not a superset
		{ingressKey(42, 0, 64, 10), ingressKey(0, 6, 64, 10), 0}, // not a superset
		{ingressKey(42, 6, 0, 0), ingressKey(0, 6, 0, 0), 0},     // not a superset
		{ingressKey(42, 6, 64, 10), ingressKey(0, 6, 64, 10), 0}, // not a superset
		{ingressKey(42, 6, 80, 0), ingressKey(0, 6, 0, 0), 0},    // not a superset
		{ingressKey(42, 6, 80, 0), ingressKey(0, 6, 64, 10), 0},  // not a superset

		// increasing specificity for a L4-only key
		{ingressKey(0, 0, 0, 0), ingressKey(0, 6, 80, 0), 1},
		{ingressKey(0, 0, 64, 10), ingressKey(0, 6, 64, 10), 1},
		{ingressKey(0, 6, 0, 0), ingressKey(0, 6, 80, 0), 2},
		{ingressKey(0, 6, 64, 10), ingressKey(0, 6, 80, 0), 2},
		{ingressKey(0, 6, 80, 0), ingressKey(0, 6, 80, 0), 0},    // same key
		{ingressKey(0, 6, 64, 10), ingressKey(0, 6, 64, 10), 0},  // same key
		{ingressKey(42, 0, 0, 0), ingressKey(0, 6, 80, 0), 0},    // not a superset
		{ingressKey(42, 0, 64, 10), ingressKey(0, 6, 80, 0), 0},  // not a superset
		{ingressKey(42, 6, 0, 0), ingressKey(0, 6, 80, 0), 0},    // not a superset
		{ingressKey(42, 6, 64, 10), ingressKey(0, 6, 80, 0), 0},  // not a superset
		{ingressKey(42, 6, 80, 0), ingressKey(0, 6, 80, 0), 0},   // not a superset
		{ingressKey(42, 6, 64, 10), ingressKey(0, 6, 64, 10), 0}, // not a superset

	}
	for i, tt := range tests {
		assert.Equal(t, tt.res, IsSuperSetOf(tt.superSet, tt.subSet), fmt.Sprintf("IsSuperSetOf failed on round %d", i+1))
		if tt.res != 0 {
			assert.Equal(t, 0, IsSuperSetOf(tt.subSet, tt.superSet), fmt.Sprintf("Reverse IsSuperSetOf succeeded on round %d", i+1))
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

// WithDefaultAuthType sets inherited auth type field as indicated.
func (e MapStateEntry) WithDefaultAuthType(authType AuthType) MapStateEntry {
	e.hasAuthType = DefaultAuthType
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

func TestPolicyKeyTrafficDirection(t *testing.T) {
	k := IngressKey()
	require.True(t, k.IsIngress())
	require.Equal(t, false, k.IsEgress())

	k = EgressKey()
	require.Equal(t, false, k.IsIngress())
	require.True(t, k.IsEgress())
}

// validatePortProto makes sure each Key in MapState abides by the contract that protocol/nexthdr
// can only be wildcarded if the destination port is also wildcarded.
func (ms *mapState) validatePortProto(t *testing.T) {
	ms.ForEach(func(k Key, _ MapStateEntry) bool {
		if k.Nexthdr == 0 {
			require.Equal(t, uint16(0), k.DestPort)
		}
		return true
	})
}

func TestMapState_denyPreferredInsertWithChanges(t *testing.T) {
	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)
	testMapState := func(initMap MapStateMap) *mapState {
		return newMapState().withState(initMap, selectorCache)
	}

	type args struct {
		key   Key
		entry MapStateEntry
	}
	tests := []struct {
		name                  string
		ms, want              *mapState
		wantAdds, wantDeletes Keys
		wantOld               MapStateMap
		args                  args
	}{
		{
			name: "test-1 - no KV added, map should remain the same",
			ms: testMapState(MapStateMap{
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key:   IngressKey(),
				entry: MapStateEntry{},
			},
			want: testMapState(MapStateMap{
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-2a - L3 allow KV should not overwrite deny entry",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressL3OnlyKey(1),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-2b - L3 port-range allow KV should not overwrite deny entry",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-3a - L3-L4 allow KV should not overwrite deny entry",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 80, 0),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-3b - L3-L4 port-range allow KV should not overwrite deny entry",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-4a - L3-L4 deny KV should overwrite allow entry",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 80, 0),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld: MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-4b - L3-L4 port-range deny KV should overwrite allow entry",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-5a - L3 deny KV should overwrite all L3-L4 allow and L3 allow entries for the same L3",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressL3OnlyKey(2): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: ingressL3OnlyKey(1),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressL3OnlyKey(2): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-5b - L3 port-range deny KV should overwrite all L3-L4 allow and L3 allow entries for the same L3",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-6a - L3 egress deny KV should not overwrite any existing ingress allow",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressL3OnlyKey(2): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: egressL3OnlyKey(1),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				egressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressL3OnlyKey(2): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds: Keys{
				egressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-6b - L3 egress port-range deny KV should not overwrite any existing ingress allow",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: egressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				egressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				ingressKey(2, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(2, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds: Keys{
				egressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-7a - L3 ingress deny KV should not be overwritten by a L3-L4 ingress allow",
			ms: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 80, 0),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-7b - L3 ingress deny KV should not be overwritten by a L3-L4 port-range ingress allow",
			ms: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-8a - L3 ingress deny KV should not be overwritten by a L3-L4-L7 ingress allow",
			ms: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 80, 0),
				entry: MapStateEntry{
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-8b - L3 ingress deny KV should not be overwritten by a L3-L4-L7 port-range ingress allow",
			ms: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: MapStateEntry{
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-9a - L3 ingress deny KV should overwrite a L3-L4-L7 ingress allow",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: ingressL3OnlyKey(1),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-9b - L3 ingress deny KV should overwrite a L3-L4-L7 port-range ingress allow",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: ingressL3OnlyKey(1),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-10a - L3 ingress deny KV should overwrite a L3-L4-L7 ingress allow and a L3-L4 deny",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressL3OnlyKey(1),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-10b - L3 ingress deny KV should overwrite a L3-L4-L7 port-range ingress allow and a L3-L4 port-range deny",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressL3OnlyKey(1),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				ingressL3OnlyKey(1): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
		},
		{
			name: "test-11a - L3 ingress allow should not be allowed if there is a L3 'all' deny",
			ms: testMapState(MapStateMap{
				egressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressL3OnlyKey(100),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				egressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-11b - L3 ingress allow should not be allowed if there is a L3 'all' deny",
			ms: testMapState(MapStateMap{
				egressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: ingressKey(100, 0, 0, 0),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
			want: testMapState(MapStateMap{
				egressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-12a - inserting a L3 'all' deny should delete all entries for that direction",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 5, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				egressKey(100, 3, 5, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: IngressKey(),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				egressKey(100, 3, 5, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				IngressKey(): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
				ingressKey(1, 3, 5, 0):  struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 5, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-12b - inserting a L3 'all' deny should delete all entries for that direction (including port ranges)",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 4, 14): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				egressKey(100, 3, 4, 14): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			args: args{
				key: IngressKey(),
				entry: MapStateEntry{
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			},
			want: testMapState(MapStateMap{
				IngressKey(): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
				egressKey(100, 3, 4, 14): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				IngressKey(): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
				ingressKey(1, 3, 4, 14):  struct{}{},
			},
			wantOld: MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 4, 14): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			},
		},
		{
			name: "test-13a - L3-L4-L7 ingress allow should overwrite a L3-L4-L7 ingress allow due to lower priority",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			}),
			args: args{
				key: ingressKey(1, 3, 80, 0),
				entry: MapStateEntry{
					ProxyPort: 9090,
					priority:  1,
					Listener:  "listener2",
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort: 9090,
					priority:  1,
					Listener:  "listener2",
				},
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld: MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			},
		},
		{
			name: "test-13b - L3-L4-L7 port-range ingress allow should overwrite a L3-L4-L7 port-range ingress allow due to lower priority",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10),
				entry: MapStateEntry{
					ProxyPort: 9090,
					priority:  1,
					Listener:  "listener2",
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): {
					ProxyPort: 9090,
					priority:  1,
					Listener:  "listener2",
				},
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld: MapStateMap{
				ingressKey(1, 3, 64, 10): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			},
		},
		{
			name: "test-14a - L4-L7 ingress allow should overwrite a L3-L4-L7 ingress allow due to lower priority on the same port",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			}),
			args: args{
				key: ingressKey(1, 3, 80, 0),
				entry: MapStateEntry{
					ProxyPort: 8080,
					priority:  1,
					Listener:  "listener1",
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort: 8080,
					priority:  1,
					Listener:  "listener1",
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld: MapStateMap{
				ingressKey(1, 3, 80, 0): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			},
		},
		{
			name: "test-14b - L4-L7 port-range ingress allow should overwrite a L3-L4-L7 port-range ingress allow due to lower priority on the same port",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			}),
			args: args{
				key: ingressKey(1, 3, 64, 10),
				entry: MapStateEntry{
					ProxyPort: 8080,
					priority:  1,
					Listener:  "listener1",
				},
			},
			want: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): {
					ProxyPort: 8080,
					priority:  1,
					Listener:  "listener1",
				},
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld: MapStateMap{
				ingressKey(1, 3, 64, 10): {
					ProxyPort: 8080,
					priority:  8080,
					Listener:  "listener1",
				},
			},
		},
	}
	for _, tt := range tests {
		changes := ChangeState{
			Adds:    make(Keys),
			Deletes: make(Keys),
			Old:     make(MapStateMap),
		}
		// copy the starting point
		ms := testMapState(make(MapStateMap, tt.ms.Len()))
		tt.ms.ForEach(func(k Key, v MapStateEntry) bool {
			ms.insert(k, v, selectorCache)
			return true
		})

		ms.denyPreferredInsertWithChanges(tt.args.key, tt.args.entry, selectorCache, denyRules, changes)
		ms.validatePortProto(t)
		require.Truef(t, ms.Equals(tt.want), "%s: MapState mismatch:\n%s", tt.name, ms.Diff(tt.want))
		require.EqualValuesf(t, tt.wantAdds, changes.Adds, "%s: Adds mismatch", tt.name)
		require.EqualValuesf(t, tt.wantDeletes, changes.Deletes, "%s: Deletes mismatch", tt.name)
		require.EqualValuesf(t, tt.wantOld, changes.Old, "%s: OldValues mismatch allows", tt.name)

		// Revert changes and check that we get the original mapstate
		ms.revertChanges(selectorCache, changes)
		require.Truef(t, ms.Equals(tt.ms), "%s: MapState mismatch:\n%s", tt.name, ms.Diff(tt.ms))
	}
}

func DNSUDPEgressKey(id identity.NumericIdentity) Key {
	return EgressKey().WithIdentity(id).WithUDPPort(53)
}

func DNSTCPEgressKey(id identity.NumericIdentity) Key {
	return EgressKey().WithIdentity(id).WithTCPPort(53)
}

func HostIngressKey() Key {
	return IngressKey().WithIdentity(identity.ReservedIdentityHost)
}

func AnyIngressKey() Key {
	return IngressKey()
}

func AnyEgressKey() Key {
	return EgressKey()
}

func HttpIngressKey(id identity.NumericIdentity) Key {
	return IngressKey().WithIdentity(id).WithTCPPort(80)
}

func HttpEgressKey(id identity.NumericIdentity) Key {
	return EgressKey().WithIdentity(id).WithTCPPort(80)
}

func allowEntry(proxyPort uint16, owners ...MapStateOwner) MapStateEntry {
	return testEntry(proxyPort, false, AuthTypeDisabled, owners...)
}

func denyEntry(proxyPort uint16, owners ...MapStateOwner) MapStateEntry {
	return testEntry(proxyPort, true, AuthTypeDisabled, owners...)
}

func testEntry(proxyPort uint16, deny bool, authType AuthType, owners ...MapStateOwner) MapStateEntry {
	listener := ""
	entry := MapStateEntry{
		ProxyPort: proxyPort,
		priority:  proxyPort,
		Listener:  listener,
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

func TestMapState_AccumulateMapChangesDeny(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)
	testMapState := func(initMap MapStateMap) *mapState {
		return newMapState().withState(initMap, selectorCache)
	}

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    u8proto.U8proto
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
		setup: testMapState(MapStateMap{
			AnyIngressKey():   allowEntry(0),
			HttpIngressKey(0): allowEntry(12345, nil),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():      allowEntry(0),
			ingressL3OnlyKey(41): denyEntry(0, csFoo).WithDependents(HttpIngressKey(41)),
			HttpIngressKey(0):    allowEntry(12345, nil),
			HttpIngressKey(41):   denyEntry(0).WithOwners(ingressL3OnlyKey(41)),
		}),
		adds: Keys{
			ingressL3OnlyKey(41): {},
			HttpIngressKey(41):   {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1b - Adding 2nd identity",
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():      allowEntry(0),
			ingressL3OnlyKey(41): denyEntry(0, csFoo).WithDependents(HttpIngressKey(41)),
			ingressL3OnlyKey(42): denyEntry(0, csFoo).WithDependents(HttpIngressKey(42)),
			HttpIngressKey(0):    allowEntry(12345, nil),
			HttpIngressKey(41):   denyEntry(0).WithOwners(ingressL3OnlyKey(41)),
			HttpIngressKey(42):   denyEntry(0).WithOwners(ingressL3OnlyKey(42)),
		}),
		adds: Keys{
			ingressL3OnlyKey(42): {},
			HttpIngressKey(42):   {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1c - Removing the same key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{42}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():      allowEntry(0),
			ingressL3OnlyKey(41): denyEntry(0, csFoo).WithDependents(HttpIngressKey(41)),
			HttpIngressKey(0):    allowEntry(12345, nil),
			HttpIngressKey(41):   denyEntry(0).WithOwners(ingressL3OnlyKey(41)),
		}),
		adds: Keys{},
		deletes: Keys{
			ingressL3OnlyKey(42): {},
			HttpIngressKey(42):   {},
		},
	}, {
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
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
			{cs: csBar, adds: []int{42, 44}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
			HttpIngressKey(43): denyEntry(0, csFoo),
			HttpIngressKey(44): denyEntry(0, csBar),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-3a - egress allow with deny-L3",
		setup: testMapState(MapStateMap{
			AnyIngressKey():        allowEntry(0),
			HostIngressKey():       allowEntry(0),
			egressKey(42, 0, 0, 0): denyEntry(0, csFoo),
		}),
		args: []args{
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():        allowEntry(0),
			HostIngressKey():       allowEntry(0),
			egressKey(42, 0, 0, 0): denyEntry(0, csFoo),
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
		state: testMapState(MapStateMap{
			AnyIngressKey():        allowEntry(0),
			HostIngressKey():       allowEntry(0),
			egressKey(42, 0, 0, 0): denyEntry(0, csFoo),
			DNSUDPEgressKey(43):    allowEntry(0, csBar),
			DNSTCPEgressKey(43):    allowEntry(0, csBar),
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
		state: testMapState(MapStateMap{
			AnyIngressKey():        allowEntry(0),
			HostIngressKey():       allowEntry(0),
			egressKey(42, 0, 0, 0): denyEntry(0, csFoo),
			DNSUDPEgressKey(43):    allowEntry(0, csBar),
			DNSTCPEgressKey(43):    allowEntry(0, csBar),
			HttpEgressKey(43):      allowEntry(1, csFoo),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-4a - Add L7 skipped due to covering L3 deny",
		setup: testMapState(MapStateMap{
			AnyIngressKey():        allowEntry(0),
			HostIngressKey():       allowEntry(0),
			egressKey(42, 0, 0, 0): denyEntry(0, csFoo),
		}),
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():        allowEntry(0),
			HostIngressKey():       allowEntry(0),
			egressKey(42, 0, 0, 0): denyEntry(0, csFoo),
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
		state: testMapState(MapStateMap{
			AnyIngressKey():        allowEntry(0),
			HostIngressKey():       allowEntry(0),
			egressKey(42, 0, 0, 0): denyEntry(0, csFoo),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		name: "test-5 - Adding L3-deny to an existing allow-all",
		setup: testMapState(MapStateMap{
			AnyIngressKey(): allowEntry(0),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():      allowEntry(0),
			ingressL3OnlyKey(41): denyEntry(0, csFoo),
		}),
		adds: Keys{
			ingressL3OnlyKey(41): {},
		},
		deletes: Keys{},
	}, {
		name: "test-6 - Multiple dependent entries",
		setup: testMapState(MapStateMap{
			AnyEgressKey():     allowEntry(0),
			HttpEgressKey(0):   allowEntry(12345, nil),
			DNSUDPEgressKey(0): allowEntry(12346, nil),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: false, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
			AnyEgressKey():         allowEntry(0),
			egressKey(41, 0, 0, 0): denyEntry(0, csFoo).WithDependents(HttpEgressKey(41), DNSUDPEgressKey(41)),
			HttpEgressKey(0):       allowEntry(12345, nil),
			HttpEgressKey(41):      denyEntry(0).WithOwners(egressKey(41, 0, 0, 0)),
			DNSUDPEgressKey(0):     allowEntry(12346, nil),
			DNSUDPEgressKey(41):    denyEntry(0).WithOwners(egressKey(41, 0, 0, 0)),
		}),
		adds: Keys{
			egressKey(41, 0, 0, 0): {},
			HttpEgressKey(41):      {},
			DNSUDPEgressKey(41):    {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(),
		adds:  Keys{
			//HttpIngressKey(42): allowEntry(0),
		},
		deletes: Keys{
			//HttpIngressKey(43): allowEntry(0),
		},
	},
	}

	policyMapState := newMapState()

	for _, tt := range tests {
		policyMaps := MapChanges{}
		if !tt.continued {
			if tt.setup != nil {
				policyMapState = tt.setup
			} else {
				policyMapState = newMapState()
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
			key := KeyForDirection(dir).WithPortProto(x.proto, x.port)
			var proxyPort uint16
			if x.redirect {
				proxyPort = 1
			}
			value := NewMapStateEntry(cs, nil, proxyPort, "", 0, x.deny, DefaultAuthType, AuthTypeDisabled)
			policyMaps.AccumulateMapChanges(cs, adds, deletes, []Key{key}, value)
		}
		adds, deletes := policyMaps.consumeMapChanges(DummyOwner{}, policyMapState, selectorCache, denyRules)
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equals(tt.state), "%s (MapState):\n%s", tt.name, policyMapState.Diff(tt.state))
		require.EqualValues(t, tt.adds, adds, tt.name+" (adds)")
		require.EqualValues(t, tt.deletes, deletes, tt.name+" (deletes)")
	}
}

func TestMapState_AccumulateMapChanges(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)
	csWildcard := newTestCachedSelector("wildcard", true)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)
	testMapState := func(initMap MapStateMap) *mapState {
		return newMapState().withState(initMap, selectorCache)
	}

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    u8proto.U8proto
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: testMapState(MapStateMap{
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
		state: newMapState(),
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
		state: testMapState(MapStateMap{
			HttpEgressKey(44): allowEntry(1, csFoo),
		}),
		adds: Keys{
			HttpEgressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5a - auth type propagation from the most specific superset",
		args: []args{
			{cs: csFoo, adds: []int{43}, hasAuth: ExplicitAuthType, authType: AuthTypeAlwaysFail},
			{cs: csFoo, adds: []int{43}, proto: 6, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, redirect: true},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeAlwaysFail),
			egressKey(43, 6, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csBar).WithDefaultAuthType(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(43, 6, 0, 0):  {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5b - auth type propagation from the most specific superset - reverse",
		args: []args{
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, redirect: true},
			{cs: csFoo, adds: []int{43}, proto: 6, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
			{cs: csFoo, adds: []int{43}, hasAuth: ExplicitAuthType, authType: AuthTypeAlwaysFail},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeAlwaysFail),
			egressKey(43, 6, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csBar).WithDefaultAuthType(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(43, 6, 0, 0):  {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-6a - added L3/L4 entry due to L3-only explicit auth type and L4-only without",
		args: []args{
			{cs: csFoo, adds: []int{43}, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: true},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csFoo).WithDefaultAuthType(AuthTypeSpire),
			egressKey(0, 6, 80, 0):  allowEntry(1, csWildcard),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(0, 6, 80, 0):  {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-6b - added L3/L4 entry due to L3-only explicit auth type and L4-only without - reverse",
		args: []args{
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: true},
			{cs: csFoo, adds: []int{43}, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csFoo).WithDefaultAuthType(AuthTypeSpire),
			egressKey(0, 6, 80, 0):  allowEntry(1, csWildcard),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(0, 6, 80, 0):  {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-7a - added L3/L4 entry due to L3/proto explicit auth type and L4-only without",
		args: []args{
			{cs: csFoo, adds: []int{43}, proto: 6, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: true},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 6, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csFoo).WithDefaultAuthType(AuthTypeSpire),
			egressKey(0, 6, 80, 0):  allowEntry(1, csWildcard),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):  {},
			egressKey(0, 6, 80, 0):  {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-7b - added L3/L4 entry due to L3/proto explicit auth type and L4-only without - reverse",
		args: []args{
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: true},
			{cs: csFoo, adds: []int{43}, proto: 6, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 6, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csFoo).WithDefaultAuthType(AuthTypeSpire),
			egressKey(0, 6, 80, 0):  allowEntry(1, csWildcard),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):  {},
			egressKey(0, 6, 80, 0):  {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			//{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
		},
		state: newMapState(),
		adds:  Keys{
			//HttpIngressKey(42): allowEntry(0),
		},
		deletes: Keys{
			//HttpIngressKey(43): allowEntry(0),
		},
	},
	}

	policyMapState := newMapState()

	for _, tt := range tests {
		policyMaps := MapChanges{}
		if !tt.continued {
			policyMapState = newMapState()
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
			key := KeyForDirection(dir).WithPortProto(x.proto, x.port)
			var proxyPort uint16
			if x.redirect {
				proxyPort = 1
			}
			value := NewMapStateEntry(cs, nil, proxyPort, "", 0, x.deny, x.hasAuth, x.authType)
			policyMaps.AccumulateMapChanges(cs, adds, deletes, []Key{key}, value)
		}
		adds, deletes := policyMaps.consumeMapChanges(DummyOwner{}, policyMapState, nil, authRules|denyRules)
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equals(tt.state), "%s (MapState):\n%s", tt.name, policyMapState.Diff(tt.state))
		require.EqualValues(t, tt.adds, adds, tt.name+" (adds)")
		require.EqualValues(t, tt.deletes, deletes, tt.name+" (deletes)")
	}
}

var testLabels = labels.LabelArray{
	labels.NewLabel("test", "ing", labels.LabelSourceReserved),
}

func TestMapState_AddVisibilityKeys(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)
	testMapState := func(initMap MapStateMap) *mapState {
		return newMapState().withState(initMap, selectorCache)
	}

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
			ms: testMapState(MapStateMap{
				AnyIngressKey(): allowEntry(0),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				AnyIngressKey():   allowEntry(0),
				HttpIngressKey(0): allowEntryD(12345, visibilityDerivedFrom, nil),
			}),
		},
		{
			name: "test-2 - Add HTTP ingress visibility - no allow-all",
			ms:   newMapState(),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: newMapState(),
		},
		{
			name: "test-3 - Add HTTP ingress visibility - L4-allow",
			ms: testMapState(MapStateMap{
				HttpIngressKey(0): allowEntryD(0, labels.LabelArrayList{testLabels}),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				HttpIngressKey(0): allowEntryD(12345, labels.LabelArrayList{visibilityDerivedFromLabels, testLabels}, nil),
			}),
		},
		{
			name: "test-4 - Add HTTP ingress visibility - L3/L4-allow",
			ms: testMapState(MapStateMap{
				HttpIngressKey(123): allowEntryD(0, labels.LabelArrayList{testLabels}, csBar),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				HttpIngressKey(123): allowEntryD(12345, labels.LabelArrayList{visibilityDerivedFromLabels, testLabels}, csBar),
			}),
		},
		{
			name: "test-5 - Add HTTP ingress visibility - L3-allow (host)",
			ms: testMapState(MapStateMap{
				HostIngressKey(): allowEntry(0),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				HostIngressKey():  allowEntry(0).WithDependents(HttpIngressKey(1)),
				HttpIngressKey(1): allowEntryD(12345, labels.LabelArrayList{visibilityDerivedFromLabels}).WithOwners(HostIngressKey()),
			}),
		},
		{
			name: "test-6 - Add HTTP ingress visibility - L3/L4-allow on different port",
			ms: testMapState(MapStateMap{
				IngressKey().WithIdentity(123).WithTCPPort(88): allowEntryD(0, labels.LabelArrayList{testLabels}, csBar),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				IngressKey().WithIdentity(123).WithTCPPort(88): allowEntryD(0, labels.LabelArrayList{testLabels}, csBar),
			}),
		},
		{
			name: "test-7 - Add HTTP ingress visibility - allow-all + L4-deny (no change)",
			ms: testMapState(MapStateMap{
				AnyIngressKey():   allowEntry(0),
				HttpIngressKey(0): denyEntry(0),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				AnyIngressKey():   allowEntry(0),
				HttpIngressKey(0): denyEntry(0),
			}),
		},
		{
			name: "test-8 - Add HTTP ingress visibility - allow-all + L3-deny",
			ms: testMapState(MapStateMap{
				AnyIngressKey():       allowEntry(0),
				ingressL3OnlyKey(234): denyEntry(0, csFoo),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				AnyIngressKey():       allowEntry(0),
				ingressL3OnlyKey(234): denyEntry(0, csFoo).WithDependents(HttpIngressKey(234)),
				HttpIngressKey(0):     allowEntryD(12345, visibilityDerivedFrom, nil),
				HttpIngressKey(234):   denyEntry(0, csFoo).WithOwners(ingressL3OnlyKey(234)),
			}),
		},
		{
			name: "test-9 - Add HTTP ingress visibility - allow-all + L3/L4-deny",
			ms: testMapState(MapStateMap{
				AnyIngressKey():     allowEntry(0),
				HttpIngressKey(132): denyEntry(0, csBar),
			}),
			args: args{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				AnyIngressKey():     allowEntry(0),
				HttpIngressKey(132): denyEntry(0, csBar),
				HttpIngressKey(0):   allowEntryD(12345, visibilityDerivedFrom, nil),
			}),
		},
		{
			name: "test-10 - Add HTTP egress visibility",
			ms: testMapState(MapStateMap{
				AnyEgressKey(): allowEntry(0),
			}),
			args: args{
				redirectPort: 12346,
				visMeta:      VisibilityMetadata{Ingress: false, Port: 80, Proto: u8proto.TCP},
			},
			want: testMapState(MapStateMap{
				AnyEgressKey():   allowEntry(0),
				HttpEgressKey(0): allowEntryD(12346, visibilityDerivedFrom, nil),
			}),
		},
	}
	for _, tt := range tests {
		old := ChangeState{
			Old: make(MapStateMap),
		}
		tt.ms.ForEach(func(k Key, v MapStateEntry) bool {
			old.insertOldIfNotExists(k, v)
			return true
		})
		changes := ChangeState{
			Adds: make(Keys),
			Old:  make(MapStateMap),
		}
		tt.ms.addVisibilityKeys(DummyOwner{}, tt.args.redirectPort, &tt.args.visMeta, selectorCache, changes)
		tt.ms.validatePortProto(t)
		require.True(t, tt.ms.Equals(tt.want), "%s:\n%s", tt.name, tt.ms.Diff(tt.want))
		// Find new and updated entries
		wantAdds := make(Keys)
		wantOld := make(MapStateMap)

		for k, v := range old.Old {
			if _, ok := tt.ms.Get(k); !ok {
				wantOld[k] = v
			}
		}
		tt.ms.ForEach(func(k Key, v MapStateEntry) bool {
			if v2, ok := old.Old[k]; ok {
				if !assert.ObjectsAreEqual(v2, v) {
					if !v.DatapathEqual(&v2) {
						wantAdds[k] = struct{}{}
					}
					wantOld[k] = v2
				}
			} else {
				wantAdds[k] = struct{}{}
			}
			return true
		})
		require.EqualValues(t, wantAdds, changes.Adds, tt.name)
		require.EqualValues(t, wantOld, changes.Old, tt.name)
	}
}

func TestMapState_AccumulateMapChangesOnVisibilityKeys(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)
	testMapState := func(initMap MapStateMap) *mapState {
		return newMapState().withState(initMap, selectorCache)
	}

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    u8proto.U8proto
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
		visOld    MapStateMap
		args      []args // changes applied, in order
		state     MapState
		adds      Keys
		deletes   Keys
	}{{
		name: "test-1a - Adding identity to deny with visibilty",
		setup: testMapState(MapStateMap{
			AnyIngressKey():       allowEntry(0),
			ingressL3OnlyKey(234): denyEntry(0, csFoo),
		}),
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		visAdds: Keys{
			HttpIngressKey(0):   {},
			HttpIngressKey(234): {},
		},
		visOld: MapStateMap{
			ingressL3OnlyKey(234): denyEntry(0, csFoo),
		},
		args: []args{
			{cs: csFoo, adds: []int{235}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():       allowEntry(0),
			ingressL3OnlyKey(234): denyEntry(0, csFoo).WithDependents(HttpIngressKey(234)),
			ingressL3OnlyKey(235): denyEntry(0, csFoo).WithDependents(HttpIngressKey(235)),
			HttpIngressKey(0):     allowEntryD(12345, visibilityDerivedFrom, nil),
			HttpIngressKey(234):   denyEntry(0).WithOwners(ingressL3OnlyKey(234)),
			HttpIngressKey(235):   denyEntry(0).WithOwners(ingressL3OnlyKey(235)),
		}),
		adds: Keys{
			ingressL3OnlyKey(235): {},
			HttpIngressKey(235):   {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1b - Removing the sole key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{235}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		state: testMapState(MapStateMap{
			AnyIngressKey():       allowEntry(0),
			ingressL3OnlyKey(234): denyEntry(0, csFoo).WithDependents(HttpIngressKey(234)),
			HttpIngressKey(0):     allowEntryD(12345, visibilityDerivedFrom, nil),
			HttpIngressKey(234):   denyEntry(0).WithOwners(ingressL3OnlyKey(234)),
		}),
		adds: Keys{},
		deletes: Keys{
			ingressL3OnlyKey(235): {},
			HttpIngressKey(235):   {},
		},
	}, {
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{235, 236}, deletes: []int{50}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: testMapState(MapStateMap{
			ingressL3OnlyKey(235): allowEntry(0, csFoo).WithDependents(HttpIngressKey(235)),
			ingressL3OnlyKey(236): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(235)),
			HttpIngressKey(236):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(236)),
		}),
		adds: Keys{
			ingressL3OnlyKey(235): {},
			HttpIngressKey(235):   {},
			ingressL3OnlyKey(236): {},
			HttpIngressKey(236):   {},
		},
		deletes: Keys{
			ingressL3OnlyKey(235): {}, // changed dependents
			ingressL3OnlyKey(236): {}, // changed dependents
		},
	}, {
		continued: true,
		name:      "test-2b - Adding Bar also selecting 235",
		args: []args{
			{cs: csBar, adds: []int{235, 237}, deletes: []int{50}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: testMapState(MapStateMap{
			ingressL3OnlyKey(235): allowEntry(0, csFoo, csBar).WithDependents(HttpIngressKey(235)),
			ingressL3OnlyKey(236): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(235)),
			HttpIngressKey(236):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(236)),
			ingressL3OnlyKey(237): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(237)),
		}),
		adds: Keys{
			ingressL3OnlyKey(237): {},
			HttpIngressKey(237):   {},
		},
		deletes: Keys{
			ingressL3OnlyKey(237): {}, // changed dependents
		},
	}, {
		continued: true,
		name:      "test-2c - Deleting 235 from Foo, remains on Bar and no deletes",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{235}, port: 0, proto: 0, ingress: true, redirect: false, deny: true},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: testMapState(MapStateMap{
			ingressL3OnlyKey(235): allowEntry(0, csBar).WithDependents(HttpIngressKey(235)),
			ingressL3OnlyKey(236): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(235)),
			HttpIngressKey(236):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(236)),
			ingressL3OnlyKey(237): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(237)),
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
			visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: testMapState(MapStateMap{
			ingressL3OnlyKey(235): allowEntry(0, csBar).WithDependents(HttpIngressKey(235)),
			ingressL3OnlyKey(236): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(235):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(235)),
			HttpIngressKey(236):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(236)),
			ingressL3OnlyKey(237): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(237)),
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
			visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: testMapState(MapStateMap{
			ingressL3OnlyKey(236): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(236):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(236)),
			ingressL3OnlyKey(237): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(237)),
		}),
		adds: Keys{},
		deletes: Keys{
			ingressL3OnlyKey(235): {},
			HttpIngressKey(235):   {},
		},
	}, {
		continued: true,
		name:      "test-2f - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{237}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: false, deny: false},
		},
		visArgs: []visArgs{{
			redirectPort: 12345,
			visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
		}},
		state: testMapState(MapStateMap{
			ingressL3OnlyKey(236): allowEntry(0, csFoo).WithDependents(HttpIngressKey(236)),
			HttpIngressKey(236):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(236)),
			ingressL3OnlyKey(237): allowEntry(0, csBar).WithDependents(HttpIngressKey(237)),
			HttpIngressKey(237):   allowEntryD(12345, visibilityDerivedFrom).WithOwners(ingressL3OnlyKey(237)),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-3a - egress HTTP proxy (setup)",
		setup: testMapState(MapStateMap{
			AnyIngressKey():  allowEntry(0),
			HostIngressKey(): allowEntry(0),
			HttpEgressKey(0): allowEntry(0),
		}),
		visArgs: []visArgs{
			{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12346,
				visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: false, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12347,
				visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: false, Port: 53, Proto: u8proto.UDP},
			},
		},
		visAdds: Keys{
			HttpIngressKey(0): {},
			HttpEgressKey(0):  {},
		},
		visOld: MapStateMap{
			// Old value for the modified entry
			HttpEgressKey(0): allowEntry(0),
		},
		args: []args{
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, redirect: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, redirect: false, deny: false},
		},
		state: testMapState(MapStateMap{
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
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-3b - egress HTTP proxy (incremental update)",
		args: []args{
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: true, deny: false},
		},
		visArgs: []visArgs{
			{
				redirectPort: 12345,
				visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: true, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12346,
				visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: false, Port: 80, Proto: u8proto.TCP},
			},
			{
				redirectPort: 12347,
				visMeta:      VisibilityMetadata{Parser: ParserTypeHTTP, Ingress: false, Port: 53, Proto: u8proto.UDP},
			},
		},
		state: testMapState(MapStateMap{
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
		state: newMapState(),
		adds:  Keys{
			//HttpIngressKey(42): {},
		},
		deletes: Keys{
			//HttpIngressKey(43): {},
		},
	},
	}

	policyMapState := newMapState()

	for _, tt := range tests {
		// Allow omit empty maps
		if tt.visAdds == nil {
			tt.visAdds = make(Keys)
		}
		if tt.visOld == nil {
			tt.visOld = make(MapStateMap)
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
				policyMapState = newMapState()
			}
		}
		changes := ChangeState{
			Adds:    make(Keys),
			Deletes: make(Keys),
			Old:     make(MapStateMap),
		}
		for _, arg := range tt.visArgs {
			policyMapState.addVisibilityKeys(DummyOwner{}, arg.redirectPort, &arg.visMeta, selectorCache, changes)
		}
		require.EqualValues(t, tt.visAdds, changes.Adds, tt.name+" (visAdds)")
		require.EqualValues(t, tt.visOld, changes.Old, tt.name+" (visOld)")

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
			key := KeyForDirection(dir).WithPortProto(x.proto, x.port)
			var proxyPort uint16
			if x.redirect {
				proxyPort = 1
			}
			value := NewMapStateEntry(cs, nil, proxyPort, "", 0, x.deny, DefaultAuthType, AuthTypeDisabled)
			policyMaps.AccumulateMapChanges(cs, adds, deletes, []Key{key}, value)
		}
		adds, deletes := policyMaps.consumeMapChanges(DummyOwner{}, policyMapState, selectorCache, denyRules)
		changes = ChangeState{
			Adds:    adds,
			Deletes: deletes,
			Old:     make(MapStateMap),
		}

		// Visibilty redirects need to be re-applied after consumeMapChanges()
		for _, arg := range tt.visArgs {
			policyMapState.addVisibilityKeys(DummyOwner{}, arg.redirectPort, &arg.visMeta, selectorCache, changes)
		}
		for k := range changes.Old {
			changes.Deletes[k] = struct{}{}
		}
		policyMapState.validatePortProto(t)
		require.True(t, tt.state.Equals(policyMapState), "%s (MapState):\n%s", tt.name, policyMapState.Diff(tt.state))
		require.EqualValues(t, tt.adds, changes.Adds, tt.name+" (adds)")
		require.EqualValues(t, tt.deletes, changes.Deletes, tt.name+" (deletes)")
	}
}

func (e MapStateEntry) asDeny() MapStateEntry {
	if !e.IsDeny {
		e.IsDeny = true
		e.ProxyPort = 0
		e.Listener = ""
		e.priority = 0
		e.hasAuthType = DefaultAuthType
		e.AuthType = AuthTypeDisabled
	}
	return e
}

func TestMapState_denyPreferredInsertWithSubnets(t *testing.T) {
	identityCache := identity.IdentityMap{
		identity.ReservedIdentityWorld: labels.LabelWorld.LabelArray(),
		worldIPIdentity:                lblWorldIP.LabelArray(),     // "192.0.2.3/32"
		worldSubnetIdentity:            lblWorldSubnet.LabelArray(), // "192.0.2.0/24"
	}

	reservedWorldID := identity.ReservedIdentityWorld
	worldIPID := worldIPIdentity
	worldSubnetID := worldSubnetIdentity
	selectorCache := testNewSelectorCache(identityCache)
	type action uint16
	const (
		noAction       = action(iota)
		insertAllowAll = action(1 << iota)
		insertA
		insertB
		insertAWithBProto
		insertAasB // Proto and entry from B
		insertBWithAProto
		insertBWithAProtoAsDeny
		insertAasDeny
		insertBasDeny
		insertBoth = insertA | insertB
	)

	type withAllowAll bool
	const (
		WithAllowAll    = withAllowAll(true)
		WithoutAllowAll = withAllowAll(false)
	)

	// these tests are based on the sheet https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw#gid=2109052536
	tests := []struct {
		name                 string
		withAllowAll         withAllowAll
		aIdentity, bIdentity identity.NumericIdentity
		aIsDeny, bIsDeny     bool
		aPort                uint16
		aProto               u8proto.U8proto
		bPort                uint16
		bProto               u8proto.U8proto
		outcome              action
	}{
		// deny-allow insertions
		{"deny-allow: a superset a|b L3-only; subset allow inserted as deny", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 0, 0, 0, insertAllowAll | insertA | insertBasDeny},
		{"deny-allow: a superset a|b L3-only; without allow-all", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 0, 0, 0, insertA | insertBasDeny},

		{"deny-allow: b superset a|b L3-only", WithAllowAll, worldIPID, worldSubnetID, true, false, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a|b L3-only; without allow-all", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 0, 0, 0, 0, insertBoth},

		{"deny-allow: a superset a L3-only, b L4; subset allow inserted as deny", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 0, 0, 6, insertAllowAll | insertA | insertBasDeny},
		{"deny-allow: a superset a L3-only, b L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 0, 0, 6, insertA | insertBasDeny},

		{"deny-allow: b superset a L3-only, b L4", WithAllowAll, worldIPID, worldSubnetID, true, false, 0, 0, 0, 6, insertAllowAll | insertBoth | insertAWithBProto},
		{"deny-allow: b superset a L3-only, b L4; without allow-all, added deny TCP due to intersecting deny", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 0, 0, 0, 6, insertBoth | insertAWithBProto},

		{"deny-allow: a superset a L3-only, b L3L4; subset allow inserted as deny", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 0, 80, 6, insertAllowAll | insertA | insertBasDeny},
		{"deny-allow: a superset a L3-only, b L3L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 0, 80, 6, insertA | insertBasDeny},

		{"deny-allow: b superset a L3-only, b L3L4; added deny TCP/80 due to intersecting deny", WithAllowAll, worldIPID, worldSubnetID, true, false, 0, 0, 80, 6, insertAllowAll | insertBoth | insertAWithBProto},
		{"deny-allow: b superset a L3-only, b L3L4; without allow-all, added deny TCP/80 due to intersecting deny", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 0, 0, 80, 6, insertBoth | insertAWithBProto},

		{"deny-allow: a superset a L4, b L3-only", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth | insertBWithAProtoAsDeny},
		{"deny-allow: a superset a L4, b L3-only; without allow-all", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 6, 0, 0, insertBoth | insertBWithAProtoAsDeny},

		{"deny-allow: b superset a L4, b L3-only", WithAllowAll, worldIPID, worldSubnetID, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L3-only; without allow-all", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 0, 6, 0, 0, insertBoth},

		{"deny-allow: a superset a L4, b L4; subset allow inserted as deny", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 6, 0, 6, insertAllowAll | insertA | insertBasDeny},
		{"deny-allow: a superset a L4, b L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 6, 0, 6, insertA | insertBasDeny},

		{"deny-allow: b superset a L4, b L4", WithAllowAll, worldIPID, worldSubnetID, true, false, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L4; without allow-all", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 0, 6, 0, 6, insertBoth},

		{"deny-allow: a superset a L4, b L3L4; subset allow inserted as deny", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 6, 80, 6, insertAllowAll | insertA | insertBasDeny},
		{"deny-allow: a superset a L4, b L3L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 0, 6, 80, 6, insertA | insertBasDeny},

		{"deny-allow: b superset a L4, b L3L4", WithAllowAll, worldIPID, worldSubnetID, true, false, 0, 6, 80, 6, insertAllowAll | insertBoth | insertAWithBProto},
		{"deny-allow: b superset a L4, b L3L4; without allow-all", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 0, 6, 80, 6, insertBoth | insertAWithBProto},

		{"deny-allow: a superset a L3L4, b L3-only", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth | insertBWithAProtoAsDeny},
		{"deny-allow: a superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 80, 6, 0, 0, insertBoth | insertBWithAProtoAsDeny},

		{"deny-allow: b superset a L3L4, b L3-only", WithAllowAll, worldIPID, worldSubnetID, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 80, 6, 0, 0, insertBoth},

		{"deny-allow: a superset a L3L4, b L4", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth | insertBWithAProtoAsDeny},
		{"deny-allow: a superset a L3L4, b L4; without allow-all", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 80, 6, 0, 6, insertBoth | insertBWithAProtoAsDeny},

		{"deny-allow: b superset a L3L4, b L4", WithAllowAll, worldIPID, worldSubnetID, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L4 without allow-all", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 80, 6, 0, 6, insertBoth},

		{"deny-allow: a superset a L3L4, b L3L4", WithAllowAll, reservedWorldID, worldSubnetID, true, false, 80, 6, 80, 6, insertAllowAll | insertA | insertBasDeny},
		{"deny-allow: a superset a L3L4, b L3L4 without allow-all", WithoutAllowAll, reservedWorldID, worldSubnetID, true, false, 80, 6, 80, 6, insertA | insertBasDeny},

		{"deny-allow: b superset a L3L4, b L3L4", WithAllowAll, worldIPID, worldSubnetID, true, false, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3L4; without allow-all", WithoutAllowAll, worldIPID, worldSubnetID, true, false, 80, 6, 80, 6, insertBoth},

		// deny-deny insertions: Note: There is no dedundancy between different non-zero security IDs on the
		// datapath, even if one would be a CIDR subset of another. Situation would be different if we could
		// completely remove (or not add in the first place) the redundant ID from the ipcache so that
		// datapath could never assign that ID to a packet for policy enforcement.
		// These test case are left here for such future improvement.
		{"deny-deny: a superset a|b L3-only", WithAllowAll, worldSubnetID, worldIPID, true, true, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: a superset a|b L3-only; without allow-all", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 0, 0, 0, 0, insertBoth},

		{"deny-deny: b superset a|b L3-only", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: b superset a|b L3-only; without allow-all", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 0, 0, 0, insertBoth},

		{"deny-deny: a superset a L3-only, b L4", WithAllowAll, worldSubnetID, worldIPID, true, true, 0, 0, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L3-only, b L4", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 0, 0, 0, 6, insertBoth},

		{"deny-deny: b superset a L3-only, b L4", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 0, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L3-only, b L4", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 0, 0, 6, insertBoth},

		{"deny-deny: a superset a L3-only, b L3L4", WithAllowAll, worldSubnetID, worldIPID, true, true, 0, 0, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L3-only, b L3L4", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 0, 0, 80, 6, insertBoth},

		{"deny-deny: b superset a L3-only, b L3L4", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 0, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L3-only, b L3L4", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 0, 80, 6, insertBoth},

		{"deny-deny: a superset a L4, b L3-only", WithAllowAll, worldSubnetID, worldIPID, true, true, 0, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L4, b L3-only", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 0, 6, 0, 0, insertBoth},

		{"deny-deny: b superset a L4, b L3-only", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L4, b L3-only", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 6, 0, 0, insertBoth},

		{"deny-deny: a superset a L4, b L4", WithAllowAll, worldSubnetID, worldIPID, true, true, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L4, b L4", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 0, 6, 0, 6, insertBoth},

		{"deny-deny: b superset a L4, b L4", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L4, b L4", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 6, 0, 6, insertBoth},

		{"deny-deny: a superset a L4, b L3L4", WithAllowAll, worldSubnetID, worldIPID, true, true, 0, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L4, b L3L4", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 0, 6, 80, 6, insertBoth},

		{"deny-deny: b superset a L4, b L3L4", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L4, b L3L4", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 0, 6, 80, 6, insertBoth},

		{"deny-deny: a superset a L3L4, b L3-only", WithAllowAll, worldSubnetID, worldIPID, true, true, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L3L4, b L3-only", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 80, 6, 0, 0, insertBoth},

		{"deny-deny: b superset a L3L4, b L3-only", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L3L4, b L3-only", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 80, 6, 0, 0, insertBoth},

		{"deny-deny: a superset a L3L4, b L4", WithAllowAll, worldSubnetID, worldIPID, true, true, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L3L4, b L4", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 80, 6, 0, 6, insertBoth},

		{"deny-deny: b superset a L3L4, b L4", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L3L4, b L4", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 80, 6, 0, 6, insertBoth},

		{"deny-deny: a superset a L3L4, b L3L4", WithAllowAll, worldSubnetID, worldIPID, true, true, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L3L4, b L3L4", WithoutAllowAll, worldSubnetID, worldIPID, true, true, 80, 6, 80, 6, insertBoth},

		{"deny-deny: b superset a L3L4, b L3L4", WithAllowAll, worldSubnetID, reservedWorldID, true, true, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L3L4, b L3L4", WithoutAllowAll, worldSubnetID, reservedWorldID, true, true, 80, 6, 80, 6, insertBoth},

		// allow-allow insertions do not need tests as their affect on one another does not matter.
	}
	for _, tt := range tests {
		anyIngressKey := IngressKey()
		allowEntry := MapStateEntry{}
		aKey := IngressKey().WithIdentity(tt.aIdentity).WithPortProto(tt.aProto, tt.aPort)
		aEntry := MapStateEntry{IsDeny: tt.aIsDeny}
		bKey := IngressKey().WithIdentity(tt.bIdentity).WithPortProto(tt.bProto, tt.bPort)
		bEntry := MapStateEntry{IsDeny: tt.bIsDeny}
		expectedKeys := newMapState()
		if tt.outcome&insertAllowAll > 0 {
			expectedKeys.allows.upsert(anyIngressKey, allowEntry, selectorCache)
		}
		if tt.outcome&insertA > 0 {
			if tt.aIsDeny {
				expectedKeys.denies.upsert(aKey, aEntry, selectorCache)
			} else {
				expectedKeys.allows.upsert(aKey, aEntry, selectorCache)
			}
		}
		if tt.outcome&insertAasDeny > 0 {
			expectedKeys.denies.upsert(aKey, aEntry.asDeny(), selectorCache)
		}
		if tt.outcome&insertB > 0 {
			if tt.bIsDeny {
				expectedKeys.denies.upsert(bKey, bEntry, selectorCache)
			} else {
				expectedKeys.allows.upsert(bKey, bEntry, selectorCache)
			}
		}
		if tt.outcome&insertBasDeny > 0 {
			expectedKeys.denies.upsert(bKey, bEntry.asDeny(), selectorCache)
		}
		if tt.outcome&insertAWithBProto > 0 {
			aKeyWithBProto := IngressKey().WithIdentity(tt.aIdentity).WithPortProto(tt.bProto, tt.bPort)
			aEntryCpy := MapStateEntry{IsDeny: tt.aIsDeny}
			aEntryCpy.owners = map[MapStateOwner]struct{}{aKey: {}}
			aEntryWithDep := aEntry.WithDependents(aKeyWithBProto)
			if tt.aIsDeny {
				expectedKeys.denies.upsert(aKey, aEntryWithDep, selectorCache)
				expectedKeys.denies.upsert(aKeyWithBProto, aEntryCpy, selectorCache)
			} else {
				expectedKeys.allows.upsert(aKey, aEntryWithDep, selectorCache)
				expectedKeys.allows.upsert(aKeyWithBProto, aEntryCpy, selectorCache)
			}
		}
		if tt.outcome&insertAasB > 0 {
			aKeyWithBProto := IngressKey().WithIdentity(tt.aIdentity).WithPortProto(tt.bProto, tt.bPort)
			bEntryWithOwner := bEntry.WithOwners(bKey)
			bEntryWithDep := bEntry.WithDependents(aKeyWithBProto)
			if tt.bIsDeny {
				expectedKeys.denies.upsert(bKey, bEntryWithDep, selectorCache)
				expectedKeys.denies.upsert(aKeyWithBProto, bEntryWithOwner, selectorCache)
			} else {
				expectedKeys.allows.upsert(bKey, bEntryWithDep, selectorCache)
				expectedKeys.allows.upsert(aKeyWithBProto, bEntryWithOwner, selectorCache)
			}
		}
		if tt.outcome&insertBWithAProto > 0 {
			bKeyWithBProto := IngressKey().WithIdentity(tt.bIdentity).WithPortProto(tt.aProto, tt.aPort)
			bEntryCpy := MapStateEntry{IsDeny: tt.bIsDeny}
			bEntryCpy.owners = map[MapStateOwner]struct{}{bKey: {}}
			bEntryWithDep := bEntry.WithDependents(bKeyWithBProto)
			if tt.bIsDeny {
				expectedKeys.denies.upsert(bKey, bEntryWithDep, selectorCache)
				expectedKeys.denies.upsert(bKeyWithBProto, bEntryCpy, selectorCache)
			} else {
				expectedKeys.allows.upsert(bKey, bEntryWithDep, selectorCache)
				expectedKeys.allows.upsert(bKeyWithBProto, bEntryCpy, selectorCache)
			}
		}
		if tt.outcome&insertBWithAProtoAsDeny > 0 {
			bKeyWithAProto := IngressKey().WithIdentity(tt.bIdentity).WithPortProto(tt.aProto, tt.aPort)
			bEntryAsDeny := bEntry.WithOwners(aKey).asDeny()
			aEntryWithDep := aEntry.WithDependents(bKeyWithAProto)
			expectedKeys.denies.upsert(aKey, aEntryWithDep, selectorCache)
			expectedKeys.denies.upsert(bKeyWithAProto, bEntryAsDeny, selectorCache)
		}
		outcomeKeys := newMapState()
		outcomeKeys.validator = &validator{} // insert validator

		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, selectorCache, allFeatures)
		}
		outcomeKeys.denyPreferredInsert(aKey, aEntry, selectorCache, allFeatures)
		outcomeKeys.denyPreferredInsert(bKey, bEntry, selectorCache, allFeatures)
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equals(outcomeKeys), "%s (MapState):\n%s", tt.name, outcomeKeys.Diff(expectedKeys))

		// Test also with reverse insertion order
		outcomeKeys = newMapState()
		outcomeKeys.validator = &validator{} // insert validator

		outcomeKeys.denyPreferredInsert(bKey, bEntry, selectorCache, allFeatures)
		outcomeKeys.denyPreferredInsert(aKey, aEntry, selectorCache, allFeatures)
		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, selectorCache, allFeatures)
		}
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equals(outcomeKeys), "%s (in reverse) (MapState):\n%s", tt.name, outcomeKeys.Diff(expectedKeys))
	}
	// Now test all cases with different traffic directions.
	// This should result in both entries being inserted with
	// no changes, as they do not affect one another anymore.
	for _, tt := range tests {
		anyIngressKey := IngressKey()
		anyEgressKey := EgressKey()
		allowEntry := MapStateEntry{}
		aKey := IngressKey().WithIdentity(tt.aIdentity).WithPortProto(tt.aProto, tt.aPort)
		aEntry := MapStateEntry{IsDeny: tt.aIsDeny}
		bKey := EgressKey().WithIdentity(tt.bIdentity).WithPortProto(tt.bProto, tt.bPort)
		bEntry := MapStateEntry{IsDeny: tt.bIsDeny}
		expectedKeys := newMapState()
		if tt.outcome&insertAllowAll > 0 {
			expectedKeys.allows.upsert(anyIngressKey, allowEntry, selectorCache)
			expectedKeys.allows.upsert(anyEgressKey, allowEntry, selectorCache)
		}
		if tt.aIsDeny {
			expectedKeys.denies.upsert(aKey, aEntry, selectorCache)
		} else {
			expectedKeys.allows.upsert(aKey, aEntry, selectorCache)
		}
		if tt.bIsDeny {
			expectedKeys.denies.upsert(bKey, bEntry, selectorCache)
		} else {
			expectedKeys.allows.upsert(bKey, bEntry, selectorCache)
		}
		outcomeKeys := newMapState()
		outcomeKeys.validator = &validator{} // insert validator

		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, selectorCache, allFeatures)
			outcomeKeys.denyPreferredInsert(anyEgressKey, allowEntry, selectorCache, allFeatures)
		}
		outcomeKeys.denyPreferredInsert(aKey, aEntry, selectorCache, allFeatures)
		outcomeKeys.denyPreferredInsert(bKey, bEntry, selectorCache, allFeatures)
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equals(outcomeKeys), "%s different traffic directions (MapState):\n%s", tt.name, outcomeKeys.Diff(expectedKeys))

		// Test also with reverse insertion order
		outcomeKeys = newMapState()
		outcomeKeys.validator = &validator{} // insert validator

		outcomeKeys.denyPreferredInsert(bKey, bEntry, selectorCache, allFeatures)
		outcomeKeys.denyPreferredInsert(aKey, aEntry, selectorCache, allFeatures)
		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyEgressKey, allowEntry, selectorCache, allFeatures)
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, selectorCache, allFeatures)
		}
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equals(outcomeKeys), "%s different traffic directions (in reverse) (MapState):\n%s", tt.name, outcomeKeys.Diff(expectedKeys))
	}
}

func TestMapState_Get_stacktrace(t *testing.T) {
	ms := newMapState()
	// This should produce a stacktrace in the error log. It is not validated here but can be
	// observed manually.
	// Example log (with newlines expanded):
	// time="2024-06-22T23:21:27+03:00" level=error msg="mapState.Get: invalid wildcard port with non-zero mask: Identity=0,DestPort=0,Nexthdr=0,TrafficDirection=0. Stacktrace:
	// github.com/hashicorp/go-hclog.Stacktrace
	// 	github.com/cilium/cilium/vendor/github.com/hashicorp/go-hclog/stacktrace.go:51
	// github.com/cilium/cilium/pkg/policy.(*mapState).Get
	// 	github.com/cilium/cilium/pkg/policy/mapstate.go:355
	// github.com/cilium/cilium/pkg/policy.TestMapState_Get_stacktrace
	// 	github.com/cilium/cilium/pkg/policy/mapstate_test.go:3699
	// testing.tRunner
	// go/src/testing/testing.go:1689" subsys=policy
	log.Error("Expecting an error log on the next log line!")
	_, ok := ms.Get(Key{})
	assert.False(t, ok)
}

type validator struct{}

// prefixesContainsAny checks that any subnet in the `a` subnet group *fully*
// contains any of the subnets in the `b` subnet group.
func prefixesContainsAny(a, b []netip.Prefix) bool {
	for _, an := range a {
		aMask := an.Bits()
		aIsIPv4 := an.Addr().Is4()
		for _, bn := range b {
			bIsIPv4 := bn.Addr().Is4()
			isSameFamily := aIsIPv4 == bIsIPv4
			if isSameFamily {
				bMask := bn.Bits()
				if bMask >= aMask && an.Contains(bn.Addr()) {
					return true
				}
			}
		}
	}
	return false
}

// identityIsSupersetOf compares two entries and keys to see if the primary identity contains
// the compared identity. This means that either that primary identity is 0 (i.e. it is a superset
// of every other identity), or one of the subnets of the primary identity fully contains or is
// equal to one of the subnets in the compared identity (note:this covers cases like "reserved:world").
func identityIsSupersetOf(primaryIdentity, compareIdentity identity.NumericIdentity, identities Identities) bool {
	// If the identities are equal then neither is a superset (for the purposes of our business logic).
	if primaryIdentity == compareIdentity {
		return false
	}

	// Consider an identity that selects a broader CIDR as a superset of
	// an identity that selects a narrower CIDR. For instance, an identity
	// corresponding to 192.0.0.0/16 is a superset of the identity that
	// corresponds to 192.0.2.3/32.
	//
	// The reasons we need to do this are surprisingly complex, taking into
	// consideration design decisions around the handling of ToFQDNs policy
	// and how L4PolicyMap/L4Filter structures cache the policies with
	// respect to specific CIDRs. More specifically:
	// - At the time of initial L4Filter creation, it is not known which
	//   specific CIDRs (or corresponding identities) are selected by a
	//   toFQDNs rule in the policy engine.
	// - It is possible to have a CIDR deny rule that should deny peers
	//   that are allowed by a ToFQDNs statement. The precedence rules in
	//   the API for such policy conflicts define that the deny should take
	//   precedence.
	// - Consider a case where there is a deny rule for 192.0.0.0/16 with
	//   an allow rule for cilium.io, and one of the IP addresses for
	//   cilium.io is 192.0.2.3.
	// - If the IP for cilium.io was known at initial policy computation
	//   time, then we would calculate the MapState from the L4Filters and
	//   immediately determine that there is a conflict between the
	//   L4Filter that denies 192.0.0.0/16 vs. the allow for 192.0.2.3.
	//   From this we could immediately discard the "allow to 192.0.2.3"
	//   policymap entry during policy calculation. This would satisfy the
	//   API constraint that deny rules take precedence over allow rules.
	//   However, this is not the case for ToFQDNs -- the IPs are not known
	//   until DNS resolution time by the selected application / endpoint.
	// - In order to make ToFQDNs policy implementation efficient, it uses
	//   a shorter incremental policy computation path that attempts to
	//   directly implement the ToFQDNs allow into a MapState entry without
	//   reaching back up to the L4Filter layer to iterate all selectors
	//   to determine traffic reachability for this newly learned IP.
	// - As such, when the new ToFQDNs allow for the 192.0.2.3 IP address
	//   is implemented, we must iterate back through all existing MapState
	//   entries to determine whether any of the other map entries already
	//   denies this traffic by virtue of the IP prefix being a superset of
	//   this new allow. This allows us to ensure that the broader CIDR
	//   deny semantics are correctly applied when there is a combination
	//   of CIDR deny rules and ToFQDNs allow rules.
	//
	// An alternative to this approach might be to change the ToFQDNs
	// policy calculation layer to reference back to the L4Filter layer,
	// and perhaps introduce additional CIDR caching somewhere there so
	// that this policy computation can be efficient while handling DNS
	// responses. As of the writing of this message, such there is no
	// active proposal to implement this proposal. As a result, any time
	// there is an incremental policy update for a new map entry, we must
	// iterate through all entries in the map and re-evaluate superset
	// relationships for deny entries to ensure that policy precedence is
	// correctly implemented between the new and old entries, taking into
	// account whether the identities may represent CIDRs that have a
	// superset relationship.
	return primaryIdentity == 0 && compareIdentity != 0 ||
		prefixesContainsAny(getNets(identities, primaryIdentity),
			getNets(identities, compareIdentity))
}

func (v *validator) isSupersetOf(a, d Key, identities Identities) {
	if a.TrafficDirection() != d.TrafficDirection() {
		panic("TrafficDirection mismatch")
	}
	if !identityIsSupersetOf(a.Identity, d.Identity, identities) {
		panic(fmt.Sprintf("superset mismatch %s !> %s",
			identities.GetPrefix(a.Identity).String(),
			identities.GetPrefix(d.Identity).String()))
	}
}

func (v *validator) isSupersetOrSame(a, d Key, identities Identities) {
	if a.TrafficDirection() != d.TrafficDirection() {
		panic("TrafficDirection mismatch")
	}
	if !(a.Identity == d.Identity ||
		identityIsSupersetOf(a.Identity, d.Identity, identities)) {
		panic(fmt.Sprintf("superset or equal mismatch %s !>= %s",
			identities.GetPrefix(a.Identity).String(),
			identities.GetPrefix(d.Identity).String()))
	}
}

func (v *validator) isAnyOrSame(a, d Key, identities Identities) {
	if a.TrafficDirection() != d.TrafficDirection() {
		panic("TrafficDirection mismatch")
	}
	if !(a.Identity == d.Identity || a.Identity == 0) {
		panic(fmt.Sprintf("ANY or equal mismatch %s !>= %s",
			identities.GetPrefix(a.Identity).String(),
			identities.GetPrefix(d.Identity).String()))
	}
}

func (v *validator) isBroader(a, d Key) {
	if a.TrafficDirection() != d.TrafficDirection() {
		panic("TrafficDirection mismatch")
	}

	// Do not consider non-matching protocols
	if !protocolsMatch(a, d) || !a.PortProtoIsBroader(d) {
		panic(fmt.Sprintf("descendant (%v) is not narrower than ancestor (%v)", d, a))
	}
}

func (v *validator) isBroaderOrEqual(a, d Key) {
	if a.TrafficDirection() != d.TrafficDirection() {
		panic("TrafficDirection mismatch")
	}

	// Do not consider non-matching protocols
	if !protocolsMatch(a, d) || !(a.PortProtoIsBroader(d) || a.PortProtoIsEqual(d)) {
		panic(fmt.Sprintf("descendant (%v) is not narrower than ancestor (%v)", d, a))
	}
}

func TestDenyPreferredInsertLogic(t *testing.T) {
	td := newTestData()
	td.bootstrapRepo(GenerateCIDRDenyRules, 1000, t)
	p, _ := td.repo.resolvePolicyLocked(fooIdentity)

	mapState := newMapState()
	mapState.validator = &validator{} // insert validator

	// This is DistillPolicy, but with MapState validator injected
	epPolicy := &EndpointPolicy{
		selectorPolicy: p,
		policyMapState: mapState,
		PolicyOwner:    DummyOwner{},
	}

	if !p.IngressPolicyEnabled || !p.EgressPolicyEnabled {
		epPolicy.policyMapState.allowAllIdentities(
			!p.IngressPolicyEnabled, !p.EgressPolicyEnabled)
	}
	p.insertUser(epPolicy)

	p.SelectorCache.mutex.RLock()
	epPolicy.toMapState()
	epPolicy.policyMapState.determineAllowLocalhostIngress()
	p.SelectorCache.mutex.RUnlock()

	n := epPolicy.policyMapState.Len()
	p.Detach()
	assert.True(t, n > 0)
}
