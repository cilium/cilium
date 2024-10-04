// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/identity"
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

// WithOwners replaces owners of 'e' with 'owners'.
// No owners is represented with a 'nil' map.
func (e MapStateEntry) WithOwners(owners ...MapStateOwner) MapStateEntry {
	e.owners = set.NewSet[MapStateOwner](owners...)
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
	e.owners.Clear()
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
	require.False(t, k.IsEgress())

	k = EgressKey()
	require.False(t, k.IsIngress())
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
	testMapState := func(initMap MapStateMap) *mapState {
		return newMapState().withState(initMap)
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
		{
			name: "test-15a - L3 port-range allow KV should not overwrite a wildcard deny entry",
			ms: testMapState(MapStateMap{
				ingressKey(0, 3, 80, 0): {
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
				ingressKey(0, 3, 80, 0): {
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
			name: "test-15b-reverse - L3 port-range allow KV should not overwrite a wildcard deny entry",
			ms: testMapState(MapStateMap{
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			args: args{
				key: ingressKey(0, 3, 80, 0),
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
					IsDeny:           false,
				},
				ingressKey(0, 3, 80, 0): {
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           true,
				},
			}),
			wantAdds: Keys{
				ingressKey(0, 3, 80, 16): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
		},
		{
			name: "test-16a - No added entry for L3 port-range allow + wildcard allow entry",
			ms: testMapState(MapStateMap{
				ingressKey(0, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
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
				ingressKey(0, 3, 80, 0): {
					ProxyPort:        8080,
					priority:         8080,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
				ingressKey(1, 3, 64, 10): { // port range 64-127 (64/10)
					ProxyPort:        0,
					DerivedFromRules: nil,
					IsDeny:           false,
				},
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     MapStateMap{},
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
			ms.insert(k, v)
			return true
		})

		ms.denyPreferredInsertWithChanges(tt.args.key, tt.args.entry, denyRules, changes)
		ms.validatePortProto(t)
		require.Truef(t, ms.Equals(tt.want), "%s: MapState mismatch:\n%s", tt.name, ms.Diff(tt.want))
		require.EqualValuesf(t, tt.wantAdds, changes.Adds, "%s: Adds mismatch", tt.name)
		require.EqualValuesf(t, tt.wantDeletes, changes.Deletes, "%s: Deletes mismatch", tt.name)
		require.EqualValuesf(t, tt.wantOld, changes.Old, "%s: OldValues mismatch allows", tt.name)

		// Revert changes and check that we get the original mapstate
		ms.revertChanges(changes)
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
	return MapStateEntry{
		ProxyPort: proxyPort,
		priority:  proxyPort,
		Listener:  "",
		AuthType:  authType,
		IsDeny:    deny,
		owners:    set.NewSet(owners...),
	}
}

func TestMapState_AccumulateMapChangesDeny(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(identityCache)
	testMapState := func(initMap MapStateMap) *mapState {
		return newMapState().withState(initMap)
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
		name: "test-0 - Adding L4-only redirect allow key to an existing allow-all with L3-only deny",
		setup: testMapState(map[Key]MapStateEntry{
			AnyIngressKey():      allowEntry(0),
			ingressL3OnlyKey(41): denyEntry(0),
		}),
		args: []args{
			{cs: csFoo, adds: []int{0}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: true, deny: false},
		},
		state: testMapState(map[Key]MapStateEntry{
			AnyIngressKey():      allowEntry(0),
			ingressL3OnlyKey(41): denyEntry(0, csFoo).WithDependents(HttpIngressKey(41)),
			HttpIngressKey(0):    allowEntry(1, nil),
			HttpIngressKey(41):   denyEntry(0).WithOwners(ingressL3OnlyKey(41)),
		}),
		adds: Keys{
			HttpIngressKey(0):  {},
			HttpIngressKey(41): {},
		},
		deletes: Keys{},
	}, {
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
		name:      "test-2b - Adding Bar also selecting 42 (and 44)",
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

	epPolicy := &EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			SelectorCache: selectorCache,
		},
		PolicyOwner: DummyOwner{},
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
		epPolicy.policyMapState = policyMapState

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
		policyMaps.SyncMapChanges(versioned.LatestTx)
		handle, changes := policyMaps.consumeMapChanges(epPolicy, denyRules)
		if handle != nil {
			handle.Close()
		}
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equals(tt.state), "%s (MapState):\n%s", tt.name, policyMapState.Diff(tt.state))
		require.EqualValues(t, tt.adds, changes.Adds, tt.name+" (adds)")
		require.EqualValues(t, tt.deletes, changes.Deletes, tt.name+" (deletes)")
	}
}

func TestMapStateEntry(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)
	csWildcard := newTestCachedSelector("wildcard", true)

	entry := allowEntry(0, csFoo, csBar)
	require.True(t, entry.owners.Has(csFoo))
	require.True(t, entry.owners.Has(csBar))
	require.False(t, entry.owners.Has(csWildcard))

	entry.owners.Insert(csWildcard)
	require.True(t, entry.owners.Has(csFoo))
	require.True(t, entry.owners.Has(csBar))
	require.True(t, entry.owners.Has(csWildcard))

	entry.owners.Remove(csBar)
	require.True(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.True(t, entry.owners.Has(csWildcard))
	require.Equal(t, 2, entry.owners.Len())

	entry.owners.Remove(csFoo)
	require.False(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.True(t, entry.owners.Has(csWildcard))
	require.Equal(t, 1, entry.owners.Len())

	entry.owners.Remove(csWildcard)
	require.False(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.False(t, entry.owners.Has(csWildcard))
	require.Equal(t, 0, entry.owners.Len())

	require.Equal(t, set.NewSet[MapStateOwner](), entry.owners)

	entry = allowEntry(0, csFoo)
	require.False(t, entry.owners.Has(nil))
	require.True(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.False(t, entry.owners.Has(csWildcard))
	require.Equal(t, 1, entry.owners.Len())

	entry.owners.Insert(nil)
	require.True(t, entry.owners.Has(nil))
	require.True(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.False(t, entry.owners.Has(csWildcard))
	require.Equal(t, 2, entry.owners.Len())

	entry.owners.Insert(csWildcard)
	require.True(t, entry.owners.Has(nil))
	require.True(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.True(t, entry.owners.Has(csWildcard))
	require.Equal(t, 3, entry.owners.Len())

	entry.owners.Remove(csBar) // does not exist
	require.True(t, entry.owners.Has(nil))
	require.True(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.True(t, entry.owners.Has(csWildcard))
	require.Equal(t, 3, entry.owners.Len())

	entry.owners.Remove(csFoo)
	require.True(t, entry.owners.Has(nil))
	require.False(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.True(t, entry.owners.Has(csWildcard))
	require.Equal(t, 2, entry.owners.Len())

	entry.owners.Remove(csWildcard)
	require.True(t, entry.owners.Has(nil))
	require.False(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.False(t, entry.owners.Has(csWildcard))
	require.Equal(t, 1, entry.owners.Len())

	entry.owners.Remove(nil)
	require.False(t, entry.owners.Has(nil))
	require.False(t, entry.owners.Has(csFoo))
	require.False(t, entry.owners.Has(csBar))
	require.False(t, entry.owners.Has(csWildcard))
	require.Equal(t, 0, entry.owners.Len())
	require.Equal(t, set.NewSet[MapStateOwner](), entry.owners)
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
		return newMapState().withState(initMap)
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
			{cs: csBar, adds: []int{42, 44}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: false, deny: false},
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
			{cs: csFoo, adds: []int{0}, proto: 6, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, redirect: true},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeAlwaysFail),
			egressKey(0, 6, 0, 0):   allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csBar).WithDefaultAuthType(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(0, 6, 0, 0):   {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5b - auth type propagation from the most specific superset - reverse",
		args: []args{
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, redirect: true},
			{cs: csFoo, adds: []int{0}, proto: 6, hasAuth: ExplicitAuthType, authType: AuthTypeSpire},
			{cs: csFoo, adds: []int{43}, hasAuth: ExplicitAuthType, authType: AuthTypeAlwaysFail},
		},
		state: testMapState(MapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry(0, csFoo).WithAuthType(AuthTypeAlwaysFail),
			egressKey(0, 6, 0, 0):   allowEntry(0, csFoo).WithAuthType(AuthTypeSpire),
			egressKey(43, 6, 80, 0): allowEntry(1, csBar).WithDefaultAuthType(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(0, 6, 0, 0):   {},
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

	epPolicy := &EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			SelectorCache: selectorCache,
		},
		PolicyOwner: DummyOwner{},
	}
	policyMapState := newMapState()

	for _, tt := range tests {
		policyMaps := MapChanges{}
		if !tt.continued {
			policyMapState = newMapState()
		}
		epPolicy.policyMapState = policyMapState

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
		policyMaps.SyncMapChanges(versioned.LatestTx)
		handle, changes := policyMaps.consumeMapChanges(epPolicy, authRules|denyRules)
		if handle != nil {
			handle.Close()
		}
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equals(tt.state), "%s (MapState):\n%s", tt.name, policyMapState.Diff(tt.state))
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
	// Mock the identities what would be selected by the world, IP, and subnet selectors

	// Selections for the label selector 'reserved:world'
	reservedWorldSelections := identity.NumericIdentitySlice{identity.ReservedIdentityWorld, worldIPIdentity, worldSubnetIdentity}

	// Selections for the CIDR selector 'cidr:192.0.2.3/32'
	worldIPSelections := identity.NumericIdentitySlice{worldIPIdentity}

	// Selections for the CIDR selector 'cidr:192.0.2.0/24'
	worldSubnetSelections := identity.NumericIdentitySlice{worldSubnetIdentity, worldIPIdentity}

	type action uint32
	const (
		noAction       = action(iota)
		insertAllowAll = action(1 << iota)
		insertA
		insertB
		insertAWithBProto
		insertAasB // Proto and entry from B
		insertBWithAProto
		insertBWithAProtoAsDeny
		worldIPl3only        // Do not expect L4 keys for IP covered by a subnet
		worldIPProtoOnly     // Do not expect port keys for IP covered by a subnet
		worldSubnetl3only    // Do not expect L4 keys for IP subnet
		worldSubnetProtoOnly // Do not expect port keys for IP subnet
		insertDenyWorld
		insertDenyWorldTCP
		insertDenyWorldHTTP
		insertBoth = insertA | insertB
	)

	type withAllowAll bool
	const (
		WithAllowAll    = withAllowAll(true)
		WithoutAllowAll = withAllowAll(false)
	)

	// these tests are based on the sheet https://docs.google.com/spreadsheets/d/1WANIoZGB48nryylQjjOw6lKjI80eVgPShrdMTMalLEw#gid=2109052536
	tests := []struct {
		name             string
		withAllowAll     withAllowAll
		aIdentities      identity.NumericIdentitySlice
		bIdentities      identity.NumericIdentitySlice
		aIsDeny, bIsDeny bool
		aPort            uint16
		aProto           u8proto.U8proto
		bPort            uint16
		bProto           u8proto.U8proto
		outcome          action
	}{
		// deny-allow insertions
		{"deny-allow: a superset a|b L3-only; subset allow inserted as deny", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 0, 0, 0, insertAllowAll | insertA},
		{"deny-allow: a superset a|b L3-only; without allow-all", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 0, 0, 0, insertA},

		{"deny-allow: b superset a|b L3-only", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a|b L3-only; without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 0, 0, 0, insertBoth},

		{"deny-allow: a superset a L3-only, b L4; subset allow inserted as deny", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 0, 0, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3-only, b L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 0, 0, 6, insertA},

		{"deny-allow: b superset a L3-only, b L4", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 0, 0, 6, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L4; without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 0, 0, 6, insertBoth | worldIPl3only},

		{"deny-allow: a superset a L3-only, b L3L4; subset allow not inserted", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 0, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3-only, b L3L4; without allow-all, subset allow not inserted", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 0, 80, 6, insertA},

		{"deny-allow: b superset a L3-only, b L3L4; IP allow not inserted", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 0, 80, 6, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L3L4; without allow-all, IP allow not inserted", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 0, 80, 6, insertBoth | worldIPl3only},

		{"deny-allow: a superset a L4, b L3-only", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth | insertBWithAProtoAsDeny},
		{"deny-allow: a superset a L4, b L3-only; without allow-all", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 6, 0, 0, insertBoth | insertBWithAProtoAsDeny},

		{"deny-allow: b superset a L4, b L3-only", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L3-only; without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 6, 0, 0, insertBoth},

		{"deny-allow: a superset a L4, b L4; subset allow inserted as deny", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 6, 0, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L4, b L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 6, 0, 6, insertA},

		{"deny-allow: b superset a L4, b L4", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L4; without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 6, 0, 6, insertBoth},

		{"deny-allow: a superset a L4, b L3L4; subset allow not inserted", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 6, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L4, b L3L4; without allow-all, subset allow not inserted", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 0, 6, 80, 6, insertA},

		{"deny-allow: b superset a L4, b L3L4", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 6, 80, 6, insertAllowAll | insertBoth | worldIPProtoOnly},
		{"deny-allow: b superset a L4, b L3L4; without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 0, 6, 80, 6, insertBoth | worldIPProtoOnly},

		{"deny-allow: a superset a L3L4, b L3-only", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth | insertBWithAProtoAsDeny},
		{"deny-allow: a superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 80, 6, 0, 0, insertBoth | insertBWithAProtoAsDeny},

		{"deny-allow: b superset a L3L4, b L3-only", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 80, 6, 0, 0, insertBoth},

		{"deny-allow: a superset a L3L4, b L4", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth | insertBWithAProtoAsDeny},
		{"deny-allow: a superset a L3L4, b L4; without allow-all", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 80, 6, 0, 6, insertBoth | insertBWithAProtoAsDeny},

		{"deny-allow: b superset a L3L4, b L4", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L4 without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 80, 6, 0, 6, insertBoth},

		{"deny-allow: a superset a L3L4, b L3L4", WithAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 80, 6, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3L4, b L3L4 without allow-all", WithoutAllowAll, reservedWorldSelections, worldSubnetSelections, true, false, 80, 6, 80, 6, insertA},

		{"deny-allow: b superset a L3L4, b L3L4", WithAllowAll, worldIPSelections, worldSubnetSelections, true, false, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3L4; without allow-all", WithoutAllowAll, worldIPSelections, worldSubnetSelections, true, false, 80, 6, 80, 6, insertBoth},

		// deny-deny insertions: Note: There is no dedundancy between different non-zero security IDs on the
		// datapath, even if one would be a CIDR subset of another. Situation would be different if we could
		// completely remove (or not add in the first place) the redundant ID from the ipcache so that
		// datapath could never assign that ID to a packet for policy enforcement.
		// These test case are left here for such future improvement.
		{"deny-deny: a superset a|b L3-only", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: a superset a|b L3-only; without allow-all", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 0, 0, 0, insertBoth},

		{"deny-deny: b superset a|b L3-only", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: b superset a|b L3-only; without allow-all", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 0, 0, 0, insertBoth},

		{"deny-deny: a superset a L3-only, b L4", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 0, 0, 6, insertAllowAll | insertA},
		{"deny-deny: a superset a L3-only, b L4; without allow-all", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 0, 0, 6, insertA},

		{"deny-deny: b superset a L3-only, b L4", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 0, 0, 6, insertAllowAll | insertBoth | worldIPl3only | worldSubnetl3only},
		{"deny-deny: b superset a L3-only, b L4; without allow-all", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 0, 0, 6, insertBoth | worldIPl3only | worldSubnetl3only},

		{"deny-deny: a superset a L3-only, b L3L4", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 0, 80, 6, insertAllowAll | insertA},
		{"deny-deny: a superset a L3-only, b L3L4; without allow-all", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 0, 80, 6, insertA},

		{"deny-deny: b superset a L3-only, b L3L4", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 0, 80, 6, insertAllowAll | insertBoth | worldIPl3only | worldSubnetl3only},
		{"deny-deny: b superset a L3-only, b L3L4; without allow-all", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 0, 80, 6, insertBoth | worldIPl3only | worldSubnetl3only},

		{"deny-deny: a superset a L4, b L3-only", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 6, 0, 0, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-deny: a superset a L4, b L3-only; without allow-all", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 6, 0, 0, insertBoth | worldIPl3only},

		{"deny-deny: b superset a L4, b L3-only", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 6, 0, 0, insertAllowAll | insertBoth | worldIPl3only | worldSubnetl3only},
		{"deny-deny: b superset a L4, b L3-only; without allow-all", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 6, 0, 0, insertBoth | worldIPl3only | worldSubnetl3only},

		{"deny-deny: a superset a L4, b L4", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L4, b L4", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 6, 0, 6, insertBoth},

		{"deny-deny: b superset a L4, b L4", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L4, b L4", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 6, 0, 6, insertBoth},

		{"deny-deny: a superset a L4, b L3L4", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 6, 80, 6, insertAllowAll | insertBoth | worldIPProtoOnly},
		{"deny-deny: a superset a L4, b L3L4; without allow-all", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 0, 6, 80, 6, insertBoth | worldIPProtoOnly},

		{"deny-deny: b superset a L4, b L3L4", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 6, 80, 6, insertAllowAll | insertBoth | worldIPProtoOnly | worldSubnetProtoOnly},
		{"deny-deny: b superset a L4, b L3L4; without allow-all", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 0, 6, 80, 6, insertBoth | worldIPProtoOnly | worldSubnetProtoOnly},

		{"deny-deny: a superset a L3L4, b L3-only", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 80, 6, 0, 0, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-deny: a superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 80, 6, 0, 0, insertBoth | worldIPl3only},

		{"deny-deny: b superset a L3L4, b L3-only", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 80, 6, 0, 0, insertAllowAll | insertBoth | worldIPl3only | worldSubnetl3only},
		{"deny-deny: b superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 80, 6, 0, 0, insertBoth | worldIPl3only | worldSubnetl3only},

		{"deny-deny: a superset a L3L4, b L4", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 80, 6, 0, 6, insertAllowAll | insertBoth | worldIPProtoOnly},
		{"deny-deny: a superset a L3L4, b L4; without allow-all", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 80, 6, 0, 6, insertBoth | worldIPProtoOnly},

		{"deny-deny: b superset a L3L4, b L4", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 80, 6, 0, 6, insertAllowAll | insertBoth | worldIPProtoOnly | worldSubnetProtoOnly},
		{"deny-deny: b superset a L3L4, b L4; without allow-all", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 80, 6, 0, 6, insertBoth | worldIPProtoOnly | worldSubnetProtoOnly},

		{"deny-deny: a superset a L3L4, b L3L4", WithAllowAll, worldSubnetSelections, worldIPSelections, true, true, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L3L4, b L3L4", WithoutAllowAll, worldSubnetSelections, worldIPSelections, true, true, 80, 6, 80, 6, insertBoth},

		{"deny-deny: b superset a L3L4, b L3L4", WithAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L3L4, b L3L4", WithoutAllowAll, worldSubnetSelections, reservedWorldSelections, true, true, 80, 6, 80, 6, insertBoth},

		// allow-allow insertions do not need tests as their affect on one another does not matter.
	}
	for _, tt := range tests {
		anyIngressKey := IngressKey()
		allowEntry := MapStateEntry{}
		var aKeys []Key
		for _, idA := range tt.aIdentities {
			if tt.outcome&worldIPl3only > 0 && idA == worldIPIdentity &&
				(tt.aProto != 0 || tt.aPort != 0) {
				continue
			}
			if tt.outcome&worldIPProtoOnly > 0 && idA == worldIPIdentity &&
				tt.aPort != 0 {
				continue
			}
			if tt.outcome&worldSubnetl3only > 0 && idA == worldSubnetIdentity &&
				(tt.aProto != 0 || tt.aPort != 0) {
				continue
			}
			if tt.outcome&worldSubnetProtoOnly > 0 && idA == worldSubnetIdentity &&
				tt.aPort != 0 {
				continue
			}
			aKeys = append(aKeys, IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort))
		}
		aEntry := MapStateEntry{IsDeny: tt.aIsDeny}
		var bKeys []Key
		for _, idB := range tt.bIdentities {
			if tt.outcome&worldIPl3only > 0 && idB == worldIPIdentity &&
				(tt.bProto != 0 || tt.bPort != 0) {
				continue
			}
			if tt.outcome&worldIPProtoOnly > 0 && idB == worldIPIdentity &&
				tt.bPort != 0 {
				continue
			}
			if tt.outcome&worldSubnetl3only > 0 && idB == worldSubnetIdentity &&
				(tt.bProto != 0 || tt.bPort != 0) {
				continue
			}
			if tt.outcome&worldSubnetProtoOnly > 0 && idB == worldSubnetIdentity &&
				tt.bPort != 0 {
				continue
			}
			bKeys = append(bKeys, IngressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort))
		}
		bEntry := MapStateEntry{IsDeny: tt.bIsDeny}
		expectedKeys := newMapState()
		if tt.outcome&insertAllowAll > 0 {
			expectedKeys.insert(anyIngressKey, allowEntry)
		}
		// insert allow expectations before deny expectations to manage overlap
		if tt.outcome&insertB > 0 {
			for _, bKey := range bKeys {
				expectedKeys.insert(bKey, bEntry)
			}
		}
		if tt.outcome&insertAasB > 0 {
			for _, bKey := range bKeys {
				for _, idA := range tt.aIdentities {
					if tt.outcome&worldIPl3only > 0 && idA == worldIPIdentity &&
						(tt.bProto != 0 || tt.bPort != 0) {
						continue
					}
					if tt.outcome&worldIPProtoOnly > 0 && idA == worldIPIdentity &&
						(tt.bPort != 0) {
						continue
					}
					if tt.outcome&worldSubnetl3only > 0 && idA == worldSubnetIdentity &&
						(tt.bProto != 0 || tt.bPort != 0) {
						continue
					}
					if tt.outcome&worldSubnetProtoOnly > 0 && idA == worldSubnetIdentity &&
						(tt.bPort != 0) {
						continue
					}
					aKeyWithBProto := IngressKey().WithIdentity(idA).WithPortProto(tt.bProto, tt.bPort)
					bEntryWithOwner := bEntry.WithOwners(bKey)
					bEntryWithDep := bEntry.WithDependents(aKeyWithBProto)

					expectedKeys.insert(bKey, bEntryWithDep)
					expectedKeys.insert(aKeyWithBProto, bEntryWithOwner)
				}
			}
		}
		if tt.outcome&insertBWithAProto > 0 {
			for _, idB := range tt.bIdentities {
				if tt.outcome&worldIPl3only > 0 && idB == worldIPIdentity &&
					(tt.aProto != 0 || tt.aPort != 0) {
					continue
				}
				if tt.outcome&worldIPProtoOnly > 0 && idB == worldIPIdentity &&
					(tt.aPort != 0) {
					continue
				}
				if tt.outcome&worldSubnetl3only > 0 && idB == worldSubnetIdentity &&
					(tt.aProto != 0 || tt.aPort != 0) {
					continue
				}
				if tt.outcome&worldSubnetProtoOnly > 0 && idB == worldSubnetIdentity &&
					(tt.aPort != 0) {
					continue
				}
				bKey := IngressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort)
				bKeyWithAProto := bKey.WithPortProto(tt.aProto, tt.aPort)
				bEntryWithProto := bEntry.WithOwners(bKey)
				bEntryWithDep := bEntry.WithDependents(bKeyWithAProto)

				expectedKeys.insert(bKey, bEntryWithDep)
				expectedKeys.insert(bKeyWithAProto, bEntryWithProto)
			}
		}
		if tt.outcome&insertA > 0 {
			for _, aKey := range aKeys {
				expectedKeys.insert(aKey, aEntry)
			}
		}
		if tt.outcome&insertAWithBProto > 0 {
			for _, idA := range tt.aIdentities {
				if tt.outcome&worldIPl3only > 0 && idA == worldIPIdentity &&
					(tt.bProto != 0 || tt.bPort != 0) {
					continue
				}
				if tt.outcome&worldIPProtoOnly > 0 && idA == worldIPIdentity &&
					(tt.bPort != 0) {
					continue
				}
				if tt.outcome&worldSubnetl3only > 0 && idA == worldSubnetIdentity &&
					(tt.bProto != 0 || tt.bPort != 0) {
					continue
				}
				if tt.outcome&worldSubnetProtoOnly > 0 && idA == worldSubnetIdentity &&
					(tt.bPort != 0) {
					continue
				}
				aKey := IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort)
				aKeyWithBProto := aKey.WithPortProto(tt.bProto, tt.bPort)
				aEntryWithProto := aEntry.WithOwners(aKey)
				aEntryWithDep := aEntry.WithDependents(aKeyWithBProto)

				expectedKeys.insert(aKey, aEntryWithDep)
				expectedKeys.insert(aKeyWithBProto, aEntryWithProto)
			}
		}
		if tt.outcome&insertBWithAProtoAsDeny > 0 {
			for _, aKey := range aKeys {
				for _, idB := range tt.bIdentities {
					if tt.outcome&worldIPl3only > 0 && idB == worldIPIdentity &&
						(tt.aProto != 0 || tt.aPort != 0) {
						continue
					}
					if tt.outcome&worldIPProtoOnly > 0 && idB == worldIPIdentity &&
						(tt.aPort != 0) {
						continue
					}
					if tt.outcome&worldSubnetl3only > 0 && idB == worldSubnetIdentity &&
						(tt.aProto != 0 || tt.aPort != 0) {
						continue
					}
					if tt.outcome&worldSubnetProtoOnly > 0 && idB == worldSubnetIdentity &&
						(tt.aPort != 0) {
						continue
					}
					bKey := IngressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort)
					bKeyWithAProto := bKey.WithPortProto(tt.aProto, tt.aPort)
					bEntryAsDeny := bEntry.WithOwners(aKey).asDeny()
					aEntryWithDep := aEntry

					aEntryWithDep.AddDependent(bKeyWithAProto)
					expectedKeys.insert(aKey, aEntryWithDep)
					expectedKeys.insert(bKeyWithAProto, bEntryAsDeny)
				}
			}
		}
		if tt.outcome&insertDenyWorld > 0 {
			worldIngressKey := IngressKey().WithIdentity(2)
			denyEntry := MapStateEntry{IsDeny: true}
			expectedKeys.insert(worldIngressKey, denyEntry)
		}
		if tt.outcome&insertDenyWorldTCP > 0 {
			worldIngressKey := IngressKey().WithIdentity(2).WithTCPPort(0)
			denyEntry := MapStateEntry{IsDeny: true}
			expectedKeys.insert(worldIngressKey, denyEntry)
		}
		if tt.outcome&insertDenyWorldHTTP > 0 {
			worldIngressKey := IngressKey().WithIdentity(2).WithTCPPort(80)
			denyEntry := MapStateEntry{IsDeny: true}
			expectedKeys.insert(worldIngressKey, denyEntry)
		}
		outcomeKeys := newMapState()

		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, allFeatures)
		}
		for _, idA := range tt.aIdentities {
			aKey := IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort)
			outcomeKeys.denyPreferredInsert(aKey, aEntry, allFeatures)
		}
		for _, idB := range tt.bIdentities {
			bKey := IngressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort)
			outcomeKeys.denyPreferredInsert(bKey, bEntry, allFeatures)
		}
		outcomeKeys.validatePortProto(t)
		if !expectedKeys.Equals(outcomeKeys) {
			fmt.Println("OUTCOME KEYS:")
			fmt.Println("DENIES:")
			for k, v := range outcomeKeys.denies.entries {
				fmt.Printf("%v: %v\n", k, v)
			}
			fmt.Println("ALLOWS:")
			for k, v := range outcomeKeys.allows.entries {
				fmt.Printf("%v: %v\n", k, v)
			}
		}

		require.True(t, expectedKeys.Equals(outcomeKeys), "%s (MapState):\n%s", tt.name, outcomeKeys.Diff(expectedKeys))

		// Test also with reverse insertion order
		outcomeKeys = newMapState()

		for _, idB := range tt.bIdentities {
			bKey := IngressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort)
			outcomeKeys.denyPreferredInsert(bKey, bEntry, allFeatures)
		}
		for _, idA := range tt.aIdentities {
			aKey := IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort)
			outcomeKeys.denyPreferredInsert(aKey, aEntry, allFeatures)
		}
		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, allFeatures)
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
		var aKeys []Key
		for _, idA := range tt.aIdentities {
			aKeys = append(aKeys, IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort))
		}
		aEntry := MapStateEntry{IsDeny: tt.aIsDeny}
		var bKeys []Key
		for _, idB := range tt.bIdentities {
			bKeys = append(bKeys, EgressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort))
		}
		bEntry := MapStateEntry{IsDeny: tt.bIsDeny}
		expectedKeys := newMapState()
		if tt.outcome&insertAllowAll > 0 {
			expectedKeys.insert(anyIngressKey, allowEntry)
			expectedKeys.insert(anyEgressKey, allowEntry)
		}
		for _, aKey := range aKeys {
			expectedKeys.insert(aKey, aEntry)
		}
		for _, bKey := range bKeys {
			expectedKeys.insert(bKey, bEntry)
		}

		outcomeKeys := newMapState()

		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, allFeatures)
			outcomeKeys.denyPreferredInsert(anyEgressKey, allowEntry, allFeatures)
		}
		for _, aKey := range aKeys {
			outcomeKeys.denyPreferredInsert(aKey, aEntry, allFeatures)
		}
		for _, bKey := range bKeys {
			outcomeKeys.denyPreferredInsert(bKey, bEntry, allFeatures)
		}
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equals(outcomeKeys), "%s different traffic directions (MapState):\n%s", tt.name, outcomeKeys.Diff(expectedKeys))

		// Test also with reverse insertion order
		outcomeKeys = newMapState()

		for _, bKey := range bKeys {
			outcomeKeys.denyPreferredInsert(bKey, bEntry, allFeatures)
		}
		for _, aKey := range aKeys {
			outcomeKeys.denyPreferredInsert(aKey, aEntry, allFeatures)
		}
		if tt.withAllowAll {
			outcomeKeys.denyPreferredInsert(anyEgressKey, allowEntry, allFeatures)
			outcomeKeys.denyPreferredInsert(anyIngressKey, allowEntry, allFeatures)
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

// TestDenyPreferredInsertLogic is now less valuable since we do not have the mapstate
// validator any more, but may still catch bugs.
func TestDenyPreferredInsertLogic(t *testing.T) {
	td := newTestData()
	td.bootstrapRepo(GenerateCIDRDenyRules, 1000, t)
	p, _ := td.repo.resolvePolicyLocked(fooIdentity)

	epPolicy := p.DistillPolicy(DummyOwner{}, false)
	epPolicy.Ready()

	n := epPolicy.policyMapState.Len()
	p.Detach()
	assert.Positive(t, n)
}
