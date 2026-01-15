// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func (e mapStateEntry) withLabels(lbls labels.LabelArrayList) mapStateEntry {
	e.derivedFromRules = makeRuleOrigin(lbls, nil)
	return e
}

// withExplicitAuth sets an explicit auth requirement
func (e mapStateEntry) withExplicitAuth(authType AuthType) mapStateEntry {
	e.AuthRequirement = authType.AsExplicitRequirement()
	return e
}

// withDerivedAuth sets a derived auth requirement
func (e mapStateEntry) withDerivedAuth(authType AuthType) mapStateEntry {
	e.AuthRequirement = authType.AsDerivedRequirement()
	return e
}

func (e mapStateEntry) WithProxyPort(proxyPort uint16) mapStateEntry {
	e.MapStateEntry = e.MapStateEntry.WithProxyPort(proxyPort)
	return e
}

func (e mapStateEntry) withLevel(priority types.Priority) mapStateEntry {
	e.MapStateEntry = e.MapStateEntry.WithPriority(priority)
	return e
}

func (e mapStateEntry) withPassPriority(priority, nextTierPriority types.Priority) mapStateEntry {
	e.passPrecedence = priority.ToPassPrecedence()
	e.nextTierPrecedence = nextTierPriority.ToPassPrecedence()
	return e
}

func (ms mapState) withState(initMap mapStateMap) mapState {
	for k, v := range initMap {
		ms.insert(k, v)
	}
	return ms
}

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
	ms.forEach(func(k Key, _ mapStateEntry) bool {
		if k.Nexthdr == 0 {
			require.Equal(t, uint16(0), k.DestPort)
		}
		return true
	})
}

func (e mapStateEntry) withHTTPProxyPort(proxyPort uint16) mapStateEntry {
	e.MapStateEntry = e.MapStateEntry.WithProxyPort(proxyPort).WithListenerPriority(ListenerPriorityHTTP)
	return e
}

func (e mapStateEntry) withProxyPortPriority(proxyPort uint16, priority ListenerPriority) mapStateEntry {
	e.MapStateEntry = e.MapStateEntry.WithProxyPort(proxyPort).WithListenerPriority(priority)
	return e
}

func TestMapState_insertWithChanges(t *testing.T) {
	type args struct {
		key   Key
		entry MapStateEntry
	}
	tests := []struct {
		name                  string
		ms, want              mapState
		wantAdds, wantDeletes Keys
		wantOld               mapStateMap
		args                  args
	}{
		{
			name: "test-1 - no KV added, map should remain the same",
			ms: testMapState(t, mapStateMap{
				IngressKey(): allowEntry(),
			}),
			args: args{
				key:   IngressKey(),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				IngressKey(): allowEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-2a - L3 allow KV should not overwrite deny entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): denyEntry(),
			}),
			args: args{
				key:   ingressL3OnlyKey(1),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1):     allowEntry(),
				ingressKey(1, 3, 80, 0): denyEntry(),
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-2b - L3 port-range allow KV should not overwrite deny entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
				ingressKey(1, 3, 80, 0):  denyEntry(),
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-3a - L3-L4 allow KV should not overwrite deny entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 80, 0),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-3b - L3-L4 port-range allow KV should not overwrite deny entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): denyEntry(), // port range 64-127 (64/10)
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): denyEntry(), // port range 64-127 (64/10)
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-4a - L3-L4 deny KV should overwrite allow entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 80, 0),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): denyEntry(),
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld: mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry(),
			},
		},
		{
			name: "test-4b - L3-L4 port-range deny KV should overwrite allow entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): denyEntry(), // port range 64-127 (64/10)
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry(),
			},
		},
		{
			name: "test-5a - L3 deny KV should overwrite all L3-L4 allow and L3 allow entries for the same L3",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry(),
				ingressL3OnlyKey(1):     allowEntry(),
				ingressKey(2, 3, 80, 0): allowEntry(),
				ingressL3OnlyKey(2):     allowEntry(),
			}),
			args: args{
				key:   ingressL3OnlyKey(1),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1):     denyEntry(),
				ingressKey(2, 3, 80, 0): allowEntry(),
				ingressL3OnlyKey(2):     allowEntry(),
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: mapStateMap{
				ingressL3OnlyKey(1):     allowEntry(),
				ingressKey(1, 3, 80, 0): allowEntry(),
			},
		},
		{
			name: "test-5b - L3 port-range deny KV should overwrite all L3-L4 allow and L3 allow entries for the same L3",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0):  allowEntry(),
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
				ingressKey(2, 3, 80, 0):  allowEntry(),
				ingressKey(2, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): denyEntry(), // port range 64-127 (64/10)
				ingressKey(2, 3, 80, 0):  allowEntry(),
				ingressKey(2, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
				ingressKey(1, 3, 80, 0):  allowEntry(),
			},
		},
		{
			name: "test-6a - L3 egress deny KV should not overwrite any existing ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry(),
				ingressL3OnlyKey(1):     allowEntry(),
				ingressKey(2, 3, 80, 0): allowEntry(),
				ingressL3OnlyKey(2):     allowEntry(),
			}),
			args: args{
				key:   egressL3OnlyKey(1),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry(),
				ingressL3OnlyKey(1):     allowEntry(),
				egressL3OnlyKey(1):      denyEntry(),
				ingressKey(2, 3, 80, 0): allowEntry(),
				ingressL3OnlyKey(2):     allowEntry(),
			}),
			wantAdds: Keys{
				egressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-6b - L3 egress port-range deny KV should not overwrite any existing ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0):  allowEntry(),
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
				ingressKey(2, 3, 80, 0):  allowEntry(),
				ingressKey(2, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
			}),
			args: args{
				key:   egressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0):  allowEntry(),
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
				egressKey(1, 3, 64, 10):  denyEntry(),  // port range 64-127 (64/10)
				ingressKey(2, 3, 80, 0):  allowEntry(),
				ingressKey(2, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
			}),
			wantAdds: Keys{
				egressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-7a - L3 ingress deny KV should not be overwritten by a L3-L4 ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 80, 0),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-7b - L3 ingress deny KV should not be overwritten by a L3-L4 port-range ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-8a - L3 ingress deny KV should not be overwritten by a L3-L4-L7 ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 80, 0),
				entry: AllowEntry.WithProxyPort(8080),
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-8b - L3 ingress deny KV should not be overwritten by a L3-L4-L7 port-range ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: AllowEntry.WithProxyPort(8080),
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-9a - L3 ingress deny KV should overwrite a L3-L4-L7 ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   ingressL3OnlyKey(1),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
			},
		},
		{
			name: "test-9b - L3 ingress deny KV should overwrite a L3-L4-L7 port-range ingress allow",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
			}),
			args: args{
				key:   ingressL3OnlyKey(1),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
			},
		},
		{
			name: "test-10a - L3 ingress deny KV should overwrite a L3-L4-L7 ingress allow and a L3-L4 deny",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
				ingressKey(1, 3, 80, 0): denyEntry(),
			}),
			args: args{
				key:   ingressL3OnlyKey(1),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
				ingressKey(1, 3, 80, 0): denyEntry(),
			},
		},
		{
			name: "test-10b - L3 ingress deny KV should overwrite a L3-L4-L7 port-range ingress allow and a L3-L4 port-range deny",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
				ingressKey(1, 3, 64, 10): denyEntry(),                          // port range 64-127 (64/10)
			}),
			args: args{
				key:   ingressL3OnlyKey(1),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressL3OnlyKey(1): denyEntry(),
			}),
			wantAdds: Keys{
				ingressL3OnlyKey(1): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
				ingressKey(1, 3, 64, 10): denyEntry(),                          // port range 64-127 (64/10)
			},
		},
		{
			name: "test-11a - L3 ingress allow should not be allowed if there is a L3 'all' deny",
			ms: testMapState(t, mapStateMap{
				egressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
				IngressKey():           denyEntry(),
			}),
			args: args{
				key:   ingressL3OnlyKey(100),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				egressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
				IngressKey():           denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-11b - L3 ingress allow should not be allowed if there is a L3 'all' deny",
			ms: testMapState(t, mapStateMap{
				egressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
				IngressKey():            denyEntry(),
			}),
			args: args{
				key:   ingressKey(100, 0, 0, 0),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				egressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
				IngressKey():            denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-12a - inserting a L3 'all' deny should delete all entries for that direction",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
				ingressKey(1, 3, 5, 0):  allowEntry().withHTTPProxyPort(8080),
				egressKey(100, 3, 5, 0): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   IngressKey(),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				IngressKey():            denyEntry(),
				egressKey(100, 3, 5, 0): allowEntry().withHTTPProxyPort(8080),
			}),
			wantAdds: Keys{
				IngressKey(): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
				ingressKey(1, 3, 5, 0):  struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
				ingressKey(1, 3, 5, 0):  allowEntry().withHTTPProxyPort(8080),
			},
		},
		{
			name: "test-12b - inserting a L3 'all' deny should delete all entries for that direction (including port ranges)",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
				ingressKey(1, 3, 4, 14):  allowEntry().withHTTPProxyPort(8080),
				egressKey(100, 3, 4, 14): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   IngressKey(),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				IngressKey():             denyEntry(),
				egressKey(100, 3, 4, 14): allowEntry().withHTTPProxyPort(8080),
			}),
			wantAdds: Keys{
				IngressKey(): struct{}{},
			},
			wantDeletes: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
				ingressKey(1, 3, 4, 14):  struct{}{},
			},
			wantOld: mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080), // port range 64-127 (64/10)
				ingressKey(1, 3, 4, 14):  allowEntry().withHTTPProxyPort(8080),
			},
		},
		{
			name: "test-13a - L3-L4-L7 ingress allow should overwrite a L3-L4-L7 ingress allow due to lower priority",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   ingressKey(1, 3, 80, 0),
				entry: AllowEntry.WithProxyPort(9090).WithListenerPriority(1),
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withProxyPortPriority(9090, 1),
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 80, 0): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld: mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
			},
		},
		{
			name: "test-13b - L3-L4-L7 port-range ingress allow should overwrite a L3-L4-L7 port-range ingress allow due to lower priority",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10),
				entry: AllowEntry.WithProxyPort(9090).WithListenerPriority(1),
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withProxyPortPriority(9090, 1),
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld: mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080),
			},
		},
		{
			name: "test-14a - L3-L4-L7 ingress allow should overwrite a L3-L4-L7 ingress allow due to higher priority on the same port",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   ingressKey(1, 3, 80, 0),
				entry: AllowEntry.WithProxyPort(8080).WithListenerPriority(1),
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withProxyPortPriority(8080, 1),
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 80, 0): struct{}{}, // precedence changed
			},
			wantDeletes: Keys{},
			wantOld: mapStateMap{
				ingressKey(1, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
			},
		},
		{
			name: "test-14b - L3-L4-L7 port-range ingress allow should overwrite a L3-L4-L7 port-range ingress allow due to higher priority on the same port",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10),
				entry: AllowEntry.WithProxyPort(8080).WithListenerPriority(1),
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withProxyPortPriority(8080, 1),
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{}, // precedence changed
			},
			wantDeletes: Keys{},
			wantOld: mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080),
			},
		},
		{
			name: "test-14c - L3-L4 ingress allow should not overwrite a L3-L4-L7 port-range ingress allow on overlapping port",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   ingressKey(1, 3, 80, 16),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry().withHTTPProxyPort(8080),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-15a - L3 port-range allow KV should not overwrite a wildcard deny entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(0, 3, 80, 0): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
				ingressKey(0, 3, 80, 0):  denyEntry(),
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-15b-reverse - L3 port-range allow KV should not overwrite a wildcard deny entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
			}),
			args: args{
				key:   ingressKey(0, 3, 80, 0),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
				ingressKey(0, 3, 80, 0):  denyEntry(),
			}),
			wantAdds: Keys{
				ingressKey(0, 3, 80, 16): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-16a - No added entry for L3 port-range allow + wildcard allow entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(0, 3, 80, 0): allowEntry().withHTTPProxyPort(8080),
			}),
			args: args{
				key:   ingressKey(1, 3, 64, 10), // port range 64-127 (64/10)
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(0, 3, 80, 0):  allowEntry().withHTTPProxyPort(8080),
				ingressKey(1, 3, 64, 10): allowEntry(), // port range 64-127 (64/10)
			}),
			wantAdds: Keys{
				ingressKey(1, 3, 64, 10): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-17 - Added entry for wildcarded port for the specified protocol",
			ms:   testMapState(t, mapStateMap{}),
			args: args{
				key:   ingressKey(1, 2, 0, 0),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 2, 0, 0): allowEntry(),
			}),
			wantAdds: Keys{
				ingressKey(1, 2, 0, 0): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-18 - Wildcard port entry should not overwrite deny entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 2, 0, 0): denyEntry(),
			}),
			args: args{
				key:   ingressKey(1, 2, 0, 0),
				entry: AllowEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 2, 0, 0): denyEntry(),
			}),
			wantAdds:    Keys{},
			wantDeletes: Keys{},
			wantOld:     mapStateMap{},
		},
		{
			name: "test-18 - Deny entry overwrites allow wildcard port entry",
			ms: testMapState(t, mapStateMap{
				ingressKey(1, 2, 0, 0): allowEntry(),
			}),
			args: args{
				key:   ingressKey(1, 2, 0, 0),
				entry: DenyEntry,
			},
			want: testMapState(t, mapStateMap{
				ingressKey(1, 2, 0, 0): denyEntry(),
			}),
			wantAdds: Keys{
				ingressKey(1, 2, 0, 0): struct{}{},
			},
			wantDeletes: Keys{},
			wantOld: mapStateMap{
				ingressKey(1, 2, 0, 0): allowEntry(),
			},
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		changes := ChangeState{
			Adds:    make(Keys),
			Deletes: make(Keys),
			old:     make(mapStateMap),
		}
		// copy the starting point
		ms := testMapState(t, make(mapStateMap, tt.ms.Len()))
		tt.ms.forEach(func(k Key, v mapStateEntry) bool {
			ms.insert(k, v)
			return true
		})

		entry := NewMapStateEntry(tt.args.entry).withLabels(labels.LabelArrayList{nil})
		ms.insertWithChanges(types.Priority(0).ToPassPrecedence(), tt.args.key, entry, denyRules, changes)
		ms.validatePortProto(t)
		require.Truef(t, ms.Equal(&tt.want), "%s: MapState mismatch:\n%s", tt.name, ms.diff(&tt.want))
		require.Equalf(t, tt.wantAdds, changes.Adds, "%s: Adds mismatch", tt.name)
		require.Equalf(t, tt.wantDeletes, changes.Deletes, "%s: Deletes mismatch", tt.name)
		require.Equalf(t, tt.wantOld, changes.old, "%s: OldValues mismatch allows", tt.name)

		// Revert changes and check that we get the original mapstate
		ms.revertChanges(changes)
		require.Truef(t, ms.Equal(&tt.ms), "%s: MapState mismatch:\n%s", tt.name, ms.diff(&tt.ms))
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

func TcpEgressKey(id identity.NumericIdentity) Key {
	return EgressKey().WithIdentity(id).WithTCPPort(0)
}

func allowEntry() mapStateEntry {
	return NewMapStateEntry(AllowEntry).withLabels(labels.LabelArrayList{nil})
}

func passEntry(priority, nextTierPriority types.Priority) mapStateEntry {
	return PassEntry(priority, nextTierPriority, NilRuleOrigin).withLabels(labels.LabelArrayList{nil})
}

func proxyEntryHTTP(proxyPort uint16) mapStateEntry {
	return NewMapStateEntry(AllowEntry.WithProxyPort(proxyPort).WithListenerPriority(ListenerPriorityHTTP)).withLabels(labels.LabelArrayList{nil})
}

func proxyEntryDNS(proxyPort uint16) mapStateEntry {
	return NewMapStateEntry(AllowEntry.WithProxyPort(proxyPort).WithListenerPriority(ListenerPriorityDNS)).withLabels(labels.LabelArrayList{nil})
}

func proxyEntryCRD(proxyPort uint16) mapStateEntry {
	return NewMapStateEntry(AllowEntry.WithProxyPort(proxyPort).WithListenerPriority(ListenerPriorityCRD)).withLabels(labels.LabelArrayList{nil})
}

func denyEntry() mapStateEntry {
	return NewMapStateEntry(DenyEntry).withLabels(labels.LabelArrayList{nil})
}

func TestMapState_AccumulateMapChangesDeny(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(t, hivetest.Logger(t), identityCache)

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		proto    u8proto.U8proto
		ingress  bool
		redirect ListenerPriority
		deny     bool
	}
	tests := []struct {
		continued bool // Start from the end state of the previous test
		name      string
		setup     mapState
		args      []args // changes applied, in order
		state     mapState
		adds      Keys
		deletes   Keys
	}{{
		name: "test-0 - Adding L4-only redirect allow key to an existing allow-all with L3-only deny",
		setup: testMapState(t, mapStateMap{
			AnyIngressKey():      allowEntry(),
			ingressL3OnlyKey(41): denyEntry(),
		}),
		args: []args{
			{cs: csFoo, adds: []int{0}, deletes: []int{}, port: 80, proto: 6, ingress: true, redirect: ListenerPriorityHTTP, deny: false},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():      allowEntry(),
			ingressL3OnlyKey(41): denyEntry(),
			HttpIngressKey(0):    proxyEntryHTTP(1),
		}),
		adds: Keys{
			HttpIngressKey(0): {},
		},
		deletes: Keys{},
	}, {
		name: "test-1a - Adding L3-deny to an existing allow-all with L4-only allow redirect map state entries",
		setup: testMapState(t, mapStateMap{
			AnyIngressKey():   allowEntry(),
			HttpIngressKey(0): proxyEntryHTTP(12345),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: ListenerPriorityHTTP, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():      allowEntry(),
			ingressL3OnlyKey(41): denyEntry(),
			HttpIngressKey(0):    proxyEntryHTTP(12345),
		}),
		adds: Keys{
			ingressL3OnlyKey(41): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1b - Adding 2nd identity",
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 0, proto: 0, ingress: true, redirect: ListenerPriorityHTTP, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():      allowEntry(),
			ingressL3OnlyKey(41): denyEntry(),
			ingressL3OnlyKey(42): denyEntry(),
			HttpIngressKey(0):    proxyEntryHTTP(12345),
		}),
		adds: Keys{
			ingressL3OnlyKey(42): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-1c - Removing the same key",
		args: []args{
			{cs: csFoo, adds: nil, deletes: []int{42}, port: 0, proto: 0, ingress: true, redirect: ListenerPriorityHTTP, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():      allowEntry(),
			ingressL3OnlyKey(41): denyEntry(),
			HttpIngressKey(0):    proxyEntryHTTP(12345),
		}),
		adds: Keys{},
		deletes: Keys{
			ingressL3OnlyKey(42): {},
		},
	}, {
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, deny: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(42): denyEntry(),
			HttpIngressKey(43): denyEntry(),
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
			{cs: csBar, adds: []int{42, 44}, deletes: []int{}, port: 80, proto: 6, ingress: true, deny: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(42): denyEntry(),
			HttpIngressKey(43): denyEntry(),
			HttpIngressKey(44): denyEntry(),
		}),
		adds: Keys{
			HttpIngressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2c - Deleting 42",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, deny: true},
			{cs: csBar, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true, deny: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(43): denyEntry(),
			HttpIngressKey(44): denyEntry(),
		}),
		adds: Keys{},
		deletes: Keys{
			HttpIngressKey(42): {},
		},
	}, {
		continued: true,
		name:      "test-2d - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: true, deny: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(43): denyEntry(),
			HttpIngressKey(44): denyEntry(),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-3a - egress allow with deny-L3",
		setup: testMapState(t, mapStateMap{
			AnyIngressKey():        allowEntry(),
			HostIngressKey():       allowEntry(),
			egressKey(42, 0, 0, 0): denyEntry(),
		}),
		args: []args{
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false, deny: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false, deny: false},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():        allowEntry(),
			HostIngressKey():       allowEntry(),
			egressKey(42, 0, 0, 0): denyEntry(),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-3b - egress allow DNS on another ID with deny-L3",
		args: []args{
			{cs: csBar, adds: []int{43}, deletes: []int{}, port: 53, proto: 17, ingress: false, deny: false},
			{cs: csBar, adds: []int{43}, deletes: []int{}, port: 53, proto: 6, ingress: false, deny: false},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():        allowEntry(),
			HostIngressKey():       allowEntry(),
			egressKey(42, 0, 0, 0): denyEntry(),
			DNSUDPEgressKey(43):    allowEntry(),
			DNSTCPEgressKey(43):    allowEntry(),
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
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP, deny: false},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():        allowEntry(),
			HostIngressKey():       allowEntry(),
			egressKey(42, 0, 0, 0): denyEntry(),
			DNSUDPEgressKey(43):    allowEntry(),
			DNSTCPEgressKey(43):    allowEntry(),
			HttpEgressKey(43):      proxyEntryHTTP(1),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-4a - Add L7 skipped due to covering L3 deny",
		setup: testMapState(t, mapStateMap{
			AnyIngressKey():        allowEntry(),
			HostIngressKey():       allowEntry(),
			egressKey(42, 0, 0, 0): denyEntry(),
		}),
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP, deny: false},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():        allowEntry(),
			HostIngressKey():       allowEntry(),
			egressKey(42, 0, 0, 0): denyEntry(),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-4b - Add & delete L7 skipped due to covering L3 deny",
		args: []args{
			{cs: csFoo, adds: []int{42}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP, deny: false},
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP, deny: false},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():        allowEntry(),
			HostIngressKey():       allowEntry(),
			egressKey(42, 0, 0, 0): denyEntry(),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		name: "test-5 - Adding L3-deny to an existing allow-all",
		setup: testMapState(t, mapStateMap{
			AnyIngressKey(): allowEntry(),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: true, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():      allowEntry(),
			ingressL3OnlyKey(41): denyEntry(),
		}),
		adds: Keys{
			ingressL3OnlyKey(41): {},
		},
		deletes: Keys{},
	}, {
		name: "test-6 - Multiple entries",
		setup: testMapState(t, mapStateMap{
			AnyEgressKey():     allowEntry(),
			HttpEgressKey(0):   proxyEntryHTTP(12345),
			DNSUDPEgressKey(0): proxyEntryDNS(12346),
		}),
		args: []args{
			{cs: csFoo, adds: []int{41}, deletes: []int{}, port: 0, proto: 0, ingress: false, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyEgressKey():         allowEntry(),
			egressKey(41, 0, 0, 0): denyEntry(),
			HttpEgressKey(0):       proxyEntryHTTP(12345),
			DNSUDPEgressKey(0):     proxyEntryDNS(12346),
		}),
		adds: Keys{
			egressKey(41, 0, 0, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			// {cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: ListenerPriorityHTTP, deny: false},
		},
		state: emptyMapState(hivetest.Logger(t)),
		adds:  Keys{
			// HttpIngressKey(42): allowEntry(),
		},
		deletes: Keys{
			// HttpIngressKey(43): allowEntry(),
		},
	},
	}

	epPolicy := &EndpointPolicy{
		SelectorPolicy: &selectorPolicy{
			SelectorCache: selectorCache,
		},
		PolicyOwner: DummyOwner{logger: hivetest.Logger(t)},
	}
	policyMapState := emptyMapState(hivetest.Logger(t))

	for _, tt := range tests {
		policyMaps := MapChanges{logger: hivetest.Logger(t)}
		if !tt.continued {
			if tt.setup.Valid() {
				policyMapState = tt.setup
			} else {
				policyMapState = testMapState(t, nil)
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
			key := KeyForDirection(dir).WithPortProto(x.proto, x.port)
			var proxyPort uint16
			var priority ListenerPriority
			if x.redirect != 0 {
				proxyPort = 1
				priority = x.redirect
			}
			verdict := types.Allow
			if x.deny {
				verdict = types.Deny
			}
			value := newMapStateEntry(0, types.MaxPriority, NilRuleOrigin, proxyPort, priority, verdict, NoAuthRequirement)
			policyMaps.AccumulateMapChanges(0, 0, adds, deletes, []Key{key}, value)
		}
		policyMaps.SyncMapChanges(types.MockSelectorSnapshot())
		_, changes := policyMaps.consumeMapChanges(epPolicy, denyRules)
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equal(&tt.state), "%s (MapState):\n%s", tt.name, policyMapState.diff(&tt.state))
		require.Equal(t, tt.adds, changes.Adds, tt.name+" (adds)")
		require.Equal(t, tt.deletes, changes.Deletes, tt.name+" (deletes)")
	}
}

func TestMapState_AccumulateMapChanges(t *testing.T) {
	csFoo := newTestCachedSelector("Foo", false)
	csBar := newTestCachedSelector("Bar", false)
	csWildcard := newTestCachedSelector("wildcard", true)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
	}
	selectorCache := testNewSelectorCache(t, hivetest.Logger(t), identityCache)

	type args struct {
		cs       *testCachedSelector
		adds     []int
		deletes  []int
		port     uint16
		prefix   uint8
		proto    u8proto.U8proto
		ingress  bool
		redirect ListenerPriority
		deny     bool
		authReq  AuthRequirement
		level    types.Priority
	}
	tests := []struct {
		continued bool // Start from the end state of the previous test
		name      string
		args      []args // changes applied, in order
		state     mapState
		adds      Keys
		deletes   Keys
	}{{
		name: "test-2a - Adding 2 identities, and deleting a nonexisting key on an empty state",
		args: []args{
			{cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(42): allowEntry(),
			HttpIngressKey(43): allowEntry(),
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
			{cs: csBar, adds: []int{42, 44}, deletes: []int{}, port: 80, proto: 6, ingress: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(42): allowEntry(),
			HttpIngressKey(43): allowEntry(),
			HttpIngressKey(44): allowEntry(),
		}),
		adds: Keys{
			HttpIngressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-2c - Deleting 42",
		args: []args{
			{cs: csFoo, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true},
			{cs: csBar, adds: []int{}, deletes: []int{42}, port: 80, proto: 6, ingress: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(43): allowEntry(),
			HttpIngressKey(44): allowEntry(),
		}),
		adds: Keys{},
		deletes: Keys{
			HttpIngressKey(42): {},
		},
	}, {
		continued: true,
		name:      "test-2f - Adding an entry that already exists, no adds",
		args: []args{
			{cs: csBar, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: true},
		},
		state: testMapState(t, mapStateMap{
			HttpIngressKey(43): allowEntry(),
			HttpIngressKey(44): allowEntry(),
		}),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-3a - egress HTTP proxy (setup)",
		args: []args{
			{cs: nil, adds: []int{0}, deletes: []int{}, port: 0, proto: 0, ingress: true},
			{cs: nil, adds: []int{1}, deletes: []int{}, port: 0, proto: 0, ingress: true},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 17, ingress: false},
			{cs: csBar, adds: []int{42}, deletes: []int{}, port: 53, proto: 6, ingress: false},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():     allowEntry(),
			HostIngressKey():    allowEntry(),
			DNSUDPEgressKey(42): allowEntry(),
			DNSTCPEgressKey(42): allowEntry(),
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
			{cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			AnyIngressKey():     allowEntry(),
			HostIngressKey():    allowEntry(),
			DNSUDPEgressKey(42): allowEntry(),
			DNSTCPEgressKey(42): allowEntry(),
			HttpEgressKey(43):   proxyEntryHTTP(1),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-4a - Add & delete; delete cancels the add in reply",
		args: []args{
			{cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
			{cs: csFoo, adds: []int{}, deletes: []int{44}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
		},
		state:   emptyMapState(hivetest.Logger(t)),
		adds:    Keys{},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-4b - Add, delete, & add; delete suppressed",
		args: []args{
			{cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
			{cs: csFoo, adds: []int{}, deletes: []int{44}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
			{cs: csFoo, adds: []int{44}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			HttpEgressKey(44): proxyEntryHTTP(1),
		}),
		adds: Keys{
			HttpEgressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-4c - Later order deny all does not prevent allow",
		args: []args{
			{level: 2, cs: nil, adds: []int{0}, deletes: []int{}, ingress: false, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyEgressKey():    denyEntry().withLevel(2),
			HttpEgressKey(44): proxyEntryHTTP(1),
		}),
		adds: Keys{
			AnyEgressKey(): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-4d - Later order deny does not override allow",
		args: []args{
			{level: 1, cs: csFoo, adds: []int{44}, deletes: []int{}, port: 0, proto: 6, ingress: false, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyEgressKey():    denyEntry().withLevel(2),
			TcpEgressKey(44):  denyEntry().withLevel(1),
			HttpEgressKey(44): proxyEntryHTTP(1),
		}),
		adds: Keys{
			TcpEgressKey(44): {},
		},
		deletes: Keys{},
	}, {
		continued: true,
		name:      "test-4e - deleting 0-order allow leaves the deny in place",
		args: []args{
			{level: 0, cs: csFoo, adds: []int{}, deletes: []int{44}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
			{level: 1, cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, deny: true},
		},
		state: testMapState(t, mapStateMap{
			AnyEgressKey():    denyEntry().withLevel(2),
			TcpEgressKey(44):  denyEntry().withLevel(1),
			HttpEgressKey(43): denyEntry().withLevel(1),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{
			HttpEgressKey(44): {},
		},
	}, {
		continued: true,
		name:      "test-4f - earlier order allow overrides later order deny",
		args: []args{
			{level: 0, cs: csFoo, adds: []int{43}, deletes: []int{}, port: 80, proto: 6, ingress: false, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			AnyEgressKey():    denyEntry().withLevel(2),
			TcpEgressKey(44):  denyEntry().withLevel(1),
			HttpEgressKey(43): proxyEntryHTTP(1).withLevel(0),
		}),
		adds: Keys{
			HttpEgressKey(43): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5a - auth type propagation from the most specific covering key",
		args: []args{
			{cs: csFoo, adds: []int{43}, authReq: AuthTypeAlwaysFail.AsExplicitRequirement()},
			{cs: csFoo, adds: []int{0}, proto: 6, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry().withExplicitAuth(AuthTypeAlwaysFail),
			egressKey(0, 6, 0, 0):   allowEntry().withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 80, 0): proxyEntryHTTP(1).withDerivedAuth(AuthTypeAlwaysFail),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(0, 6, 0, 0):   {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5a-r - auth type propagation from the most specific covering key - reverse",
		args: []args{
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, redirect: ListenerPriorityHTTP},
			{cs: csFoo, adds: []int{0}, proto: 6, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csFoo, adds: []int{43}, authReq: AuthTypeAlwaysFail.AsExplicitRequirement()},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 0, 0, 0):  allowEntry().withExplicitAuth(AuthTypeAlwaysFail),
			egressKey(0, 6, 0, 0):   allowEntry().withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 80, 0): proxyEntryHTTP(1).withDerivedAuth(AuthTypeAlwaysFail),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0):  {},
			egressKey(0, 6, 0, 0):   {},
			egressKey(43, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5b - higher priority proxy port override with auth entries",
		args: []args{
			{cs: csFoo, adds: []int{43}, proto: 6, redirect: ListenerPriorityHTTP},
			// lower priority redirect (ListenerPriorityCRD) is overridden by ListenerPriorityHTTP
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityCRD},
			// but more specific entries with different auth are not
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csBar, adds: []int{43}, port: 81, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0): proxyEntryHTTP(1),
			// egressKey(43, 6, 80, 12): proxyEntryCRD(1),
			egressKey(43, 6, 80, 0): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 81, 0): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0): {},
			// egressKey(43, 6, 80, 12): {},
			egressKey(43, 6, 80, 16): {},
			egressKey(43, 6, 81, 16): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5b-r - higher priority proxy port override with auth entries - reverse",
		args: []args{
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 80, 12): proxyEntryHTTP(1),
			egressKey(43, 6, 80, 0):  proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 80, 12): {},
			egressKey(43, 6, 80, 0):  {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5c - higher priority proxy port not overridden with auth entries",
		args: []args{
			{cs: csFoo, adds: []int{43}, proto: 6, redirect: ListenerPriorityCRD},
			// higher priority redirect (ListenerPriorityHTTP) is not overridden by ListenerPriorityCRD
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityHTTP},
			// more specific entries with different auth are not overridden
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csBar, adds: []int{43}, port: 81, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0):   proxyEntryCRD(1),
			egressKey(43, 6, 80, 12): proxyEntryHTTP(1),
			egressKey(43, 6, 80, 0):  proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 81, 0):  proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):   {},
			egressKey(43, 6, 80, 12): {},
			egressKey(43, 6, 80, 16): {},
			egressKey(43, 6, 81, 16): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5c-r - higher priority proxy port not overridden with auth entries - reverse",
		args: []args{
			// more specific entries with different auth are not overridden
			{cs: csBar, adds: []int{43}, port: 81, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			// higher priority redirect (ListenerPriorityHTTP) is not overridden by ListenerPriorityCRD
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityHTTP},
			{cs: csFoo, adds: []int{43}, proto: 6, redirect: ListenerPriorityCRD},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0):   proxyEntryCRD(1),
			egressKey(43, 6, 80, 12): proxyEntryHTTP(1),
			egressKey(43, 6, 80, 0):  proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 81, 0):  proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):   {},
			egressKey(43, 6, 80, 12): {},
			egressKey(43, 6, 80, 16): {},
			egressKey(43, 6, 81, 16): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5d - higher priority proxy port propagation to auth entries",
		args: []args{
			{cs: csFoo, adds: []int{43}, proto: 6, redirect: ListenerPriorityHTTP},
			// lower priority redirect (ListenerPriorityCRD) is overridden by ListenerPriorityHTTP redirect, but kept due to different auth requirement
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityCRD, authReq: AuthTypeSpire.AsExplicitRequirement()},
			// but more specific entries without redirect and the same auth are not added
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csBar, adds: []int{43}, port: 81, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0):   proxyEntryHTTP(1),
			egressKey(43, 6, 80, 12): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 80, 16): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 81, 16): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):   {},
			egressKey(43, 6, 80, 12): {},
			egressKey(43, 6, 80, 16): {},
			egressKey(43, 6, 81, 16): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5d-r - higher priority proxy port propagation to auth entries - reverse",
		args: []args{
			{cs: csBar, adds: []int{43}, port: 81, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityCRD, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csFoo, adds: []int{43}, proto: 6, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0):   proxyEntryHTTP(1),
			egressKey(43, 6, 80, 12): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 80, 16): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
			egressKey(43, 6, 81, 16): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):   {},
			egressKey(43, 6, 80, 12): {},
			egressKey(43, 6, 80, 16): {},
			egressKey(43, 6, 81, 16): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5e - higher priority proxy port propagation to auth proxy entry",
		args: []args{
			{cs: csFoo, adds: []int{43}, proto: 6, redirect: ListenerPriorityHTTP},
			// lower priority redirect (ListenerPriorityCRD) is overridden by ListenerPriorityHTTP redirect, but kept due to different auth requirement
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityCRD, authReq: AuthTypeSpire.AsExplicitRequirement()},
			// but more specific entries with same auth are not added
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16},
			{cs: csBar, adds: []int{43}, port: 81, proto: 6, prefix: 16},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0):   proxyEntryHTTP(1),
			egressKey(43, 6, 80, 12): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):   {},
			egressKey(43, 6, 80, 12): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-5e-r - higher priority proxy port propagation to auth proxy entry - reverse",
		args: []args{
			{cs: csBar, adds: []int{43}, port: 81, proto: 6, prefix: 16},
			{cs: csBar, adds: []int{43}, port: 80, proto: 6, prefix: 16},
			{cs: csFoo, adds: []int{43}, port: 80, proto: 6, prefix: 12, redirect: ListenerPriorityCRD, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csFoo, adds: []int{43}, proto: 6, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0):   proxyEntryHTTP(1),
			egressKey(43, 6, 80, 12): proxyEntryHTTP(1).withExplicitAuth(AuthTypeSpire),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0):   {},
			egressKey(43, 6, 80, 12): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-6a - L3-only explicit auth type and L4-only without",
		args: []args{
			{cs: csFoo, adds: []int{43}, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 0, 0, 0): allowEntry().withExplicitAuth(AuthTypeSpire),
			egressKey(0, 6, 80, 0): proxyEntryHTTP(1),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0): {},
			egressKey(0, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-6a-r - L3-only explicit auth type and L4-only without - reverse",
		args: []args{
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: ListenerPriorityHTTP},
			{cs: csFoo, adds: []int{43}, authReq: AuthTypeSpire.AsExplicitRequirement()},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 0, 0, 0): allowEntry().withExplicitAuth(AuthTypeSpire),
			egressKey(0, 6, 80, 0): proxyEntryHTTP(1),
		}),
		adds: Keys{
			egressKey(43, 0, 0, 0): {},
			egressKey(0, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-7a - L3/proto explicit auth type and L4-only without",
		args: []args{
			{cs: csFoo, adds: []int{43}, proto: 6, authReq: AuthTypeSpire.AsExplicitRequirement()},
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: ListenerPriorityHTTP},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0): allowEntry().withExplicitAuth(AuthTypeSpire),
			egressKey(0, 6, 80, 0): proxyEntryHTTP(1),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0): {},
			egressKey(0, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-7a-1 - L3/proto explicit auth type and L4-only without - reverse",
		args: []args{
			{cs: csWildcard, adds: []int{0}, port: 80, proto: 6, redirect: ListenerPriorityHTTP},
			{cs: csFoo, adds: []int{43}, proto: 6, authReq: AuthTypeSpire.AsExplicitRequirement()},
		},
		state: testMapState(t, mapStateMap{
			egressKey(43, 6, 0, 0): allowEntry().withExplicitAuth(AuthTypeSpire),
			egressKey(0, 6, 80, 0): proxyEntryHTTP(1),
		}),
		adds: Keys{
			egressKey(43, 6, 0, 0): {},
			egressKey(0, 6, 80, 0): {},
		},
		deletes: Keys{},
	}, {
		continued: false,
		name:      "test-n - title",
		args:      []args{
			// {cs: csFoo, adds: []int{42, 43}, deletes: []int{50}, port: 80, proto: 6, ingress: true, redirect: ListenerPriorityHTTP, deny: false},
		},
		state: emptyMapState(hivetest.Logger(t)),
		adds:  Keys{
			// HttpIngressKey(42): allowEntry(),
		},
		deletes: Keys{
			// HttpIngressKey(43): allowEntry(),
		},
	},
	}

	epPolicy := &EndpointPolicy{
		SelectorPolicy: &selectorPolicy{
			SelectorCache: selectorCache,
		},
		PolicyOwner: DummyOwner{logger: hivetest.Logger(t)},
	}
	policyMapState := emptyMapState(hivetest.Logger(t))

	for _, tt := range tests {
		t.Log(tt.name)
		policyMaps := MapChanges{logger: hivetest.Logger(t)}
		if !tt.continued {
			policyMapState = emptyMapState(hivetest.Logger(t))
		}
		epPolicy.policyMapState = policyMapState

		for _, x := range tt.args {
			dir := trafficdirection.Egress
			if x.ingress {
				dir = trafficdirection.Ingress
			}
			adds := x.cs.addSelections(x.adds...)
			deletes := x.cs.deleteSelections(x.deletes...)
			key := KeyForDirection(dir).WithPortProtoPrefix(x.proto, x.port, x.prefix)
			var proxyPort uint16
			var priority ListenerPriority
			if x.redirect != 0 {
				proxyPort = 1
				priority = x.redirect
			}
			verdict := types.Allow
			if x.deny {
				verdict = types.Deny
			}
			value := newMapStateEntry(x.level, types.MaxPriority, NilRuleOrigin, proxyPort, priority, verdict, x.authReq)
			policyMaps.AccumulateMapChanges(0, 0, adds, deletes, []Key{key}, value)
		}
		policyMaps.SyncMapChanges(types.MockSelectorSnapshot())
		_, changes := policyMaps.consumeMapChanges(epPolicy, authRules|denyRules|redirectRules)
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equal(&tt.state), "%s (MapState):\n%s", tt.name, policyMapState.diff(&tt.state))
		require.Equal(t, tt.adds, changes.Adds, tt.name+" (adds)")
		require.Equal(t, tt.deletes, changes.Deletes, tt.name+" (deletes)")
	}

	// repeat tests without the auth feature set when not actually used so that both code paths get tested
	authFeatureUsed := false
	for _, tt := range tests {
		t.Log(tt.name + " (without auth feature)")
		policyMaps := MapChanges{logger: hivetest.Logger(t)}
		if !tt.continued {
			authFeatureUsed = false
			policyMapState = emptyMapState(hivetest.Logger(t))
		}
		epPolicy.policyMapState = policyMapState

		for _, x := range tt.args {
			dir := trafficdirection.Egress
			if x.ingress {
				dir = trafficdirection.Ingress
			}
			adds := x.cs.addSelections(x.adds...)
			deletes := x.cs.deleteSelections(x.deletes...)
			key := KeyForDirection(dir).WithPortProtoPrefix(x.proto, x.port, x.prefix)
			var proxyPort uint16
			var priority ListenerPriority
			if x.redirect != 0 {
				proxyPort = 1
				priority = x.redirect
			}
			if x.authReq != NoAuthRequirement {
				authFeatureUsed = true
			}
			verdict := types.Allow
			if x.deny {
				verdict = types.Deny
			}
			value := newMapStateEntry(x.level, types.MaxPriority, NilRuleOrigin, proxyPort, priority, verdict, x.authReq)
			policyMaps.AccumulateMapChanges(0, 0, adds, deletes, []Key{key}, value)
		}
		policyMaps.SyncMapChanges(types.MockSelectorSnapshot())
		features := denyRules | redirectRules
		if authFeatureUsed {
			features |= authRules
		}
		_, changes := policyMaps.consumeMapChanges(epPolicy, features)
		policyMapState.validatePortProto(t)
		require.True(t, policyMapState.Equal(&tt.state), "%s (MapState):\n%s", tt.name, policyMapState.diff(&tt.state))
		require.Equal(t, tt.adds, changes.Adds, tt.name+" (adds)")
		require.Equal(t, tt.deletes, changes.Deletes, tt.name+" (deletes)")
	}
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
		worldIPl3only        // Do not expect L4 keys for IP covered by a subnet
		worldIPProtoOnly     // Do not expect port keys for IP covered by a subnet
		worldSubnetl3only    // Do not expect L4 keys for IP subnet
		worldSubnetProtoOnly // Do not expect port keys for IP subnet
		insertDenyWorld
		insertDenyWorldTCP
		insertDenyWorldHTTP
		insertAL3NotInB
		insertBL3NotInA
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
		allowAllLevel    types.Priority
		aIdentities      identity.NumericIdentitySlice
		aLevel           types.Priority
		bIdentities      identity.NumericIdentitySlice
		bLevel           types.Priority
		aIsDeny, bIsDeny bool
		aPort            uint16
		aProto           u8proto.U8proto
		bPort            uint16
		bProto           u8proto.U8proto
		outcome          action
	}{
		// deny-allow insertions
		{"deny-allow: a superset a|b L3-only; subset allow inserted as deny", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 0, insertAllowAll | insertA},
		{"deny-allow: a superset a|b L3-only; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertAllowAll | insertA},
		{"deny-allow: a superset a|b L3-only; later order keys not inserted", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertA},
		{"deny-allow: a superset a|b L3-only; later order allowAll", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: a superset a|b L3-only; without allow-all", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 0, insertA},
		{"deny-allow: a superset a|b L3-only; without allow-all, later order allow", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertA},
		{"deny-allow: a superset a|b L3-only; without allow-all, later order world deny inserted", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertBoth},

		{"deny-allow: b superset a|b L3-only", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a|b L3-only; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a|b L3-only; later order keys not inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertB},
		{"deny-allow: b superset a|b L3-only; later order less specific deny NOT inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertAllowAll | insertB},
		{"deny-allow: b superset a|b L3-only; without allow-all", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 0, insertBoth},
		{"deny-allow: b superset a|b L3-only; without allow-all, later order allow", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertBoth},
		{"deny-allow: b superset a|b L3-only; without allow-all, later order more specific deny NOT inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 0, insertB},

		{"deny-allow: a superset a L3-only, b L4; subset allow inserted as deny", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3-only, b L4; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3-only, b L4; later order keys not inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 0, 0, 0, 6, insertA},
		{"deny-allow: a superset a L3-only, b L4; earlier order allow inserted as allow", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L3-only, b L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 6, insertA},
		{"deny-allow: a superset a L3-only, b L4; without allow-all, later order subset allow inserted as deny", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertA},
		{"deny-allow: a superset a L3-only, b L4; without allow-all, earlier order allow inserted as allow", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertBoth},

		{"deny-allow: b superset a L3-only, b L4", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 6, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L4; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L4; later order wider keys inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertBoth},
		{"deny-allow: b superset a L3-only, b L4; later order more specific deny inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3-only, b L4; without allow-all, added deny TCP due to intersecting deny", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 0, 6, insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L4; without allow-all, added deny TCP due to intersecting deny", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L4; without allow-all, later order more specific deny inserted without denying TCP", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 0, 6, insertBoth},

		{"deny-allow: a superset a L3-only, b L3L4; subset allow inserted as deny", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3-only, b L3L4; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3-only, b L3L4; later order keys not inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 0, 0, 80, 6, insertA},
		{"deny-allow: a superset a L3-only, b L3L4; earlier order allow inserted as allow", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L3-only, b L3L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 80, 6, insertA},
		{"deny-allow: a superset a L3-only, b L3L4; without allow-all, later order subset allow inserted as deny", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertA},
		{"deny-allow: a superset a L3-only, b L3L4; without allow-all, earlier order allow inserted as allow", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertBoth},

		{"deny-allow: b superset a L3-only, b L3L4; IP allow not inserted", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 80, 6, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L3L4; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertAllowAll | insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L3L4; later order wider keys inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertBoth},
		{"deny-allow: b superset a L3-only, b L3L4; later order allow-all, more specific deny inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3-only, b L3L4; without allow-all, IP allow not inserted", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 0, 80, 6, insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L3L4; without allow-all, IP allow not inserted", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertBoth | worldIPl3only},
		{"deny-allow: b superset a L3-only, b L3L4; without allow-all, later order more specific deny inserted without denying TCP/80", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 0, 80, 6, insertBoth},

		{"deny-allow: a superset a L4, b L3-only", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L4, b L3-only; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L4, b L3-only; later order wider keys inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L4, b L3-only; later order allow-all, world deny inserted", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth | insertAL3NotInB},
		{"deny-allow: a superset a L4, b L3-only; without allow-all", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L4, b L3-only; without allow-all, later order allow the same", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L4, b L3-only; without allow-all, later order world/TCP deny inserted", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertBoth | insertAL3NotInB},

		{"deny-allow: b superset a L4, b L3-only", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L3-only; later order allows the same", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: b superset a L4, b L3-only; later order keys not inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertB},
		{"deny-allow: b superset a L4, b L3-only; later order more specific deny NOT inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertAllowAll | insertB},
		{"deny-allow: b superset a L4, b L3-only; without allow-all, more specific deny added", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: b superset a L4, b L3-only; without allow-all, later order allows the same", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertBoth},
		{"deny-allow: b superset a L4, b L3-only; without allow-all, later order more specific deny not inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 0, insertB},

		{"deny-allow: a superset a L4, b L4; subset allow inserted as deny", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L4, b L4; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L4, b L4; later order keys not inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 0, 6, 0, 6, insertA},
		{"deny-allow: a superset a L4, b L4; later order world deny inserted", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L4, b L4; without allow-all, subset allow inserted as deny", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 6, insertA},
		{"deny-allow: a superset a L4, b L4; without allow-all, later order subset allow inserted as deny", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertA},
		{"deny-allow: a superset a L4, b L4; without allow-all, earlier order allow inserted as allow", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertBoth},

		{"deny-allow: b superset a L4, b L4", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L4; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L4; later order keys not inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertB},
		{"deny-allow: b superset a L4, b L4; later order more specific deny NOT inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertAllowAll | insertB},
		{"deny-allow: b superset a L4, b L4; without allow-all", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 0, 6, insertBoth},
		{"deny-allow: b superset a L4, b L4; without allow-all, later order allows the same", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertBoth},
		{"deny-allow: b superset a L4, b L4; without allow-all, later order more specific deny NOT inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 0, 6, insertB},

		{"deny-allow: a superset a L4, b L3L4; subset allow not inserted", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L4, b L3L4; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L4, b L3L4; later order keys not inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 0, 6, 80, 6, insertA},
		{"deny-allow: a superset a L4, b L3L4; later order world deny inserted", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L4, b L3L4; without allow-all, subset allow not inserted", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 80, 6, insertA},
		{"deny-allow: a superset a L4, b L3L4; without allow-all, later order allows the same", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertA},
		{"deny-allow: a superset a L4, b L3L4; without allow-all, earlier order allow inserted as allow", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertBoth},

		{"deny-allow: b superset a L4, b L3L4", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 80, 6, insertAllowAll | insertBoth | worldIPProtoOnly},
		{"deny-allow: b superset a L4, b L3L4; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertAllowAll | insertBoth | worldIPProtoOnly},
		{"deny-allow: b superset a L4, b L3L4; later order wider keys inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertBoth},
		{"deny-allow: b superset a L4, b L3L4; later order more specific deny inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L4, b L3L4; without allow-all", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 0, 6, 80, 6, insertBoth | worldIPProtoOnly},
		{"deny-allow: b superset a L4, b L3L4; without allow-all, later order allows the same", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertBoth | worldIPProtoOnly},
		{"deny-allow: b superset a L4, b L3L4; without allow-all, later order more specific deny inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 0, 6, 80, 6, insertBoth},

		{"deny-allow: a superset a L3L4, b L3-only", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L3L4, b L3-only; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L3L4, b L3-only; later order wider keys inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 80, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L3L4, b L3-only; later order world deny inserted", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth | insertAL3NotInB},
		{"deny-allow: a superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L3L4, b L3-only; without allow-all, later order allows the same", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertBoth},
		{"deny-allow: a superset a L3L4, b L3-only; without allow-all, later order world deny inserted", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertBoth | insertAL3NotInB},

		{"deny-allow: b superset a L3L4, b L3-only", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3-only; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3-only; later order keys not inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertB},
		{"deny-allow: b superset a L3L4, b L3-only; later order more specific deny NOT inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertAllowAll | insertB},
		{"deny-allow: b superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 0, insertBoth},
		{"deny-allow: b superset a L3L4, b L3-only; without allow-all, later order allows the same", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertBoth},
		{"deny-allow: b superset a L3L4, b L3-only; without allow-all, later order more specific deny NOT inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 0, insertB},

		{"deny-allow: a superset a L3L4, b L4", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L3L4, b L4; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L3L4, b L4; later order wider keys inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 80, 6, 0, 6, insertBoth},
		{"deny-allow: a superset a L3L4, b L4; later order world deny inserted", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth | insertAL3NotInB},
		{"deny-allow: a superset a L3L4, b L4; without allow-all", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 6, insertBoth},
		{"deny-allow: a superset a L3L4, b L4; without allow-all, later order allows the same", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertBoth},
		{"deny-allow: a superset a L3L4, b L4; without allow-all, later order world deny inserted", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertBoth | insertAL3NotInB},

		{"deny-allow: b superset a L3L4, b L4", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L4; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L4; later order keys not inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertB},
		{"deny-allow: b superset a L3L4, b L4; later order more specific deny NOT inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertAllowAll | insertB},
		{"deny-allow: b superset a L3L4, b L4; without allow-all", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 0, 6, insertBoth},
		{"deny-allow: b superset a L3L4, b L4; without allow-all, later order allows the same", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertBoth},
		{"deny-allow: b superset a L3L4, b L4; without allow-all, later order more specific deny NOT inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 0, 6, insertB},

		{"deny-allow: a superset a L3L4, b L3L4", WithAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3L4, b L3L4; later order allows the same", WithAllowAll, 2, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertAllowAll | insertA},
		{"deny-allow: a superset a L3L4, b L3L4; later order keys not inserted", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 1, true, false, 80, 6, 80, 6, insertA},
		{"deny-allow: a superset a L3L4, b L3L4; later order world deny inserted", WithAllowAll, 3, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: a superset a L3L4, b L3L4; without allow-all", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 80, 6, insertA},
		{"deny-allow: a superset a L3L4, b L3L4; without allow-all, later order allows the same", WithoutAllowAll, 0, reservedWorldSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertA},
		{"deny-allow: a superset a L3L4, b L3L4; without allow-all, later order world deny inserted", WithoutAllowAll, 0, reservedWorldSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertBoth},

		{"deny-allow: b superset a L3L4, b L3L4", WithAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3L4; later order allows the same", WithAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-allow: b superset a L3L4, b L3L4; later order keys not inserted", WithoutAllowAll, 0, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertB},
		{"deny-allow: b superset a L3L4, b L3L4; later order more specific deny NOT inserted", WithAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertAllowAll | insertB},
		{"deny-allow: b superset a L3L4, b L3L4; without allow-all", WithoutAllowAll, 0, worldIPSelections, 0, worldSubnetSelections, 0, true, false, 80, 6, 80, 6, insertBoth},
		{"deny-allow: b superset a L3L4, b L3L4; without allow-all, later order allows the same", WithoutAllowAll, 2, worldIPSelections, 0, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertBoth},
		{"deny-allow: b superset a L3L4, b L3L4; without allow-all, later order more specific deny NOT inserted", WithoutAllowAll, 3, worldIPSelections, 2, worldSubnetSelections, 1, true, false, 80, 6, 80, 6, insertB},

		// deny-deny insertions: Note: There is no redundancy between different non-zero security IDs on the
		// datapath, even if one would be a CIDR subset of another. Situation would be different if we could
		// completely remove (or not add in the first place) the redundant ID from the ipcache so that
		// datapath could never assign that ID to a packet for policy enforcement.
		// These test case are left here for such future improvement.
		{"deny-deny: a superset a|b L3-only", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: a superset a|b L3-only; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 0, 0, 0, insertBoth},

		{"deny-deny: b superset a|b L3-only", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 0, 0, 0, insertAllowAll | insertBoth},
		{"deny-deny: b superset a|b L3-only; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 0, 0, 0, insertBoth},

		{"deny-deny: a superset a L3-only, b L4", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 0, 0, 6, insertAllowAll | insertA},
		{"deny-deny: a superset a L3-only, b L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 0, 0, 6, insertA},

		{"deny-deny: b superset a L3-only, b L4", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 0, 0, 6, insertAllowAll | insertBoth | insertBL3NotInA},
		{"deny-deny: b superset a L3-only, b L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 0, 0, 6, insertBoth | insertBL3NotInA},

		{"deny-deny: a superset a L3-only, b L3L4", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 0, 80, 6, insertAllowAll | insertA},
		{"deny-deny: a superset a L3-only, b L3L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 0, 80, 6, insertA},

		{"deny-deny: b superset a L3-only, b L3L4", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 0, 80, 6, insertAllowAll | insertBoth | insertBL3NotInA},
		{"deny-deny: b superset a L3-only, b L3L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 0, 80, 6, insertBoth | insertBL3NotInA},

		{"deny-deny: a superset a L4, b L3-only", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 6, 0, 0, insertAllowAll | insertBoth | insertAL3NotInB},
		{"deny-deny: a superset a L4, b L3-only; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 6, 0, 0, insertBoth | insertAL3NotInB},

		{"deny-deny: b superset a L4, b L3-only", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 6, 0, 0, insertAllowAll | insertB},
		{"deny-deny: b superset a L4, b L3-only; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 6, 0, 0, insertB},

		{"deny-deny: a superset a L4, b L4", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L4, b L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 6, 0, 6, insertBoth},

		{"deny-deny: b superset a L4, b L4", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 6, 0, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L4, b L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 6, 0, 6, insertBoth},

		{"deny-deny: a superset a L4, b L3L4", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 6, 80, 6, insertAllowAll | insertA},
		{"deny-deny: a superset a L4, b L3L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 0, 6, 80, 6, insertA},

		{"deny-deny: b superset a L4, b L3L4", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 6, 80, 6, insertAllowAll | insertBoth | insertBL3NotInA},
		{"deny-deny: b superset a L4, b L3L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 0, 6, 80, 6, insertBoth | insertBL3NotInA},

		{"deny-deny: a superset a L3L4, b L3-only", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 80, 6, 0, 0, insertAllowAll | insertBoth | insertAL3NotInB},
		{"deny-deny: a superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 80, 6, 0, 0, insertBoth | insertAL3NotInB},

		{"deny-deny: b superset a L3L4, b L3-only", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 80, 6, 0, 0, insertAllowAll | insertB},
		{"deny-deny: b superset a L3L4, b L3-only; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 80, 6, 0, 0, insertB},

		{"deny-deny: a superset a L3L4, b L4", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 80, 6, 0, 6, insertAllowAll | insertBoth | insertAL3NotInB},
		{"deny-deny: a superset a L3L4, b L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 80, 6, 0, 6, insertBoth | insertAL3NotInB},

		{"deny-deny: b superset a L3L4, b L4", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 80, 6, 0, 6, insertAllowAll | insertB},
		{"deny-deny: b superset a L3L4, b L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 80, 6, 0, 6, insertB},

		{"deny-deny: a superset a L3L4, b L3L4", WithAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: a superset a L3L4, b L3L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, worldIPSelections, 0, true, true, 80, 6, 80, 6, insertBoth},

		{"deny-deny: b superset a L3L4, b L3L4", WithAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 80, 6, 80, 6, insertAllowAll | insertBoth},
		{"deny-deny: b superset a L3L4, b L3L4; without allow-all", WithoutAllowAll, 0, worldSubnetSelections, 0, reservedWorldSelections, 0, true, true, 80, 6, 80, 6, insertBoth},

		// allow-allow insertions do not need tests as their affect on one another does not matter.
	}
	for _, tt := range tests {
		anyIngressKey := IngressKey()
		allowEntry := allowEntry().withLevel(tt.allowAllLevel)
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
		aEntry := NewMapStateEntry(types.NewMapStateEntry(tt.aLevel, tt.aIsDeny, 0, 0, types.NoAuthRequirement))
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
		bEntry := NewMapStateEntry(types.NewMapStateEntry(tt.bLevel, tt.bIsDeny, 0, 0, types.NoAuthRequirement))
		expectedKeys := emptyMapState(hivetest.Logger(t))
		if tt.outcome&insertAllowAll > 0 {
			expectedKeys.insert(anyIngressKey, allowEntry)
		}
		// insert allow expectations before deny expectations to manage overlap
		if tt.aLevel <= tt.bLevel && tt.outcome&insertB > 0 {
		BLoop1:
			for _, bKey := range bKeys {
				if tt.outcome&insertBL3NotInA > 0 {
					for _, aKey := range aKeys {
						if bKey.Identity == aKey.Identity {
							continue BLoop1
						}
					}
				}
				expectedKeys.insert(bKey, bEntry)
			}
		}
		if tt.outcome&insertA > 0 {
		ALoop:
			for _, aKey := range aKeys {
				if tt.outcome&insertAL3NotInB > 0 {
					for _, bKey := range bKeys {
						if aKey.Identity == bKey.Identity {
							continue ALoop
						}
					}
				}
				expectedKeys.insert(aKey, aEntry)
			}
		}
		if tt.aLevel > tt.bLevel && tt.outcome&insertB > 0 {
		BLoop:
			for _, bKey := range bKeys {
				if tt.outcome&insertBL3NotInA > 0 {
					for _, aKey := range aKeys {
						if bKey.Identity == aKey.Identity {
							continue BLoop
						}
					}
				}
				expectedKeys.insert(bKey, bEntry)
			}
		}
		if tt.outcome&insertDenyWorld > 0 {
			worldIngressKey := IngressKey().WithIdentity(2)
			expectedKeys.insert(worldIngressKey, denyEntry())
		}
		if tt.outcome&insertDenyWorldTCP > 0 {
			worldIngressKey := IngressKey().WithIdentity(2).WithTCPPort(0)
			expectedKeys.insert(worldIngressKey, denyEntry())
		}
		if tt.outcome&insertDenyWorldHTTP > 0 {
			worldIngressKey := IngressKey().WithIdentity(2).WithTCPPort(80)
			expectedKeys.insert(worldIngressKey, denyEntry())
		}
		outcomeKeys := emptyMapState(hivetest.Logger(t))

		changes := ChangeState{}
		if tt.withAllowAll {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), anyIngressKey, allowEntry, allFeatures, changes)
		}
		for _, idA := range tt.aIdentities {
			aKey := IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort)
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), aKey, aEntry, allFeatures, changes)
		}
		for _, idB := range tt.bIdentities {
			bKey := IngressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort)
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), bKey, bEntry, allFeatures, changes)
		}
		outcomeKeys.validatePortProto(t)

		require.True(t, expectedKeys.Equal(&outcomeKeys), "%s (MapState):\n%s\nExpected:\n%s\nObtained:\n%s\n", tt.name, outcomeKeys.diff(&expectedKeys), expectedKeys, outcomeKeys)

		// Test also with reverse insertion order
		outcomeKeys = emptyMapState(hivetest.Logger(t))

		for _, idB := range tt.bIdentities {
			bKey := IngressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort)
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), bKey, bEntry, allFeatures, changes)
		}
		for _, idA := range tt.aIdentities {
			aKey := IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort)
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), aKey, aEntry, allFeatures, changes)
		}
		if tt.withAllowAll {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), anyIngressKey, allowEntry, allFeatures, changes)
		}
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equal(&outcomeKeys), "%s (in reverse) (MapState):\n%s\nExpected:\n%s\nObtained:\n%s\n", tt.name, outcomeKeys.diff(&expectedKeys), expectedKeys, outcomeKeys)
	}
	// Now test all cases with different traffic directions.
	// This should result in both entries being inserted with
	// no changes, as they do not affect one another anymore.
	for _, tt := range tests {
		anyIngressKey := IngressKey()
		anyEgressKey := EgressKey()
		allowEntry := allowEntry().withLevel(tt.allowAllLevel)
		var aKeys []Key
		for _, idA := range tt.aIdentities {
			aKeys = append(aKeys, IngressKey().WithIdentity(idA).WithPortProto(tt.aProto, tt.aPort))
		}
		aEntry := NewMapStateEntry(types.NewMapStateEntry(tt.aLevel, tt.aIsDeny, 0, 0, types.NoAuthRequirement))
		var bKeys []Key
		for _, idB := range tt.bIdentities {
			bKeys = append(bKeys, EgressKey().WithIdentity(idB).WithPortProto(tt.bProto, tt.bPort))
		}
		bEntry := NewMapStateEntry(types.NewMapStateEntry(tt.bLevel, tt.bIsDeny, 0, 0, types.NoAuthRequirement))
		expectedKeys := emptyMapState(hivetest.Logger(t))
		if tt.outcome&insertAllowAll > 0 {
			expectedKeys.insert(anyIngressKey, allowEntry)
			expectedKeys.insert(anyEgressKey, allowEntry)
		}
		if tt.withAllowAll == WithoutAllowAll || (!tt.aIsDeny && tt.aLevel < tt.allowAllLevel) || tt.aLevel <= tt.allowAllLevel {
			for _, aKey := range aKeys {
				expectedKeys.insert(aKey, aEntry)
			}
		}
		if tt.withAllowAll == WithoutAllowAll || (!tt.bIsDeny && tt.bLevel < tt.allowAllLevel) || tt.bLevel <= tt.allowAllLevel {
			for _, bKey := range bKeys {
				expectedKeys.insert(bKey, bEntry)
			}
		}
		outcomeKeys := emptyMapState(hivetest.Logger(t))

		changes := ChangeState{}
		if tt.withAllowAll {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), anyIngressKey, allowEntry, allFeatures, changes)
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), anyEgressKey, allowEntry, allFeatures, changes)
		}
		for _, aKey := range aKeys {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), aKey, aEntry, allFeatures, changes)
		}
		for _, bKey := range bKeys {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), bKey, bEntry, allFeatures, changes)
		}
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equal(&outcomeKeys), "%s different traffic directions (MapState):\n%s", tt.name, outcomeKeys.diff(&expectedKeys))

		// Test also with reverse insertion order
		outcomeKeys = emptyMapState(hivetest.Logger(t))

		for _, bKey := range bKeys {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), bKey, bEntry, allFeatures, changes)
		}
		for _, aKey := range aKeys {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), aKey, aEntry, allFeatures, changes)
		}
		if tt.withAllowAll {
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), anyEgressKey, allowEntry, allFeatures, changes)
			outcomeKeys.insertWithChanges(types.Priority(0).ToPassPrecedence(), anyIngressKey, allowEntry, allFeatures, changes)
		}
		outcomeKeys.validatePortProto(t)
		require.True(t, expectedKeys.Equal(&outcomeKeys), "%s different traffic directions (in reverse) (MapState):\n%s", tt.name, outcomeKeys.diff(&expectedKeys))
	}
}

func TestMapState_Get_stacktrace(t *testing.T) {
	ms := emptyMapState(hivetest.Logger(t))
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
	log := hivetest.Logger(t)
	log.Error("Expecting an error log on the next log line!")
	_, ok := ms.Get(Key{})
	assert.False(t, ok)
}

// TestDenyPreferredInsertLogic is now less valuable since we do not have the mapstate
// validator any more, but may still catch bugs.
func TestDenyPreferredInsertLogic(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))
	td.bootstrapRepo(GenerateCIDRDenyRules, 1000, t)
	p, _ := td.repo.resolvePolicyLocked(fooIdentity)

	epPolicy := p.DistillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, nil)
	epPolicy.Ready()

	n := epPolicy.policyMapState.Len()
	p.detach(true, 0)
	assert.Positive(t, n)
}

// equalsMapState determines if this mapState is deeply equal to the argument mapStateMap
func (msA *mapState) equalsMapState(msB mapStateMap) bool {
	if msA.Len() != len(msB) {
		return false
	}
	return msA.forEach(func(kA Key, vA mapStateEntry) bool {
		vB, ok := msB[kA]
		return ok && vB == vA
	})
}

func (obtained *mapState) diffMapState(expected mapStateMap) (res string) {
	res += "Missing (-), Unexpected (+):\n"
	for kE, vE := range expected {
		if vO, ok := obtained.get(kE); ok {
			if vO != vE {
				res += "- " + kE.String() + ": " + vE.String() + "\n"
				res += "+ " + kE.String() + ": " + vO.String() + "\n"
			}
		} else {
			res += "- " + kE.String() + ": " + vE.String() + "\n"
		}
	}
	obtained.forEach(func(kE Key, vE mapStateEntry) bool {
		if _, ok := expected[kE]; !ok {
			res += "+ " + kE.String() + ": " + vE.String() + "\n"
		}
		return true
	})
	return res
}

type keyEntry struct {
	key   Key
	entry mapStateEntry
}

func TestMapState_orderedMapStateValidation(t *testing.T) {
	// identities used in tests
	identityFoo := identity.NumericIdentity(100)
	labelsFoo := labels.ParseSelectLabelArray("foo", "blue")
	identityWorld := identity.ReservedIdentityWorld
	labelsWorld := labels.LabelWorld.LabelArray()
	identitySubnet := localIdentity(192020)
	labelsSubnet := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("192.0.2.0/24")))).LabelArray()
	identitySubnetIP := localIdentity(192023)
	labelsSubnetIP := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("192.0.2.3/32")))).LabelArray()
	identityWorldIP := localIdentity(192042)
	labelsWorldIP := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("192.0.4.2/32")))).LabelArray()
	identity1111 := localIdentity(1111)
	labels1111 := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("1.1.1.1/32")))).LabelArray()
	identity1100 := localIdentity(1100)
	labels1100 := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("1.1.0.0/16")))).LabelArray()

	type probe struct {
		key   Key
		found bool
		entry MapStateEntry
	}
	type TierEntries struct {
		basePriority types.Priority
		entries      []keyEntry
	}
	tests := []struct {
		name       string               // test name
		identities identity.IdentityMap // Identities used in the test
		tiers      []TierEntries        // Explicitly ordered sets of implicitly ordered entries
		want       mapStateMap          // expected MapState, optional
		probes     []probe              // probes to test the policy, optional
	}{{
		name: "allow one.one.one.one, deny everything else on port 80 TAKE 2",
		// 1. allow 1.1.1.1:80
		// 2. deny *:80-81
		// 3. allow 1.1.1.1:*
		identities: identity.IdentityMap{
			identity1111:  labels1111,
			identity1100:  labels1100,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				// allow port 80 on 1.1.1.1 for TCP
				// - this would get overridden by the deny if the policy was not
				//   ordered
				{key: egressKey(identity1111, 6, 80, 0), entry: allowEntry()},
				// deny TCP ports 80-81 on all destinations
				// - wildcard L3
				{key: egressKey(0, 6, 80, 15), entry: denyEntry()},
				// allow all identities selected by 1.1.1.1/32 on any proto/port
				{key: egressKey(identity1111, 0, 0, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			// allow entries for line 0
			egressKey(identity1111, 6, 80, 0): allowEntry().withLevel(1000),
			// deny entries for line 1
			egressKey(0, 6, 80, 15): denyEntry().withLevel(1001),
			// allow entries due to line 2
			egressKey(identity1111, 0, 0, 0): allowEntry().withLevel(1002),
		},
		probes: []probe{
			{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 81, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
		},
	}, {
		name: "allow one.one.one.one, deny everything else on port 80 TAKE 3a",
		// 1. allow 1.1.1.1:80
		// 2. deny *:80
		// 3. allow 1.1.1.1:*
		identities: identity.IdentityMap{
			identity1111:  labels1111,
			identity1100:  labels1100,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 2000,
			entries: []keyEntry{
				// deny TCP port 80 on all destinations
				// - wildcard L3
				{key: egressKey(0, 6, 80, 16), entry: denyEntry()},
			},
		}, {
			basePriority: 1000,
			entries: []keyEntry{
				// allow port 80 on 1.1.1.1 for TCP
				// - this would get overridden by the deny if the policy was not
				//   ordered
				{key: egressKey(identity1111, 6, 80, 15), entry: allowEntry()},
			},
		}, {
			basePriority: 3000,
			entries: []keyEntry{
				// allow all identities selected by 1.1.1.1/32 on any proto/port
				{key: egressKey(identity1111, 0, 0, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			// allow entries for line 0
			egressKey(identity1111, 6, 80, 15): allowEntry().withLevel(1000),
			// deny entries for line 1
			egressKey(0, 6, 80, 16): denyEntry().withLevel(2000),
			// allow entries due to line 2
			egressKey(identity1111, 0, 0, 0): allowEntry().withLevel(3000),
		},
		probes: []probe{
			{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
		},
	}, {
		name: "allow one.one.one.one, deny everything else on port 80 TAKE 3",
		// 1. allow 1.1.1.1:80-81
		// 2. deny *:80
		// 3. allow 1.1.1.1:*
		identities: identity.IdentityMap{
			identity1111:  labels1111,
			identity1100:  labels1100,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				// allow port 80 on 1.1.1.1 for TCP
				// - this would get overridden by the deny if the policy was not
				//   ordered
				{key: egressKey(identity1111, 6, 80, 15), entry: allowEntry()},
				// deny TCP port 80 on all destinations
				// - wildcard L3
				{key: egressKey(0, 6, 80, 16), entry: denyEntry()},
				// allow all identities selected by 1.1.1.1/32 on any proto/port
				{key: egressKey(identity1111, 0, 0, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			// allow entries for line 0
			egressKey(identity1111, 6, 80, 15): allowEntry().withLevel(1000),
			// deny entries for line 1
			egressKey(0, 6, 80, 16): denyEntry().withLevel(1001),
			// allow entries due to line 2
			egressKey(identity1111, 0, 0, 0): allowEntry().withLevel(1002),
		},
		probes: []probe{
			{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
		},
	}, {
		name: "allow one.one.one.one, deny everything else on port 80 TAKE 4",
		// 1. allow 1.1.1.1:80
		// 2. deny *:80
		// 3. allow 1.1.1.1:*
		identities: identity.IdentityMap{
			identity1111:  labels1111,
			identity1100:  labels1100,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				// allow ports 80-81 on 1.1.1.1 for TCP
				// - this would get overridden by the deny if the policy was not
				//   ordered
				{key: egressKey(identity1111, 6, 80, 15), entry: allowEntry()},
				// deny TCP ports 80-143 on all destinations
				// - wildcard L3
				{key: egressKey(0, 6, 80, 10), entry: denyEntry()},
				// allow all identities selected by 1.1.1.1/32 on any proto/port
				{key: egressKey(identity1111, 0, 0, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			// allow entries for line 0
			egressKey(identity1111, 6, 80, 15): allowEntry().withLevel(1000),
			// deny entries for line 1
			egressKey(0, 6, 80, 10): denyEntry().withLevel(1001),
			// allow entries due to line 2
			egressKey(identity1111, 0, 0, 0): allowEntry().withLevel(1002),
		},
		probes: []probe{
			{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 82, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 8080, 16), found: true, entry: AllowEntry},
		},
	}, {
		name: "allow one.one.one.one:80-81, deny everything else on ports 80-81, then allow on 1.1.1.1:*",
		// 1. allow 1.1.1.1:80
		// 2. deny *:80
		// 3. allow 1.1.1.1:*
		identities: identity.IdentityMap{
			identity1111:  labels1111,
			identity1100:  labels1100,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				// allow ports 80-81 on 1.1.1.1 for TCP
				// - this would get overridden by the deny if the policy was not
				//   ordered
				{key: egressKey(identity1111, 6, 80, 15), entry: allowEntry()},
			},
		}, {
			basePriority: 2000,
			entries: []keyEntry{
				// deny TCP ports 80-143 on all destinations
				// - wildcard L3
				{key: egressKey(0, 6, 80, 15), entry: denyEntry()},
			},
		}, {
			basePriority: 3000,
			entries: []keyEntry{
				// allow all identities selected by 1.1.1.1/32 on any proto/port
				{key: egressKey(identity1111, 0, 0, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			// allow entries for line 0
			egressKey(identity1111, 6, 80, 15): allowEntry().withLevel(1000),
			// deny entries for line 1
			egressKey(0, 6, 80, 15): denyEntry().withLevel(2000),
			// allow entries due to line 2
			egressKey(identity1111, 0, 0, 0): allowEntry().withLevel(3000),
		},
		probes: []probe{
			{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 81, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 8080, 16), found: true, entry: AllowEntry},
		},
	}, {
		name: "allow one.one.one.one, deny everything else on port 80",
		// 1. allow 1.1.1.1:80
		// 2. deny *:80
		// 3. allow 1.1.0.0/16:*
		identities: identity.IdentityMap{
			identity1111:  labels1111,
			identity1100:  labels1100,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				// allow port 80 on 1.1.1.1 for TCP and UDP
				// - this would get overridden by the deny if the policy was not
				//   ordered
				{key: egressKey(identity1111, 6, 80, 0), entry: allowEntry()},
				{key: egressKey(identity1111, 17, 80, 0), entry: allowEntry()},
				// deny TCP and UDP port 80 on all destinations
				// - wildcard L3
				{key: egressKey(0, 6, 80, 0), entry: denyEntry()},
				{key: egressKey(0, 17, 80, 0), entry: denyEntry()},
				// allow all identities selected by 1.1.0.0/16 on any proto/port
				// - identities for 1.1.1.1/32 and 1.1.0.0/16 are selected
				{key: egressKey(identity1100, 0, 0, 0), entry: allowEntry()},
				{key: egressKey(identity1111, 0, 0, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			// allow entries for lines 0-2
			egressKey(identity1111, 6, 80, 0):  allowEntry().withLevel(1000),
			egressKey(identity1111, 17, 80, 0): allowEntry().withLevel(1001),
			// deny entries for lines 3-5
			egressKey(0, 6, 80, 0):  denyEntry().withLevel(1002),
			egressKey(0, 17, 80, 0): denyEntry().withLevel(1003),
			// allow entries due to lines 6-7
			egressKey(identity1100, 0, 0, 0): allowEntry().withLevel(1004),
			egressKey(identity1111, 0, 0, 0): allowEntry().withLevel(1005),
		},
		probes: []probe{
			{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1100, 17, 8080, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1100, 17, 80, 16), found: true, entry: DenyEntry},
		},
	}, {
		name: "ordered test-1a: earlier order allow takes precedence",
		identities: identity.IdentityMap{
			identityFoo:   labelsFoo,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				// port 80 with prefix length 15 covers ports 80-81
				{key: ingressKey(identityFoo, 6, 80, 15), entry: allowEntry()},
				{key: ingressKey(0, 6, 80, 0), entry: denyEntry()},
			},
		}},
		want: mapStateMap{
			ingressKey(identityFoo, 6, 80, 15): allowEntry().withLevel(1000),
			ingressKey(0, 6, 80, 16):           denyEntry().withLevel(1001),
		},
		probes: []probe{
			{key: ingressKey(identityWorld, 17, 8080, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 8080, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 79, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 81, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 82, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityFoo, 17, 8080, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityFoo, 6, 8080, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityFoo, 6, 79, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityFoo, 6, 80, 16), found: true, entry: AllowEntry},
			{key: ingressKey(identityFoo, 6, 81, 16), found: true, entry: AllowEntry},
			{key: ingressKey(identityFoo, 6, 82, 16), found: false, entry: DenyEntry},
		},
	}, {
		name: "ordered test-1b: earlier order allow takes precedence",
		identities: identity.IdentityMap{
			identityFoo:   labelsFoo,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				{key: ingressL3OnlyKey(identityFoo), entry: allowEntry()},
			},
		}, {
			basePriority: 2000,
			entries: []keyEntry{
				{key: ingressKey(0, 6, 80, 0), entry: denyEntry()},
			},
		}},
		want: mapStateMap{
			ingressL3OnlyKey(identityFoo): allowEntry().withLevel(1000),
			ingressKey(0, 6, 80, 0):       denyEntry().withLevel(2000),
		},
		probes: []probe{
			{key: ingressKey(identityWorld, 17, 8080, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 8080, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: ingressKey(identityFoo, 17, 8080, 16), found: true, entry: AllowEntry},
			{key: ingressKey(identityFoo, 6, 8080, 16), found: true, entry: AllowEntry},
			{key: ingressKey(identityFoo, 6, 80, 16), found: true, entry: AllowEntry},
		},
	}, {
		name: "ordered test-2a: earlier order deny takes precedence",
		identities: identity.IdentityMap{
			identityFoo:   labelsFoo,
			identityWorld: labelsWorld,
		},
		tiers: []TierEntries{{
			basePriority: 1000,
			entries: []keyEntry{
				{key: ingressL3OnlyKey(identityFoo), entry: denyEntry()},
			},
		}, {
			basePriority: 2000,
			entries: []keyEntry{
				{key: ingressKey(0, 6, 0, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			ingressL3OnlyKey(identityFoo): denyEntry().withLevel(1000),
			ingressKey(0, 6, 0, 0):        allowEntry().withLevel(2000),
		},
		probes: []probe{
			{key: ingressKey(identityWorld, 17, 8080, 16), found: false, entry: DenyEntry},
			{key: ingressKey(identityWorld, 6, 8080, 16), found: true, entry: AllowEntry},
			{key: ingressKey(identityWorld, 6, 80, 16), found: true, entry: AllowEntry},
			{key: ingressKey(identityFoo, 17, 8080, 16), found: true, entry: DenyEntry},
			{key: ingressKey(identityFoo, 6, 8080, 16), found: true, entry: DenyEntry},
			{key: ingressKey(identityFoo, 6, 80, 16), found: true, entry: DenyEntry},
			// unmapped IDs are dropped by default even without an explicit deny rule
			{key: egressKey(77, 6, 53, 16), found: false, entry: DenyEntry},
			{key: egressKey(77, 6, 443, 16), found: false, entry: DenyEntry},
			{key: egressKey(77, 6, 80, 16), found: false, entry: DenyEntry},
			{key: egressKey(77, 17, 53, 16), found: false, entry: DenyEntry},
			{key: egressKey(77, 17, 443, 16), found: false, entry: DenyEntry},
			{key: egressKey(77, 17, 80, 16), found: false, entry: DenyEntry},
		},
	}, {
		name: "ordered test-3a: CIDR deny with an earlier order allow hole",
		identities: identity.IdentityMap{
			identityFoo:      labelsFoo,
			identityWorld:    labelsWorld,
			identityWorldIP:  labelsWorldIP,
			identitySubnet:   labelsSubnet,
			identitySubnetIP: labelsSubnetIP,
		},
		tiers: []TierEntries{{
			basePriority: 42000,
			entries: []keyEntry{
				// Allow egress to a UDP DNS server IP in a subnet
				{key: egressKey(identitySubnetIP, 17, 53, 16), entry: allowEntry()},
				// Deny all identities matching the world label
				// later order deny on SubnetIP does not override earlier order allows above
				{key: egressL3OnlyKey(identitySubnetIP), entry: denyEntry()},
				{key: egressL3OnlyKey(identitySubnet), entry: denyEntry()},
				{key: egressL3OnlyKey(identityWorldIP), entry: denyEntry()},
				{key: egressL3OnlyKey(identityWorld), entry: denyEntry()},
			},
		}, {
			basePriority: 65000,
			entries: []keyEntry{
				{key: egressL3OnlyKey(0), entry: denyEntry()},
				// Later order allow-all has no effect after earlier order deny all
				{key: egressL3OnlyKey(0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			egressKey(identitySubnetIP, 17, 53, 16): allowEntry().withLevel(42000),
			egressL3OnlyKey(identitySubnetIP):       denyEntry().withLevel(42001),
			egressL3OnlyKey(identitySubnet):         denyEntry().withLevel(42002),
			egressL3OnlyKey(identityWorldIP):        denyEntry().withLevel(42003),
			egressL3OnlyKey(identityWorld):          denyEntry().withLevel(42004),
			egressL3OnlyKey(0):                      denyEntry().withLevel(65000),
		},
		probes: []probe{
			{key: egressKey(identitySubnetIP, 6, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identitySubnetIP, 17, 53, 16), found: true, entry: AllowEntry},
			{key: egressKey(identitySubnetIP, 132, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identitySubnet, 6, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identitySubnet, 6, 443, 16), found: true, entry: DenyEntry},
			{key: egressKey(identitySubnet, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identitySubnet, 17, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identitySubnet, 17, 443, 16), found: true, entry: DenyEntry},
			{key: egressKey(identitySubnet, 17, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorld, 6, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorld, 6, 443, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorld, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorld, 17, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorld, 17, 443, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorld, 17, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorldIP, 6, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorldIP, 6, 443, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorldIP, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorldIP, 17, 53, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorldIP, 17, 443, 16), found: true, entry: DenyEntry},
			{key: egressKey(identityWorldIP, 17, 80, 16), found: true, entry: DenyEntry},
		},
	}, {
		name: "deny 1.1.1.1",
		identities: identity.IdentityMap{
			identity1111: labels1111,
		},
		tiers: []TierEntries{{
			basePriority: 0,
			entries: []keyEntry{
				{key: egressKey(identity1111, 0, 0, 0), entry: denyEntry()},
			},
		}, {
			basePriority: 1000,
			entries: []keyEntry{
				// HTTP allow 1.1.1.1, overruled by the deny
				{key: egressKey(identity1111, 6, 80, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			egressKey(identity1111, 0, 0, 0): denyEntry().withLevel(0),
		},
		probes: []probe{},
	}, {
		name: "Allow 1.1.1.1",
		identities: identity.IdentityMap{
			identity1111: labels1111,
		},
		tiers: []TierEntries{{
			basePriority: 0,
			entries: []keyEntry{
				// Allow verdict on 1.1.1.1
				{key: egressKey(identity1111, 0, 0, 0), entry: allowEntry()},
				// deny 1.1.1.1
				{key: egressKey(identity1111, 0, 0, 0), entry: denyEntry()},
			},
		}, {
			basePriority: 1000,
			entries: []keyEntry{
				// HTTP allow 1.1.1.1, shadowed by the allow above
				{key: egressKey(identity1111, 6, 80, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			egressKey(identity1111, 0, 0, 0): allowEntry().withLevel(0),
		},
		probes: []probe{},
	}, {
		name: "PASS 1.1.1.1 over deny all",
		identities: identity.IdentityMap{
			identity1111: labels1111,
		},
		tiers: []TierEntries{{
			basePriority: 0,
			entries: []keyEntry{
				// HTTP PASS verdict on 1.1.1.1
				{key: egressKey(identity1111, 0, 0, 0), entry: passEntry(0, 1000)},
				// deny 1.1.1.1
				{key: egressKey(identity1111, 0, 0, 0), entry: denyEntry()},
			},
		}, {
			basePriority: 1000,
			entries: []keyEntry{
				// HTTP allow 1.1.1.1
				{key: egressKey(identity1111, 6, 80, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			egressKey(identity1111, 0, 0, 0):  passEntry(0, 1000),
			egressKey(identity1111, 6, 80, 0): allowEntry().withLevel(1),
		},
		probes: []probe{},
	}}

	for _, tt := range tests {
		t.Log(tt.name)

		// create tierEntries and permutations for each tier
		var tierEntries [][]keyEntry
		var tierPermutations [][][]int
		var tierLimits []int
		for _, tier := range tt.tiers {
			entries := slices.Clone(tier.entries)
			idx := make([]int, 0, len(entries))
			for i := range entries {
				entries[i].entry.MapStateEntry = entries[i].entry.MapStateEntry.WithPriority(tier.basePriority + types.Priority(i))
				idx = append(idx, i)
			}
			tierEntries = append(tierEntries, entries)
			perms := permutations(idx)
			tierPermutations = append(tierPermutations, perms)
			tierLimits = append(tierLimits, len(perms))
		}

		// iterate through all the combinations of permutations for each tier
		combinations := func(limits []int) iter.Seq[[]int] {
			return func(yield func([]int) bool) {
				combo := make([]int, len(limits))
				for {
					if !yield(combo) {
						return
					}
					//return
					// get next combo
					for i, limit := range limits {
						if combo[i] >= limit-1 {
							if i == len(combo)-1 {
								return // done
							}
							continue
						}
						combo[i]++
					}
				}
			}
		}
		for tierPermutation := range combinations(tierLimits) {
			name := fmt.Sprintf("%s combination %v (limits %v)", tt.name, tierPermutation, tierLimits)
			t.Run(name, func(t *testing.T) {
				//t.Parallel()
				t.Log(name)
				changes := ChangeState{
					Adds:    make(Keys),
					Deletes: make(Keys),
					old:     make(mapStateMap),
				}

				// create mapState
				ms := emptyMapState(hivetest.Logger(t))

				// insert entries tier-by-tier, using the given permutation on each tier
				for tier, perm := range tierPermutation {
					for _, i := range tierPermutations[tier][perm] {
						tierBasePrecedence := tt.tiers[tier].basePriority.ToPassPrecedence()
						ms.insertWithChanges(tierBasePrecedence, tierEntries[tier][i].key, tierEntries[tier][i].entry, orderedRules|denyRules, changes)
					}
				}

				// validate mapState
				ms.validatePortProto(t)
				require.Truef(t, ms.equalsMapState(tt.want), "%s: MapState mismatch on permutation %v:\n%s", tt.name, tierPermutation, ms.diffMapState(tt.want))

				// run probes
				for _, probe := range tt.probes {
					v, found := ms.lookup(probe.key)
					require.Equal(t, probe.found, found)
					// Ignore and labels for precedence for probe test
					v.Precedence = 0
					probe.entry.Precedence = 0
					require.Equalf(t, probe.entry, v.MapStateEntry, "%s: Verdict mismatch for key %s:\n- %s\n+ %s\n\nMapState:\n%s", tt.name, probe.key, probe.entry, v.MapStateEntry, ms)
				}
			})
		}
	}
}

func TestMapState_passValidation(t *testing.T) {
	// identities used in tests
	identity1111 := localIdentity(1111)
	labels1111 := labels.GetCIDRLabels(netip.MustParsePrefix(string(api.CIDR("1.1.1.1/32")))).LabelArray()

	identityCache := identity.IdentityMap{
		identity1111: labels1111,
	}
	selectorCache := testNewSelectorCache(t, hivetest.Logger(t), identityCache)

	type probe struct {
		key   Key
		found bool
		entry MapStateEntry
	}
	type TierEntries struct {
		basePriority types.Priority
		entries      []keyEntry
	}
	tests := []struct {
		name       string               // test name
		identities identity.IdentityMap // Identities used in the test
		tiers      []TierEntries        // Explicitly ordered sets of implicitly ordered entries
		want       mapStateMap          // expected MapState, optional
		probes     []probe              // probes to test the policy, optional
	}{{
		name: "PASS 1.1.1.1 over deny all",
		identities: identity.IdentityMap{
			identity1111: labels1111,
		},
		tiers: []TierEntries{{
			basePriority: 0,
			entries: []keyEntry{
				// PASS verdict on 1.1.1.1
				{key: egressKey(identity1111, 0, 0, 0), entry: passEntry(0, 1000)},
				// wildcard deny
				{key: egressKey(0, 0, 0, 0), entry: denyEntry()},
			},
		}, {
			basePriority: 1000,
			entries: []keyEntry{
				// HTTP allow 1.1.1.1
				{key: egressKey(identity1111, 6, 80, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			egressKey(identity1111, 0, 0, 0):  passEntry(0, 1000),
			egressKey(0, 0, 0, 0):             denyEntry().withLevel(100),
			egressKey(identity1111, 6, 80, 0): allowEntry().withLevel(1),
		},
		probes: []probe{},
	}, {
		name: "wildcard PASS over deny 1.1.1.1",
		identities: identity.IdentityMap{
			identity1111: labels1111,
		},
		tiers: []TierEntries{{
			basePriority: 0,
			entries: []keyEntry{
				// wildcard PASS
				{key: egressKey(0, 0, 0, 0), entry: passEntry(0, 1000)},
				// deny 1.1.1.1 (should be shadowed by the pass entry above)
				{key: egressKey(identity1111, 0, 0, 0), entry: denyEntry()},
			},
		}, {
			basePriority: 1000,
			entries: []keyEntry{
				// HTTP allow 1.1.1.1
				{key: egressKey(identity1111, 6, 80, 0), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			egressKey(0, 0, 0, 0):             passEntry(0, 1000),
			egressKey(identity1111, 6, 80, 0): allowEntry().withLevel(1),
		},
		probes: []probe{},
	}, {
		name: "PASS 1.1.1.1 over deny all, with wildcard and probes",
		identities: identity.IdentityMap{
			identity1111: labels1111,
		},
		tiers: []TierEntries{{
			basePriority: 0,
			entries: []keyEntry{
				// wildcard deny all TCP port 81
				{key: egressKey(0, 6, 81, 0), entry: denyEntry()},
			},
		}, {
			basePriority: 1000,
			entries: []keyEntry{
				// HTTP PASS verdict on 1.1.1.1
				{key: egressKey(identity1111, 0, 0, 0), entry: passEntry(1000, 2000)},
				// wildcard deny
				{key: egressKey(0, 0, 0, 0), entry: denyEntry()},
			},
		}, {
			basePriority: 2000,
			entries: []keyEntry{
				// HTTP deny 1.1.1.1 on TCP port 90
				{key: egressKey(identity1111, 6, 90, 0), entry: denyEntry()},
				// HTTP allow 1.1.1.1 on TCP port 80-95
				{key: egressKey(identity1111, 6, 80, 12), entry: allowEntry()},
			},
		}},
		want: mapStateMap{
			egressKey(0, 6, 81, 0):             denyEntry().withLevel(0),
			egressKey(identity1111, 0, 0, 0):   passEntry(1000, 2000),
			egressKey(0, 0, 0, 0):              denyEntry().withLevel(1100),
			egressKey(identity1111, 6, 90, 0):  denyEntry().withLevel(1001),
			egressKey(identity1111, 6, 80, 12): allowEntry().withLevel(1002),
		},
		probes: []probe{
			{key: egressKey(2, 6, 80, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 79, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 80, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 81, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 82, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 89, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 90, 16), found: true, entry: DenyEntry},
			{key: egressKey(identity1111, 6, 91, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 95, 16), found: true, entry: AllowEntry},
			{key: egressKey(identity1111, 6, 96, 16), found: true, entry: DenyEntry},
		},
	}}

	for _, tt := range tests {
		t.Log(tt.name)

		t.Run(tt.name, func(t *testing.T) {
			epPolicy := &EndpointPolicy{
				SelectorPolicy: &selectorPolicy{
					SelectorCache: selectorCache,
					L4Policy:      L4Policy{},
				},
				PolicyOwner:      DummyOwner{logger: hivetest.Logger(t)},
				policyMapState:   emptyMapState(hivetest.Logger(t)),
				policyMapChanges: MapChanges{logger: hivetest.Logger(t)},
			}

			for tier := range tt.tiers {
				nPassEntries := types.Priority(0)
				basePriority := tt.tiers[tier].basePriority
				for i, kv := range tt.tiers[tier].entries {
					key := kv.key
					entry := kv.entry
					if entry.IsValid() {
						// In this test we leave a gap of 100 priorities after each
						// PASS verdict
						entry = entry.withLevel(basePriority + types.Priority(i) + nPassEntries*99)
					}
					if entry.IsPassEntry() {
						nPassEntries++
					}

					adds := identity.NumericIdentitySlice{key.Identity}
					keys := []Key{key}
					epPolicy.policyMapChanges.AccumulateMapChanges(types.Tier(tier), basePriority, adds, nil, keys, entry)
				}
			}
			epPolicy.policyMapChanges.SyncMapChanges(types.MockSelectorSnapshot())
			_, changes := epPolicy.policyMapChanges.consumeMapChanges(epPolicy, denyRules|redirectRules)

			// validate mapState
			epPolicy.policyMapState.validatePortProto(t)
			if len(tt.want) != 0 {
				wantKeys := make(Keys)
				for k := range epPolicy.policyMapState.entries {
					wantKeys[k] = struct{}{}
				}
				require.Equal(t, wantKeys, changes.Adds, tt.name+" (adds)")
				require.Equal(t, Keys{}, changes.Deletes, tt.name+" (deletes)")

				require.Truef(t, epPolicy.policyMapState.equalsMapState(tt.want), "%s: MapState mismatch:\n%s", tt.name, epPolicy.policyMapState.diffMapState(tt.want))
			}
			// run probes
			for i, probe := range tt.probes {
				v, found := epPolicy.policyMapState.lookup(probe.key)
				msg := "found"
				if probe.found {
					msg = "not found"
				}
				require.Equal(t, probe.found, found, "probe %d key %s: %v", i, msg, probe.key)
				// Ignore and labels for precedence for probe test
				v.Precedence = 0
				probe.entry.Precedence = 0
				require.Equalf(t, probe.entry, v.MapStateEntry, "%s: Verdict mismatch for key %s:\n- %s\n+ %s\n\nMapState:\n%s", tt.name, probe.key, probe.entry, v.MapStateEntry, epPolicy.policyMapState)
			}
		})
	}
}

func permutations(arr []int) [][]int {
	var helper func([]int, int)
	res := [][]int{}

	helper = func(arr []int, n int) {
		if n == 1 {
			res = append(res, slices.Clone(arr))
		} else {
			for i := 0; i < n; i++ {
				helper(arr, n-1)
				if n%2 == 1 {
					tmp := arr[i]
					arr[i] = arr[n-1]
					arr[n-1] = tmp
				} else {
					tmp := arr[0]
					arr[0] = arr[n-1]
					arr[n-1] = tmp
				}
			}
		}
	}
	helper(arr, len(arr))
	return res
}
