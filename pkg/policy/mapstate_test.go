// Copyright 2019-2020 Authors of Cilium
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
