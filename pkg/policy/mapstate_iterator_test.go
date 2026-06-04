// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

// This tests that iterators return the set of keys that we expect.
//
// To reduce boilerplate, the keys are represented in a string form:
//
// id:proto:port:prefix
//

import (
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// This returns a map with four levels of keys.
// At every level, there is a wildcard and 2 non-wildcard entries.
//
// The levels are
// proto 0
// proto tcp port 0-65565,
// proto tcp port 8-15
// proto tcp port 10
func multiLevelMapState(t *testing.T) *mapState {
	ids := []identity.NumericIdentity{0, 257, 258}
	keys := []types.Key{
		types.IngressKey(),
		types.IngressKey().WithProto(u8proto.TCP),
		types.IngressKey().WithTCPPortPrefix(8, 13),
		types.IngressKey().WithTCPPort(10),
	}

	out := emptyMapState(hivetest.Logger(t))

	for _, id := range ids {
		for _, key := range keys {
			key.Identity = id
			out.insert(key, allowEntry())
		}
	}
	return &out
}

func TestMapState_CoveringBroaderOrEqualKeys(t *testing.T) {
	type testcase struct {
		startKey  string
		shouldSee []string
	}

	cases := []testcase{
		{
			startKey: "258:6:10:16", // port 10
			shouldSee: []string{
				"258:6:10:16",
				"0:6:10:16",
				"258:6:8:13",
				"0:6:8:13",
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:10:16", // port 10
			shouldSee: []string{
				"0:6:10:16",
				"0:6:8:13",
				"0:6",
				"0",
			},
		},

		{
			startKey: "258:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"258:6:8:13",
				"0:6:8:13",
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"0:6:8:13",
				"0:6",
				"0",
			},
		},

		{
			startKey: "258:6:2:16",
			shouldSee: []string{
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:2:16",
			shouldSee: []string{
				"0:6",
				"0",
			},
		},

		{
			startKey: "0",
			shouldSee: []string{
				"0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.startKey, func(t *testing.T) {
			want := sets.New[types.Key]()
			for _, k := range tc.shouldSee {
				want.Insert(mustParseKey(k))
			}

			ms := multiLevelMapState(t)
			seen := sets.New[types.Key]()
			for k := range ms.CoveringBroaderOrEqualKeys(mustParseKey(tc.startKey)) {
				seen.Insert(k)
			}

			require.Equal(t, want, seen)
		})
	}
}

func TestMapState_BroaderOrEqualKeys(t *testing.T) {
	type testcase struct {
		startKey  string
		shouldSee []string
	}

	cases := []testcase{
		{
			startKey: "258:6:10:16", // port 10
			shouldSee: []string{
				"258:6:10:16",
				"0:6:10:16",
				"258:6:8:13",
				"0:6:8:13",
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:10:16", // port 10
			shouldSee: []string{
				"257:6:10:16",
				"258:6:10:16",
				"0:6:10:16",
				"257:6:8:13",
				"258:6:8:13",
				"0:6:8:13",
				"257:6",
				"258:6",
				"0:6",
				"257",
				"258",
				"0",
			},
		},

		{
			startKey: "258:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"258:6:8:13",
				"0:6:8:13",
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"257:6:8:13",
				"258:6:8:13",
				"0:6:8:13",
				"257:6",
				"258:6",
				"0:6",
				"257",
				"258",
				"0",
			},
		},

		{
			startKey: "258:6:2:16",
			shouldSee: []string{
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:2:16",
			shouldSee: []string{
				"257:6",
				"258:6",
				"0:6",
				"257",
				"258",
				"0",
			},
		},

		{
			startKey: "0",
			shouldSee: []string{
				"257",
				"258",
				"0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.startKey, func(t *testing.T) {
			want := sets.New[types.Key]()
			for _, k := range tc.shouldSee {
				want.Insert(mustParseKey(k))
			}

			ms := multiLevelMapState(t)
			seen := sets.New[types.Key]()
			for k := range ms.BroaderOrEqualKeys(mustParseKey(tc.startKey)) {
				seen.Insert(k)
			}

			require.Equal(t, want, seen)
		})
	}
}

func TestMapState_CoveredNarrowerOrEqualKeys(t *testing.T) {
	type testcase struct {
		startKey  string
		shouldSee []string
	}

	cases := []testcase{
		{
			startKey: "258:6:10:16", // port 10
			shouldSee: []string{
				"258:6:10:16",
			},
		},

		{
			startKey: "0:6:10:16", // port 10
			shouldSee: []string{
				"257:6:10:16",
				"258:6:10:16",
				"0:6:10:16",
			},
		},

		{
			startKey:  "258:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{},
		},

		{
			startKey:  "0:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{},
		},

		{
			startKey: "258:6:8:14",
			shouldSee: []string{
				"258:6:10:16",
			},
		},

		{
			startKey: "0:6:8:14",
			shouldSee: []string{
				"257:6:10:16",
				"258:6:10:16",
				"0:6:10:16",
			},
		},

		{
			startKey: "257:6:8:13",
			shouldSee: []string{
				"257:6:10:16",
				"257:6:8:13",
			},
		},

		{
			startKey: "0:6:8:13",
			shouldSee: []string{
				"257:6:10:16",
				"257:6:8:13",
				"258:6:10:16",
				"258:6:8:13",
				"0:6:10:16",
				"0:6:8:13",
			},
		},

		{
			startKey: "257",
			shouldSee: []string{
				"257:6:10:16",
				"257:6:8:13",
				"257:6",
				"257",
			},
		},

		{
			startKey: "0",
			shouldSee: []string{
				"257:6:10:16",
				"258:6:10:16",
				"0:6:10:16",
				"257:6:8:13",
				"258:6:8:13",
				"0:6:8:13",
				"257:6",
				"258:6",
				"0:6",
				"257",
				"258",
				"0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.startKey, func(t *testing.T) {
			want := sets.New[types.Key]()
			for _, k := range tc.shouldSee {
				want.Insert(mustParseKey(k))
			}

			ms := multiLevelMapState(t)
			seen := sets.New[types.Key]()
			for k := range ms.CoveredNarrowerOrEqualKeys(mustParseKey(tc.startKey)) {
				seen.Insert(k)
			}

			require.Equal(t, want, seen)
		})
	}
}

func TestMapState_NarrowerOrEqualKeys(t *testing.T) {
	type testcase struct {
		startKey  string
		shouldSee []string
	}

	cases := []testcase{
		{
			startKey: "258:6:10:16", // port 10
			shouldSee: []string{
				"258:6:10:16",
				"0:6:10:16",
			},
		},

		{
			startKey: "0:6:10:16", // port 10
			shouldSee: []string{
				"257:6:10:16",
				"258:6:10:16",
				"0:6:10:16",
			},
		},

		{
			startKey:  "258:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{},
		},

		{
			startKey:  "0:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{},
		},

		{
			startKey: "258:6:8:14",
			shouldSee: []string{
				"258:6:10:16",
				"0:6:10:16",
			},
		},

		{
			startKey: "0:6:8:14",
			shouldSee: []string{
				"257:6:10:16",
				"258:6:10:16",
				"0:6:10:16",
			},
		},

		{
			startKey: "257:6:8:13",
			shouldSee: []string{
				"257:6:10:16",
				"0:6:10:16",
				"257:6:8:13",
				"0:6:8:13",
			},
		},

		{
			startKey: "0:6:8:13",
			shouldSee: []string{
				"257:6:10:16",
				"257:6:8:13",
				"258:6:10:16",
				"258:6:8:13",
				"0:6:10:16",
				"0:6:8:13",
			},
		},

		{
			startKey: "257",
			shouldSee: []string{
				"257:6:10:16",
				"0:6:10:16",
				"257:6:8:13",
				"0:6:8:13",
				"257:6",
				"0:6",
				"257",
				"0",
			},
		},

		{
			startKey: "0",
			shouldSee: []string{
				"257:6:10:16",
				"258:6:10:16",
				"0:6:10:16",
				"257:6:8:13",
				"258:6:8:13",
				"0:6:8:13",
				"257:6",
				"258:6",
				"0:6",
				"257",
				"258",
				"0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.startKey, func(t *testing.T) {
			want := sets.New[types.Key]()
			for _, k := range tc.shouldSee {
				want.Insert(mustParseKey(k))
			}

			ms := multiLevelMapState(t)
			seen := sets.New[types.Key]()
			for k := range ms.NarrowerOrEqualKeys(mustParseKey(tc.startKey)) {
				seen.Insert(k)
			}

			require.Equal(t, want, seen)
		})
	}
}

func TestMapState_CoveringKeysWithSameID(t *testing.T) {
	type testcase struct {
		startKey  string
		shouldSee []string
	}

	cases := []testcase{
		{
			startKey: "258:6:10:16", // port 10
			shouldSee: []string{
				"258:6:10:16",
				"258:6:8:13",
				"258:6",
				"258",
			},
		},

		{
			startKey: "0:6:10:16", // port 10
			shouldSee: []string{
				"0:6:10:16",
				"0:6:8:13",
				"0:6",
				"0",
			},
		},

		{
			startKey: "258:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"258:6:8:13",
				"258:6",
				"258",
			},
		},

		{
			startKey: "0:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"0:6:8:13",
				"0:6",
				"0",
			},
		},

		{
			startKey: "258:6:2:16",
			shouldSee: []string{
				"258:6",
				"258",
			},
		},

		{
			startKey: "0:6:2:16",
			shouldSee: []string{
				"0:6",
				"0",
			},
		},

		{
			startKey: "0",
			shouldSee: []string{
				"0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.startKey, func(t *testing.T) {
			want := sets.New[types.Key]()
			for _, k := range tc.shouldSee {
				want.Insert(mustParseKey(k))
			}

			ms := multiLevelMapState(t)
			seen := sets.New[types.Key]()
			for k := range ms.CoveringKeysWithSameID(mustParseKey(tc.startKey)) {
				seen.Insert(k)
			}

			require.Equal(t, want, seen)
		})
	}
}

func TestMapState_SubsetKeysWithSameID(t *testing.T) {
	type testcase struct {
		startKey  string
		shouldSee []string
	}

	cases := []testcase{
		{
			startKey: "258:6:10:16", // port 10
			shouldSee: []string{
				"258:6:10:16",
			},
		},

		{
			startKey: "0:6:10:16", // port 10
			shouldSee: []string{
				"0:6:10:16",
			},
		},

		{
			startKey:  "258:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{},
		},

		{
			startKey:  "0:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{},
		},

		{
			startKey: "258:6:8:14",
			shouldSee: []string{
				"258:6:10:16",
			},
		},

		{
			startKey: "0:6:8:14",
			shouldSee: []string{
				"0:6:10:16",
			},
		},

		{
			startKey: "257:6:8:13",
			shouldSee: []string{
				"257:6:10:16",
				"257:6:8:13",
			},
		},

		{
			startKey: "0:6:8:13",
			shouldSee: []string{
				"0:6:10:16",
				"0:6:8:13",
			},
		},

		{
			startKey: "257",
			shouldSee: []string{
				"257:6:10:16",
				"257:6:8:13",
				"257:6",
				"257",
			},
		},

		{
			startKey: "0",
			shouldSee: []string{
				"0:6:10:16",
				"0:6:8:13",
				"0:6",
				"0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.startKey, func(t *testing.T) {
			want := sets.New[types.Key]()
			for _, k := range tc.shouldSee {
				want.Insert(mustParseKey(k))
			}

			ms := multiLevelMapState(t)
			seen := sets.New[types.Key]()
			for k := range ms.SubsetKeysWithSameID(mustParseKey(tc.startKey)) {
				seen.Insert(k)
			}

			require.Equal(t, want, seen)
		})
	}
}

func TestMapState_LPMAncestors(t *testing.T) {

	type testcase struct {
		startKey  string
		shouldSee []string // ordered now
	}

	cases := []testcase{
		{
			startKey: "258:6:10:16", // port 10
			shouldSee: []string{
				"258:6:10:16",
				"0:6:10:16",
				"258:6:8:13",
				"0:6:8:13",
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:10:16", // port 10
			shouldSee: []string{
				"0:6:10:16",
				"0:6:8:13",
				"0:6",
				"0",
			},
		},

		{
			startKey: "258:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"258:6:8:13",
				"0:6:8:13",
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:11:16", // port 11 (not in mapstate directly)
			shouldSee: []string{
				"0:6:8:13",
				"0:6",
				"0",
			},
		},

		{
			startKey: "258:6:2:16",
			shouldSee: []string{
				"258:6",
				"0:6",
				"258",
				"0",
			},
		},

		{
			startKey: "0:6:2:16",
			shouldSee: []string{
				"0:6",
				"0",
			},
		},

		{
			startKey: "0",
			shouldSee: []string{
				"0",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.startKey, func(t *testing.T) {
			want := make([]types.Key, 0, len(tc.shouldSee))
			for _, k := range tc.shouldSee {
				want = append(want, mustParseKey(k))
			}

			ms := multiLevelMapState(t)
			seen := make([]types.Key, 0, len(want))
			for k := range ms.LPMAncestors(mustParseKey(tc.startKey)) {
				seen = append(seen, k)
			}

			require.Equal(t, want, seen)
		})
	}

}

func mustParseKey(ks string) types.Key {
	getNum := func(s string) int {
		i, err := strconv.Atoi(s)
		if err != nil {
			panic("invalid number " + s)
		}
		return i
	}

	parts := strings.Split(ks, ":")
	if len(parts) < 1 || len(parts) > 4 {
		panic("invalid spec " + ks)
	}

	out := types.IngressKey()
	out = out.WithIdentity(identity.NumericIdentity(getNum(parts[0])))

	if len(parts) >= 2 {
		out = out.WithProto(u8proto.U8proto(getNum(parts[1])))
	}
	if len(parts) == 3 {
		out = out.WithPort(uint16(getNum(parts[2])))
	}
	if len(parts) == 4 {
		out = out.WithPortPrefix(uint16(getNum(parts[2])), uint8(getNum(parts[3])))
	}
	return out
}

func TestMustParseKey(t *testing.T) {
	require.Equal(t,
		types.IngressKey().WithIdentity(0),
		mustParseKey("0"),
	)

	require.Equal(t,
		types.IngressKey().WithIdentity(42).WithProto(6),
		mustParseKey("42:6"),
	)

	require.Equal(t,
		types.IngressKey().WithIdentity(42).WithProto(6).WithPort(100),
		mustParseKey("42:6:100"),
	)

	require.Equal(t,
		types.IngressKey().WithIdentity(42).WithProto(6).WithPortPrefix(8, 13),
		mustParseKey("42:6:8:13"),
	)
}
