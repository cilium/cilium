// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// customFuncs tweaks the generated structs to restrict them to values
// that are valid and pass the JSON marshalling.
var customFuncs = []any{
	// Generate valid IPs
	func(addr *netip.Addr, c fuzz.Continue) error {
		ipv4, err := c.F.GetBool()
		if err != nil {
			return err
		}
		n := 16
		if ipv4 {
			n = 4
		}
		bs, err := c.F.GetNBytes(n)
		if err != nil {
			return err
		}
		var ok bool
		*addr, ok = netip.AddrFromSlice(bs)
		if !ok {
			return errors.New("AddrFromSlice fail")
		}
		return nil
	},

	// Generate printable strings
	func(s *string, c fuzz.Continue) error {
		n, err := c.F.GetInt()
		if err != nil {
			return err
		}
		*s, err = c.F.GetStringFrom("abcd1234", n)
		return err
	},
}

// tableRowJSONFuzzer is a fuzz test to validate that when 'T' goes
// via JSON marshalling and unmarshalling the TableRow() function
// returns the same result. This ensures that the cilium-dbg output
// for the type 'T' works as expected when 'T' is transferred over
// the REST API.
//
// The test does not check for full equality as the JSON marshalling
// results in e.g. different Time values. Since we currently use the JSON
// marshalling only for the StateDB table output this is fine, but this
// test should be extended to cover other use-cases if they arise.
func tableRowJSONFuzzer[T statedb.TableWritable](f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		cons := fuzz.NewConsumer(data)
		cons.AddFuncs(customFuncs)

		var target T
		err := cons.GenerateWithCustom(&target)
		if err != nil {
			return
		}

		svcBytes, err := json.Marshal(target)
		if err != nil {
			t.Fatalf("Marshal: %s", err)
		}

		var unmarshalled T
		err = json.Unmarshal(svcBytes, &unmarshalled)
		if err != nil {
			t.Fatalf("Unmarshal: %s", err)
		}

		row1 := target.TableRow()
		row2 := unmarshalled.TableRow()
		if !slices.Equal(row1, row2) {
			t.Fatalf("With %v, rows do not match: %#v VS %#v", target, row1, row2)
		}
	})
}

func FuzzJSONService(f *testing.F) {
	tableRowJSONFuzzer[*loadbalancer.Service](f)
}

func FuzzJSONFrontend(f *testing.F) {
	tableRowJSONFuzzer[*loadbalancer.Frontend](f)
}

func FuzzJSONBackend(f *testing.F) {
	tableRowJSONFuzzer[*loadbalancer.Backend](f)
}
