// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fence

import "testing"

// TestFence will ensure stale revisions
// are fenced off and new revisions are not.
func TestFence(t *testing.T) {
	table := []struct {
		// name of the test
		Name string
		// any order of Meta objects to front
		// load into the fence
		Load []Meta
		// the final Meta to record the result
		// of the fence
		Final Meta
		// what we expect the outcome to be when
		// Final is presented to the fence.
		Expect bool
	}{
		{
			Name: "No fence",
			Load: []Meta{
				{
					UUID: "1",
					Rev:  1,
				},
				{
					UUID: "1",
					Rev:  2,
				},
				{
					UUID: "1",
					Rev:  3,
				},
				{
					UUID: "1",
					Rev:  4,
				},
			},
			Final: Meta{
				UUID: "1",
				Rev:  5,
			},
			Expect: false,
		},
		{
			Name: "No fence - replay same rev",
			Load: []Meta{
				{
					UUID: "1",
					Rev:  1,
				},
			},
			Final: Meta{
				UUID: "1",
				Rev:  1,
			},
			Expect: false,
		},
		{
			Name: "Fence - stale rev",
			Load: []Meta{
				{
					UUID: "1",
					Rev:  1,
				},
				{
					UUID: "1",
					Rev:  2,
				},
				{
					UUID: "1",
					Rev:  3,
				},
				{
					UUID: "1",
					Rev:  4,
				},
			},
			Final: Meta{
				UUID: "1",
				Rev:  1,
			},
			Expect: true,
		},
	}

	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			f := Fencer{}
			for _, m := range tt.Load {
				f.Fence(m)
			}
			if b := f.Fence(tt.Final); b != tt.Expect {
				t.Fatalf("got: %v, want: %v", b, tt.Expect)
			}
		})
	}
}
