// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestWorkloads_toProto(t *testing.T) {
	uu := map[string]struct {
		in Workloads
		e  []*flow.Workload
	}{
		"none": {},

		"empty": {
			in: make(Workloads, 0),
		},

		"full": {
			in: Workloads{
				Workload{
					Name: "blee",
					Kind: "duh",
				},
				Workload{
					Name: "fred",
					Kind: "duh",
				},
			},
			e: []*flow.Workload{
				{
					Name: "blee",
					Kind: "duh",
				},
				{
					Name: "fred",
					Kind: "duh",
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func TestWorkload_toProto(t *testing.T) {
	uu := map[string]struct {
		in Workload
		e  *flow.Workload
	}{
		"empty": {},

		"filled": {
			in: Workload{
				Name: "blee",
				Kind: "duh",
			},
			e: &flow.Workload{
				Name: "blee",
				Kind: "duh",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			a := u.in.toProto()
			assert.Equal(t, u.e, a)
		})
	}
}

func TestProtoToWorkloads(t *testing.T) {
	uu := map[string]struct {
		in []*flow.Workload
		e  Workloads
	}{
		"none": {},

		"empty": {
			in: make([]*flow.Workload, 0),
		},

		"full": {
			in: []*flow.Workload{
				{
					Name: "blee",
					Kind: "duh",
				},
				{
					Name: "fred",
					Kind: "duh",
				},
			},
			e: Workloads{
				Workload{
					Name: "blee",
					Kind: "duh",
				},
				Workload{
					Name: "fred",
					Kind: "duh",
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToWorkloads(u.in))
		})
	}
}

func Test_protoToWorkload(t *testing.T) {
	uu := map[string]struct {
		in *flow.Workload
		e  Workload
	}{
		"none": {},

		"filled": {
			in: &flow.Workload{
				Name: "foo",
				Kind: "bar",
			},
			e: Workload{
				Name: "foo",
				Kind: "bar",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			a := protoToWorkload(u.in)
			assert.Equal(t, u.e, a)
		})
	}
}

func TestWorkload_isEmpty(t *testing.T) {
	uu := map[string]struct {
		in Workload
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: Workload{
				Name: "foo",
				Kind: "bar",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			a := u.in.isEmpty()
			assert.Equal(t, u.e, a)
		})
	}
}
