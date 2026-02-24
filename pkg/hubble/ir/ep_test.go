// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestEndpointIsEmpty(t *testing.T) {
	uu := map[string]struct {
		e    Endpoint
		want bool
	}{
		"empty": {
			want: true,
		},

		"partial": {
			e: Endpoint{
				ID:       1,
				Identity: 100,
			},
		},

		"full": {
			e: Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cluster",
				Namespace:   "namespace",
				PodName:     "pod",
				Labels:      []string{"label1", "label2"},
				Workloads:   []Workload{{Name: "workload1", Kind: "kind1"}},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.want, u.e.IsEmpty())
		})
	}
}

func TestEndpoint_merge(t *testing.T) {
	uu := map[string]struct {
		e1, e2, want Endpoint
	}{
		"empty": {},

		"blank-src": {
			e2: Endpoint{
				ID:       1,
				Identity: 100,
			},
			want: Endpoint{
				ID:       1,
				Identity: 100,
			},
		},

		"blank-dst": {
			e1: Endpoint{
				ID:       1,
				Identity: 100,
			},
			want: Endpoint{
				ID:       1,
				Identity: 100,
			},
		},

		"full": {
			e1: Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cl1",
				Namespace:   "ns1",
				PodName:     "p1",
				Labels:      []string{"l1", "l2"},
				Workloads:   []Workload{{Name: "wk1", Kind: "po"}},
			},
			e2: Endpoint{
				ID:          300,
				Identity:    400,
				ClusterName: "cl2",
				Namespace:   "ns2",
				PodName:     "p2",
				Labels:      []string{"l1-1", "l1-2"},
				Workloads:   []Workload{{Name: "wk1-2", Kind: "po"}},
			},
			want: Endpoint{
				ID:          300,
				Identity:    400,
				ClusterName: "cl2",
				Namespace:   "ns2",
				PodName:     "p2",
				Labels:      []string{"l1-1", "l1-2"},
				Workloads:   []Workload{{Name: "wk1-2", Kind: "po"}},
			},
		},

		"partial": {
			e1: Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cl1",
				Namespace:   "ns1",
				PodName:     "p1",
				Labels:      []string{"l1", "l2"},
				Workloads:   []Workload{{Name: "wk1", Kind: "po"}},
			},
			e2: Endpoint{
				Labels:    []string{"l1-1", "l1-2"},
				Workloads: []Workload{{Name: "wk1-2", Kind: "po"}},
			},
			want: Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cl1",
				Namespace:   "ns1",
				PodName:     "p1",
				Labels:      []string{"l1-1", "l1-2"},
				Workloads:   []Workload{{Name: "wk1-2", Kind: "po"}},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.want, u.e1.merge(u.e2))
		})
	}
}

func TestProtoToEP(t *testing.T) {
	uu := map[string]struct {
		in   *flow.Endpoint
		want Endpoint
	}{
		"nil": {
			in:   nil,
			want: Endpoint{},
		},

		"empty": {
			in:   &flow.Endpoint{},
			want: Endpoint{},
		},

		"full": {
			in: &flow.Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cluster",
				Namespace:   "namespace",
				PodName:     "pod",
				Labels:      []string{"label1", "label2"},
				Workloads: []*flow.Workload{
					{Name: "workload1", Kind: "kind1"},
				},
			},
			want: Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cluster",
				Namespace:   "namespace",
				PodName:     "pod",
				Labels:      []string{"label1", "label2"},
				Workloads: []Workload{
					{Name: "workload1", Kind: "kind1"},
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.want, ProtoToEp(u.in))
		})
	}
}

func TestEndpoint_toProto(t *testing.T) {
	uu := map[string]struct {
		in   Endpoint
		want *flow.Endpoint
	}{
		"empty": {
			in:   Endpoint{},
			want: nil,
		},

		"full": {
			in: Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cluster",
				Namespace:   "namespace",
				PodName:     "pod",
				Labels:      []string{"label1", "label2"},
				Workloads: []Workload{
					{Name: "workload1", Kind: "kind1"},
				},
			},
			want: &flow.Endpoint{
				ID:          100,
				Identity:    200,
				ClusterName: "cluster",
				Namespace:   "namespace",
				PodName:     "pod",
				Labels:      []string{"label1", "label2"},
				Workloads: []*flow.Workload{
					{Name: "workload1", Kind: "kind1"},
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.want, u.in.toProto())
		})
	}
}
