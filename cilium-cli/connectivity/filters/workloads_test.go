// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestWorkloads(t *testing.T) {
	source := &flowpb.Workload{Name: "client", Kind: "Deployment"}
	destination := &flowpb.Workload{Name: "echo-other-node", Kind: "Deployment"}

	tests := []struct {
		name   string
		filter FlowFilterImplementation
		flow   *flowpb.Flow
		match  bool
	}{
		{
			name:   "both workloads",
			filter: Workloads(source, destination),
			flow: &flowpb.Flow{
				Source:      &flowpb.Endpoint{Workloads: []*flowpb.Workload{source}},
				Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{destination}},
			},
			match: true,
		},
		{
			name:   "missing destination workload",
			filter: Workloads(source, destination),
			flow: &flowpb.Flow{
				Source:      &flowpb.Endpoint{Workloads: []*flowpb.Workload{source}},
				Destination: &flowpb.Endpoint{},
			},
		},
		{
			name:   "wrong source kind",
			filter: Workloads(source, destination),
			flow: &flowpb.Flow{
				Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{{
					Name: "client",
					Kind: "StatefulSet",
				}}},
				Destination: &flowpb.Endpoint{Workloads: []*flowpb.Workload{destination}},
			},
		},
		{
			name:   "source only",
			filter: Workloads(source, nil),
			flow: &flowpb.Flow{
				Source: &flowpb.Endpoint{Workloads: []*flowpb.Workload{source}},
			},
			match: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowContext := NewFlowContext()
			assert.Equal(t, tt.match, tt.filter.Match(tt.flow, &flowContext))
		})
	}
}
