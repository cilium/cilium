// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// Workloads tracks workloads
type Workloads []Workload

func (ws Workloads) toProto() []*flow.Workload {
	if len(ws) == 0 {
		return nil
	}

	workloads := make([]*flow.Workload, 0, len(ws))
	for _, w := range ws {
		workloads = append(workloads, &flow.Workload{
			Name: w.Name,
			Kind: w.Kind,
		})
	}

	return workloads
}

// ProtoToWorkloads converts a protobuf Workloads slice to an internal representation.
func ProtoToWorkloads(ww []*flow.Workload) Workloads {
	if len(ww) == 0 {
		return nil
	}

	workloads := make([]Workload, 0, len(ww))
	for _, w := range ww {
		workloads = append(workloads, protoToWorkload(w))
	}

	return workloads
}

// Workload tracks a flow workload information.
type Workload struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

func (w Workload) isEmpty() bool {
	return w.Name == "" && w.Kind == ""
}

func (w Workload) toProto() *flow.Workload {
	if w.isEmpty() {
		return nil
	}

	return &flow.Workload{
		Name: w.Name,
		Kind: w.Kind,
	}
}

func protoToWorkload(w *flow.Workload) Workload {
	if w == nil {
		return Workload{}
	}

	return Workload{
		Name: w.Name,
		Kind: w.Kind,
	}
}
