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

	workloads := make([]*flow.Workload, len(ws))
	for i := range ws {
		workloads[i] = &flow.Workload{
			Name: ws[i].Name,
			Kind: ws[i].Kind,
		}
	}

	return workloads
}

// ProtoToWorkloads converts a protobuf Workloads slice to an internal representation.
func ProtoToWorkloads(ww []*flow.Workload) Workloads {
	if len(ww) == 0 {
		return nil
	}

	workloads := make([]Workload, 0, len(ww))
	for i := range ww {
		workloads = append(workloads, protoToWorkload(ww[i]))
	}

	return workloads
}

// Workload tracks a flow workload information.
type Workload struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

// IsEmpty returns true if the workload has no information set.
func (w Workload) IsEmpty() bool {
	return w.Name == "" && w.Kind == ""
}

func (w Workload) toProto() *flow.Workload {
	if w.IsEmpty() {
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
