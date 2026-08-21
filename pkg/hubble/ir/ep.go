// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// Endpoint tracks flow endpoint information.
type Endpoint struct {
	ClusterName string    `json:"cluster_name,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	PodName     string    `json:"pod_name,omitempty"`
	Labels      []string  `json:"labels,omitempty"`
	Workloads   Workloads `json:"workloads,omitempty"`
	ID          uint32    `json:"id,omitempty"`
	Identity    uint32    `json:"identity,omitempty"`
}

// IsEmpty returns true if the endpoint has no information set.
func (e Endpoint) IsEmpty() bool {
	return e.ID == 0 && e.Identity == 0 && e.ClusterName == "" && e.Namespace == "" && e.PodName == "" && len(e.Labels) == 0 && len(e.Workloads) == 0
}

// epTestMerge merges 2 endpoints
// NOTE: This is only used for testing!
func epTestMerge(e1, e2 Endpoint) Endpoint {
	if e2.ID != 0 {
		e1.ID = e2.ID
	}
	if e2.Identity != 0 {
		e1.Identity = e2.Identity
	}

	if e2.ClusterName != "" {
		e1.ClusterName = e2.ClusterName
	}
	if e2.Namespace != "" {
		e1.Namespace = e2.Namespace
	}
	if e2.PodName != "" {
		e1.PodName = e2.PodName
	}

	if len(e2.Labels) > 0 {
		e1.Labels = e2.Labels
	}

	if len(e2.Workloads) > 0 {
		e1.Workloads = e2.Workloads
	}

	return e1
}

func (e Endpoint) toProto() *flow.Endpoint {
	if e.IsEmpty() {
		return nil
	}

	return &flow.Endpoint{
		ID:          e.ID,
		Identity:    e.Identity,
		ClusterName: e.ClusterName,
		Namespace:   e.Namespace,
		PodName:     e.PodName,
		Labels:      e.Labels,
		Workloads:   e.Workloads.toProto(),
	}
}

// ProtoToEp converts protobuf endpoint to its internal representation.
func ProtoToEp(e *flow.Endpoint) Endpoint {
	if e == nil {
		return Endpoint{}
	}

	// This is necessary for the decoder to assign labels to the empty slice vs the nil slice.
	var lbls []string
	if len(e.Labels) > 0 {
		lbls = e.Labels
	}

	return Endpoint{
		ID:          e.ID,
		Identity:    e.Identity,
		ClusterName: e.ClusterName,
		Namespace:   e.Namespace,
		PodName:     e.PodName,
		Labels:      lbls,
		Workloads:   ProtoToWorkloads(e.Workloads),
	}
}
