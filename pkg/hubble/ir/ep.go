// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

// Endpoint tracks flow endpoint information.
type Endpoint struct {
	ClusterName string    `json:"clusterName,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	PodName     string    `json:"podName,omitempty"`
	Labels      []string  `json:"labels,omitempty"`
	Workloads   Workloads `json:"workloads,omitempty"`
	ID          uint32    `json:"id,omitempty"`
	Identity    uint32    `json:"identity,omitempty"`
}

// IsEmpty returns true if the endpoint has no information set.
func (e Endpoint) IsEmpty() bool {
	return e.ID == 0 && e.Identity == 0 && e.ClusterName == "" && e.Namespace == "" && e.PodName == "" && len(e.Labels) == 0 && len(e.Workloads) == 0
}

func (e Endpoint) merge(e1 Endpoint) Endpoint {
	if e1.ID != 0 {
		e.ID = e1.ID
	}
	if e1.Identity != 0 {
		e.Identity = e1.Identity
	}

	if e1.ClusterName != "" {
		e.ClusterName = e1.ClusterName
	}
	if e1.Namespace != "" {
		e.Namespace = e1.Namespace
	}
	if e1.PodName != "" {
		e.PodName = e1.PodName
	}

	if len(e1.Labels) > 0 {
		e.Labels = e1.Labels
	}

	if len(e1.Workloads) > 0 {
		e.Workloads = e1.Workloads
	}

	return e
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
