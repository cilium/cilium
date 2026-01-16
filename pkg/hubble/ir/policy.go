// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import "github.com/cilium/cilium/api/v1/flow"

// Policy tracks flow policy matching information.
type Policy struct {
	Kind      string   `json:"kind,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	Labels    []string `json:"labels,omitempty"`
	Revision  uint64   `json:"revision,omitempty"`
}

// ProtoToPolicy converts a protobuf policy to an internal policy.
func ProtoToPolicy(p *flow.Policy) Policy {
	if p == nil {
		return Policy{}
	}

	return Policy{
		Kind:      p.Kind,
		Namespace: p.Namespace,
		Name:      p.Name,
		Labels:    p.Labels,
		Revision:  p.Revision,
	}
}
