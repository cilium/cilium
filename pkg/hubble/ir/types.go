// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

// Aggregate tracks aggregate flow information.
type Aggregate struct {
	IngressFlowCount uint32 `json:"ingressFlowCount,omitempty"`
	EgressFlowCount  uint32 `json:"egressFlowCount,omitempty"`
}
