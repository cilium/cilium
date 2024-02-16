// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

const (
	// maximum number of operations a single json patch may contain.
	// See https://github.com/kubernetes/kubernetes/pull/74000
	MaxJSONPatchOperations = 10000
)

// JSONPatch structure based on the RFC 6902
type JSONPatch struct {
	OP    string      `json:"op,omitempty"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value"`
}
