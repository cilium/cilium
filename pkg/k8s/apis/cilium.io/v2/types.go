// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	"fmt"
	"reflect"
	"time"

	"github.com/cilium/cilium/common"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
)

var (
	// log is the k8s package logger object.
	log = common.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumNetworkPolicy is a Kubernetes third-party resource with an extended version
// of NetworkPolicy
type CiliumNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec *api.Rule `json:"spec,omitempty"`

	// Specs is a list of desired Cilium specific rule specification.
	Specs api.Rules `json:"specs,omitempty"`

	// Status is the status of the Cilium policy rule
	Status CiliumNetworkPolicyStatus `json:"status"`
}

// CiliumNetworkPolicyStatus is the status of a Cilium policy rule
type CiliumNetworkPolicyStatus struct {
	// Nodes is the Cilium policy status for each node
	Nodes map[string]CiliumNetworkPolicyNodeStatus `json:"nodes,omitempty"`
}

// CiliumNetworkPolicyNodeStatus is the status of a Cilium policy rule for a
// specific node
type CiliumNetworkPolicyNodeStatus struct {
	// OK is true when the policy has been installed successfully
	OK bool `json:"ok,omitempty"`

	// Error describes the error condition if OK is false
	Error string `json:"error,omitempty"`

	// LastUpdated contains the last time this status was updated
	LastUpdated Timestamp `json:"lastUpdated,omitempty"`
}

// NewTimestamp creates a new Timestamp with the current time.Now()
func NewTimestamp() Timestamp {
	return Timestamp{time.Now()}
}

// Timestamp is a wrapper of time.Time so that we can create our own
// implementation of DeepCopyInto.
type Timestamp struct {
	time.Time
}

// DeepCopyInto creates a deep-copy of the Time value.  The underlying time.Time
// type is effectively immutable in the time API, so it is safe to
// copy-by-assign, despite the presence of (unexported) Pointer fields.
func (t *Timestamp) DeepCopyInto(out *Timestamp) {
	*out = *t
}

// SetPolicyStatus sets the given policy status for the given nodes' map
func (r *CiliumNetworkPolicy) SetPolicyStatus(nodeName string, cnpns CiliumNetworkPolicyNodeStatus) {
	if r.Status.Nodes == nil {
		r.Status.Nodes = map[string]CiliumNetworkPolicyNodeStatus{}
	}
	r.Status.Nodes[nodeName] = cnpns
}

// SpecEquals returns true if the spec and specs metadata is the sa
func (r *CiliumNetworkPolicy) SpecEquals(o *CiliumNetworkPolicy) bool {
	if o == nil {
		return r == nil
	}
	return reflect.DeepEqual(r.Spec, o.Spec) &&
		reflect.DeepEqual(r.Specs, o.Specs)
}

// Parse parses a CiliumNetworkPolicy and returns a list of cilium policy
// rules.
func (r *CiliumNetworkPolicy) Parse() (api.Rules, error) {
	if r.ObjectMeta.Name == "" {
		return nil, fmt.Errorf("CiliumNetworkPolicy must have name")
	}

	namespace := k8sconst.ExtractNamespace(&r.ObjectMeta)
	name := r.ObjectMeta.Name

	retRules := api.Rules{}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, fmt.Errorf("Invalid CiliumNetworkPolicy spec: %s", err)

		}
		cr := k8sconst.ParseToCiliumRule(namespace, name, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, fmt.Errorf("Invalid CiliumNetworkPolicy specs: %s", err)

			}
			cr := k8sconst.ParseToCiliumRule(namespace, name, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumNetworkPolicyList is a list of CiliumNetworkPolicy objects
type CiliumNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNetworkPolicy
	Items []CiliumNetworkPolicy `json:"items"`
}
