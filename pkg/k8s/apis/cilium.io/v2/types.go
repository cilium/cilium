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

	"github.com/cilium/cilium/api/v1/models"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api/v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"
)

var (
	// log is the k8s package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumNetworkPolicy is a Kubernetes third-party resource with an extended version
// of NetworkPolicy
type CiliumNetworkPolicy struct {
	// +k8s:openapi-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec *v2.Rule `json:"spec,omitempty"`

	// Specs is a list of desired Cilium specific rule specification.
	Specs v2.Rules `json:"specs,omitempty"`

	// Status is the status of the Cilium policy rule
	// +optional
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

	// Revision is the policy revision of the repository which first implemented
	// this policy.
	Revision uint64 `json:"localPolicyRevision,omitempty"`

	// Enforcing is set to true once all endpoints present at the time the
	// policy has been imported are enforcing this policy.
	Enforcing bool `json:"enforcing,omitempty"`
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
func (r *CiliumNetworkPolicy) Parse() (v2.Rules, error) {
	if r.ObjectMeta.Name == "" {
		return nil, fmt.Errorf("CiliumNetworkPolicy must have name")
	}

	namespace := k8sUtils.ExtractNamespace(&r.ObjectMeta)
	name := r.ObjectMeta.Name

	retRules := v2.Rules{}

	if r.Spec != nil {
		if err := r.Spec.Sanitize(); err != nil {
			return nil, fmt.Errorf("Invalid CiliumNetworkPolicy spec: %s", err)

		}
		cr := k8sUtils.ParseToCiliumRule(namespace, name, r.Spec)
		retRules = append(retRules, cr)
	}
	if r.Specs != nil {
		for _, rule := range r.Specs {
			if err := rule.Sanitize(); err != nil {
				return nil, fmt.Errorf("Invalid CiliumNetworkPolicy specs: %s", err)

			}
			cr := k8sUtils.ParseToCiliumRule(namespace, name, rule)
			retRules = append(retRules, cr)
		}
	}

	return retRules, nil
}

// GetControllerName returns the unique name for the controller manager.
func (r *CiliumNetworkPolicy) GetControllerName() string {
	name := k8sUtils.GetObjNamespaceName(&r.ObjectMeta)
	return fmt.Sprintf("%s (v2 %s)", k8sConst.CtrlPrefixPolicyStatus, name)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumNetworkPolicyList is a list of CiliumNetworkPolicy objects
// +k8s:openapi-gen=false
type CiliumNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNetworkPolicy
	Items []CiliumNetworkPolicy `json:"items"`
}

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumEndpoint is the status of a Cilium policy rule
// +k8s:openapi-gen=false
type CiliumEndpoint struct {
	// +k8s:openapi-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	metav1.ObjectMeta `json:"metadata"`

	Status CiliumEndpointDetail `json:"status"`
}

// CiliumEndpointDetail is the status of a Cilium policy rule
// The custom deepcopy function below is a workaround. We can generate a
// deepcopy for CiliumEndpointDetail but not for the various models.* types it
// includes. We can't generate functions for classes in other packages, nor can
// we change the models.Endpoint type to use proxy types we define here.
// +k8s:deepcopy-gen=false
type CiliumEndpointDetail models.Endpoint

// DeepCopyInto is an inefficient hack to allow reusing models.Endpoint in the
// CiliumEndpoint CRD.
func (in *CiliumEndpointDetail) DeepCopyInto(out *CiliumEndpointDetail) {
	*out = *in
	b, err := (*models.Endpoint)(in).MarshalBinary()
	if err != nil {
		log.WithError(err).Error("Cannot marshal models.Endpoint during CiliumEndpoitnDetail deepcopy")
		return
	}
	err = (*models.Endpoint)(out).UnmarshalBinary(b)
	if err != nil {
		log.WithError(err).Error("Cannot unmarshal models.Endpoint during CiliumEndpoitnDetail deepcopy")
		return
	}
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CiliumEndpointList is a list of CiliumEndpoint objects
// +k8s:openapi-gen=false
type CiliumEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEndpoint
	Items []CiliumEndpoint `json:"items"`
}
