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

package k8s

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// CiliumNetworkPolicy is a Kubernetes third-party resource with an extended version
// of NetworkPolicy
type CiliumNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	Metadata metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired Cilium specific rule specification.
	Spec api.Rule `json:"spec"`
}

// GetObjectKind returns the kind of the object
func (r *CiliumNetworkPolicy) GetObjectKind() schema.ObjectKind {
	return &r.TypeMeta
}

// GetObjectMeta returns the metadata of the object
func (r *CiliumNetworkPolicy) GetObjectMeta() metav1.Object {
	return &r.Metadata
}

// Parse parses a CiliumNetworkPolicy and returns a list of internal policy rules
func (r *CiliumNetworkPolicy) Parse() (api.Rules, error) {
	if err := r.Spec.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid spec: %s", err)
	}

	if r.Metadata.Name == "" {
		return nil, fmt.Errorf("CiliumNetworkPolicy must have name")
	}

	// Convert resource name to a Cilium policy rule label
	label := fmt.Sprintf("%s=%s", k8s.PolicyLabelName, r.Metadata.Name)

	// TODO: Warn about overwritten labels?
	r.Spec.Labels = labels.ParseLabelArray(label)

	return api.Rules{&r.Spec}, nil
}

type ciliumNetworkPolicyCopy CiliumNetworkPolicy

// UnmarshalJSON parses JSON into a CiliumNetworkPolicy
func (e *CiliumNetworkPolicy) UnmarshalJSON(data []byte) error {
	tmp := ciliumNetworkPolicyCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := CiliumNetworkPolicy(tmp)
	*e = tmp2
	return nil
}

// CiliumNetworkPolicyList is a list of CiliumNetworkPolicy objects
type CiliumNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	Metadata metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNetworkPolicy
	Items []CiliumNetworkPolicy `json:"items"`
}

// GetObjectKind returns the kind of the object
func (r *CiliumNetworkPolicyList) GetObjectKind() schema.ObjectKind {
	return &r.TypeMeta
}

// GetListMeta returns the metadata of the object
func (r *CiliumNetworkPolicyList) GetListMeta() metav1.List {
	return &r.Metadata
}

type ciliumNetworkPolicyListCopy CiliumNetworkPolicyList

// UnmarshalJSON parses JSON into a CiliumNetworkPolicyList
func (e *CiliumNetworkPolicyList) UnmarshalJSON(data []byte) error {
	tmp := ciliumNetworkPolicyListCopy{}
	err := json.Unmarshal(data, &tmp)
	if err != nil {
		return err
	}
	tmp2 := CiliumNetworkPolicyList(tmp)
	*e = tmp2
	return nil
}
