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
	"fmt"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CiliumRule is third-party ressource that can be used with Kubernetes
type CiliumRule struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	// Spec is the desired Cilium specific rule specification.
	Spec api.Rule
}

func (r *CiliumRule) Parse() (api.Rules, error) {
	if err := r.Spec.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid spec: %s", err)
	}

	if r.Name == "" {
		return nil, fmt.Errorf("CiliumRule must have name")
	}

	// Convert resource name to a Cilium policy rule label
	label := fmt.Sprintf("%s=%s", k8s.PolicyLabelName, r.Name)

	// TODO: Warn about overwritten labels?
	r.Spec.Labels = labels.ParseLabelArray(label)

	return api.Rules{&r.Spec}, nil
}
