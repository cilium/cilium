// Copyright 2019 Authors of Cilium
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

package types

import (
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NetworkPolicy struct {
	*networkingv1.NetworkPolicy
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Service struct {
	*v1.Service
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Endpoints struct {
	*v1.Endpoints
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Ingress struct {
	*v1beta1.Ingress
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SlimCNP struct {
	*v2.CiliumNetworkPolicy
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Pod struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	StatusPodIP     string
	StatusHostIP    string
	SpecHostNetwork bool
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Node struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Type            v1.NodeAddressType
	StatusAddresses []v1.NodeAddress
	SpecPodCIDR     string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Namespace struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Identity struct {
	*v2.CiliumIdentity
}

// ConvertToIdentity converts a *v1.Namespace into a *types.Namespace.
// WARNING calling this function will set *all* fields of the given Namespace as
// empty.
func ConvertToIdentity(obj interface{}) interface{} {
	identity, ok := obj.(*v2.CiliumIdentity)
	if !ok {
		return nil
	}
	return &Identity{
		CiliumIdentity: identity,
	}
}
