// Copyright 2019-2020 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"k8s.io/api/core/v1"
	"k8s.io/api/discovery/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type NetworkPolicy struct {
	*networkingv1.NetworkPolicy
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type Service struct {
	*v1.Service
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type Endpoints struct {
	*v1.Endpoints
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type EndpointSlice struct {
	*v1beta1.EndpointSlice
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=true
type SlimCNP struct {
	*v2.CiliumNetworkPolicy
}

type ContainerPort struct {
	Protocol      string
	ContainerPort int32
	HostPort      int32
	HostIP        string
}

type PodContainer struct {
	Name              string
	Image             string
	VolumeMountsPaths []string
	HostPorts         []ContainerPort
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
type Pod struct {
	// +deepequal-gen=false
	metav1.TypeMeta
	// +deepequal-gen=false
	metav1.ObjectMeta
	StatusPodIP            string
	StatusHostIP           string
	SpecServiceAccountName string
	SpecHostNetwork        bool

	// For Istio & hostPort mapping we need to keep these:
	SpecContainers []PodContainer
}

// AnnotationsEqual returns whether the annotation with any key in
// relevantAnnotations is equal in anno1 and anno2.
func AnnotationsEqual(relevantAnnotations []string, anno1, anno2 map[string]string) bool {
	for _, an := range relevantAnnotations {
		if anno1[an] != anno2[an] {
			return false
		}
	}
	return true
}

func (in *Pod) DeepEqual(other *Pod) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if in.Namespace != other.Namespace {
		return false
	}

	if !AnnotationsEqual([]string{annotation.ProxyVisibility}, in.GetAnnotations(), other.GetAnnotations()) {
		return false
	}

	oldPodLabels := in.GetLabels()
	newPodLabels := other.GetLabels()
	if !comparator.MapStringEquals(oldPodLabels, newPodLabels) {
		return false
	}

	return in.deepEqual(other)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type Node struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Type            v1.NodeAddressType
	StatusAddresses []v1.NodeAddress
	SpecPodCIDR     string
	SpecPodCIDRs    []string
	SpecTaints      []v1.Taint
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
type Namespace struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
type CiliumEndpoint struct {
	// +deepequal-gen=false
	metav1.TypeMeta
	// +deepequal-gen=false
	metav1.ObjectMeta
	Identity   *v2.EndpointIdentity
	Networking *v2.EndpointNetworking
	Encryption *v2.EncryptionSpec
}

func (in *CiliumEndpoint) DeepEqual(other *CiliumEndpoint) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if in.Namespace != other.Namespace {
		return false
	}

	return in.deepEqual(other)
}
