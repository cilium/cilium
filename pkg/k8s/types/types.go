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
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=true
type SlimCNP struct {
	*v2.CiliumNetworkPolicy
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen:private-method=true
type CiliumEndpoint struct {
	// +deepequal-gen=false
	slim_metav1.TypeMeta
	// +deepequal-gen=false
	slim_metav1.ObjectMeta
	Identity   *v2.EndpointIdentity
	Networking *v2.EndpointNetworking
	Encryption *v2.EncryptionSpec
	NamedPorts models.NamedPorts
}

type Configuration interface {
	K8sAPIDiscoveryEnabled() bool
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

// +deepequal-gen=true
type IPSlice []string
