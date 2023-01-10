// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/api/v1/models"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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
