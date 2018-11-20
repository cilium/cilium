// Copyright 2018 Authors of Cilium
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

package utils

import (
	"github.com/cilium/cilium/pkg/versioned"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/kubelet/types"
)

// ExtractNamespace extracts the namespace of ObjectMeta.
func ExtractNamespace(np metav1.Object) string {
	ns := np.GetNamespace()
	if ns == "" {
		return v1.NamespaceDefault
	}
	return ns
}

// GetObjNamespaceName returns the object's namespace and name.
func GetObjNamespaceName(obj metav1.Object) string {
	return ExtractNamespace(obj) + "/" + obj.GetName()
}

// GetObjUID returns the object's namespace and name.
func GetObjUID(obj metav1.Object) string {
	return GetObjNamespaceName(obj) + "/" + string(obj.GetUID())
}

// GetVerStructFrom returns a versionedObject of the given objMeta.
func GetVerStructFrom(objMeta metav1.Object) (versioned.UUID, versioned.Object) {
	uuid := versioned.UUID(GetObjUID(objMeta))
	v := versioned.ParseVersion(objMeta.GetResourceVersion())
	vs := versioned.Object{
		Data:    objMeta,
		Version: v,
	}
	return uuid, vs
}

// IsInfraContainer returns true if the given set of labels represent a infra
// container.
func IsInfraContainer(labels map[string]string) bool {
	return labels[types.KubernetesContainerNameLabel] == "POD"

}
