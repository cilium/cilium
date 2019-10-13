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
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/kubelet/types"
)

// ExtractNamespace extracts the namespace of ObjectMeta.
// For cluster scoped objects the Namespace field is empty and this function
// assumes that the object is returned from kubernetes itself implying that
// the namespace is empty only and only when the Object is cluster scoped
// and thus returns empty namespace for such objects.
func ExtractNamespace(np metav1.Object) string {
	return np.GetNamespace()
}

// ExtractNamespaceOrDefault extracts the namespace of ObjectMeta, it returns default
// namespace if the namespace field in the ObjectMeta is empty.
func ExtractNamespaceOrDefault(np metav1.Object) string {
	ns := np.GetNamespace()
	if ns == "" {
		return v1.NamespaceDefault
	}

	return ns
}

// GetObjNamespaceName returns the object's namespace and name.
// If the object is cluster scoped then the function returns only the object name
// without any namespace prefix.
func GetObjNamespaceName(obj metav1.Object) string {
	ns := ExtractNamespace(obj)
	if ns == "" {
		return obj.GetName()
	}

	return ns + "/" + obj.GetName()
}

// GetObjUID returns the object's namespace and name.
func GetObjUID(obj metav1.Object) string {
	return GetObjNamespaceName(obj) + "/" + string(obj.GetUID())
}

// IsInfraContainer returns true if the given set of labels represent a infra
// container.
func IsInfraContainer(labels map[string]string) bool {
	return labels[types.KubernetesContainerNameLabel] == "POD"

}
