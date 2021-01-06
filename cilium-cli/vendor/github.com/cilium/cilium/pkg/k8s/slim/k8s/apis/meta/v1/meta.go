// Copyright 2016 The Kubernetes Authors.
// Copyright 2020 Authors of Cilium
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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func (meta *ListMeta) GetResourceVersion() string        { return meta.ResourceVersion }
func (meta *ListMeta) SetResourceVersion(version string) { meta.ResourceVersion = version }
func (meta *ListMeta) GetSelfLink() string               { panic("not implemented") }
func (meta *ListMeta) SetSelfLink(_ string)              { panic("not implemented") }
func (meta *ListMeta) GetContinue() string               { return meta.Continue }
func (meta *ListMeta) SetContinue(c string)              { meta.Continue = c }
func (meta *ListMeta) GetRemainingItemCount() *int64     { return meta.RemainingItemCount }
func (meta *ListMeta) SetRemainingItemCount(c *int64)    { meta.RemainingItemCount = c }

func (obj *TypeMeta) GetObjectKind() schema.ObjectKind { return obj }

// SetGroupVersionKind satisfies the ObjectKind interface for all objects that embed TypeMeta
func (obj *TypeMeta) SetGroupVersionKind(gvk schema.GroupVersionKind) {
	obj.APIVersion, obj.Kind = gvk.ToAPIVersionAndKind()
}

// GroupVersionKind satisfies the ObjectKind interface for all objects that embed TypeMeta
func (obj *TypeMeta) GroupVersionKind() schema.GroupVersionKind {
	return schema.FromAPIVersionAndKind(obj.APIVersion, obj.Kind)
}

func (obj *ListMeta) GetListMeta() metav1.ListInterface { return obj }

func (obj *ObjectMeta) GetObjectMeta() metav1.Object { return obj }

// Namespace implements metav1.Object for any object with an ObjectMeta typed field. Allows
// fast, direct access to metadata fields for API objects.
func (meta *ObjectMeta) GetNamespace() string              { return meta.Namespace }
func (meta *ObjectMeta) SetNamespace(namespace string)     { meta.Namespace = namespace }
func (meta *ObjectMeta) GetName() string                   { return meta.Name }
func (meta *ObjectMeta) SetName(name string)               { meta.Name = name }
func (meta *ObjectMeta) GetGenerateName() string           { panic("not implemented") }
func (meta *ObjectMeta) SetGenerateName(string)            { panic("not implemented") }
func (meta *ObjectMeta) GetUID() types.UID                 { return meta.UID }
func (meta *ObjectMeta) SetUID(uid types.UID)              { meta.UID = uid }
func (meta *ObjectMeta) GetResourceVersion() string        { return meta.ResourceVersion }
func (meta *ObjectMeta) SetResourceVersion(ver string)     { meta.ResourceVersion = ver }
func (meta *ObjectMeta) GetGeneration() int64              { panic("not implemented") }
func (meta *ObjectMeta) SetGeneration(_ int64)             { panic("not implemented") }
func (meta *ObjectMeta) GetSelfLink() string               { panic("not implemented") }
func (meta *ObjectMeta) SetSelfLink(_ string)              { panic("not implemented") }
func (meta *ObjectMeta) GetCreationTimestamp() metav1.Time { panic("not implemented") }
func (meta *ObjectMeta) SetCreationTimestamp(_ metav1.Time) {
	panic("not implemented")
}
func (meta *ObjectMeta) GetDeletionTimestamp() *metav1.Time { panic("not implemented") }
func (meta *ObjectMeta) SetDeletionTimestamp(_ *metav1.Time) {
	panic("not implemented")
}
func (meta *ObjectMeta) GetDeletionGracePeriodSeconds() *int64 {
	panic("not implemented")
}
func (meta *ObjectMeta) SetDeletionGracePeriodSeconds(_ *int64) {
	panic("not implemented")
}
func (meta *ObjectMeta) GetLabels() map[string]string                 { return meta.Labels }
func (meta *ObjectMeta) SetLabels(labels map[string]string)           { meta.Labels = labels }
func (meta *ObjectMeta) GetAnnotations() map[string]string            { return meta.Annotations }
func (meta *ObjectMeta) SetAnnotations(annotations map[string]string) { meta.Annotations = annotations }
func (meta *ObjectMeta) GetFinalizers() []string                      { panic("not implemented") }
func (meta *ObjectMeta) SetFinalizers(_ []string)                     { panic("not implemented") }
func (meta *ObjectMeta) GetOwnerReferences() []metav1.OwnerReference  { panic("not implemented") }
func (meta *ObjectMeta) SetOwnerReferences(_ []metav1.OwnerReference) {
	panic("not implemented")
}
func (meta *ObjectMeta) GetClusterName() string                         { panic("not implemented") }
func (meta *ObjectMeta) SetClusterName(_ string)                        { panic("not implemented") }
func (meta *ObjectMeta) GetManagedFields() []metav1.ManagedFieldsEntry  { panic("not implemented") }
func (meta *ObjectMeta) SetManagedFields(_ []metav1.ManagedFieldsEntry) { panic("not implemented") }
