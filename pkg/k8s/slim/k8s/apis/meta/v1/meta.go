// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2016 The Kubernetes Authors.

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
func (meta *ObjectMeta) GetDeletionTimestamp() *metav1.Time {
	if meta.DeletionTimestamp == nil {
		return nil
	}
	return &metav1.Time{
		Time: meta.DeletionTimestamp.Time,
	}
}
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
func (meta *ObjectMeta) GetOwnerReferences() []metav1.OwnerReference {
	return FullOwnerReferences(meta.OwnerReferences)
}
func (meta *ObjectMeta) SetOwnerReferences(references []metav1.OwnerReference) {
	meta.OwnerReferences = SlimOwnerReferences(references)
}
func (meta *ObjectMeta) GetZZZ_DeprecatedClusterName() string           { panic("not implemented") }
func (meta *ObjectMeta) SetZZZ_DeprecatedClusterName(_ string)          { panic("not implemented") }
func (meta *ObjectMeta) GetManagedFields() []metav1.ManagedFieldsEntry  { panic("not implemented") }
func (meta *ObjectMeta) SetManagedFields(_ []metav1.ManagedFieldsEntry) { panic("not implemented") }
