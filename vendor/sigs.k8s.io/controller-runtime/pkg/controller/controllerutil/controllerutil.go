/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllerutil

import (
	"context"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// AlreadyOwnedError is an error returned if the object you are trying to assign
// a controller reference is already owned by another controller Object is the
// subject and Owner is the reference for the current owner.
type AlreadyOwnedError struct {
	Object metav1.Object
	Owner  metav1.OwnerReference
}

func (e *AlreadyOwnedError) Error() string {
	return fmt.Sprintf("Object %s/%s is already owned by another %s controller %s", e.Object.GetNamespace(), e.Object.GetName(), e.Owner.Kind, e.Owner.Name)
}

func newAlreadyOwnedError(obj metav1.Object, owner metav1.OwnerReference) *AlreadyOwnedError {
	return &AlreadyOwnedError{
		Object: obj,
		Owner:  owner,
	}
}

// OwnerReferenceOption is a function that can modify a `metav1.OwnerReference`.
type OwnerReferenceOption func(*metav1.OwnerReference)

// WithBlockOwnerDeletion allows configuring the BlockOwnerDeletion field on the `metav1.OwnerReference`.
func WithBlockOwnerDeletion(blockOwnerDeletion bool) OwnerReferenceOption {
	return func(ref *metav1.OwnerReference) {
		ref.BlockOwnerDeletion = &blockOwnerDeletion
	}
}

// SetControllerReference sets owner as a Controller OwnerReference on controlled.
// This is used for garbage collection of the controlled object and for
// reconciling the owner object on changes to controlled (with a Watch + EnqueueRequestForOwner).
// Since only one OwnerReference can be a controller, it returns an error if
// there is another OwnerReference with Controller flag set.
func SetControllerReference(owner, controlled metav1.Object, scheme *runtime.Scheme, opts ...OwnerReferenceOption) error {
	// Validate the owner.
	ro, ok := owner.(runtime.Object)
	if !ok {
		return fmt.Errorf("%T is not a runtime.Object, cannot call SetControllerReference", owner)
	}
	if err := validateOwner(owner, controlled); err != nil {
		return err
	}

	// Create a new controller ref.
	gvk, err := apiutil.GVKForObject(ro, scheme)
	if err != nil {
		return err
	}
	ref := metav1.OwnerReference{
		APIVersion:         gvk.GroupVersion().String(),
		Kind:               gvk.Kind,
		Name:               owner.GetName(),
		UID:                owner.GetUID(),
		BlockOwnerDeletion: ptr.To(true),
		Controller:         ptr.To(true),
	}
	for _, opt := range opts {
		opt(&ref)
	}

	// Return early with an error if the object is already controlled.
	if existing := metav1.GetControllerOf(controlled); existing != nil && !referSameObject(*existing, ref) {
		return newAlreadyOwnedError(controlled, *existing)
	}

	// Update owner references and return.
	upsertOwnerRef(ref, controlled)
	return nil
}

// SetOwnerReference is a helper method to make sure the given object contains an object reference to the object provided.
// This allows you to declare that owner has a dependency on the object without specifying it as a controller.
// If a reference to the same object already exists, it'll be overwritten with the newly provided version.
func SetOwnerReference(owner, object metav1.Object, scheme *runtime.Scheme, opts ...OwnerReferenceOption) error {
	// Validate the owner.
	ro, ok := owner.(runtime.Object)
	if !ok {
		return fmt.Errorf("%T is not a runtime.Object, cannot call SetOwnerReference", owner)
	}
	if err := validateOwner(owner, object); err != nil {
		return err
	}

	// Create a new owner ref.
	gvk, err := apiutil.GVKForObject(ro, scheme)
	if err != nil {
		return err
	}
	ref := metav1.OwnerReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		UID:        owner.GetUID(),
		Name:       owner.GetName(),
	}
	for _, opt := range opts {
		opt(&ref)
	}

	// Update owner references and return.
	upsertOwnerRef(ref, object)
	return nil
}

// RemoveOwnerReference is a helper method to make sure the given object removes an owner reference to the object provided.
// This allows you to remove the owner to establish a new owner of the object in a subsequent call.
func RemoveOwnerReference(owner, object metav1.Object, scheme *runtime.Scheme) error {
	owners := object.GetOwnerReferences()
	length := len(owners)
	if length < 1 {
		return fmt.Errorf("%T does not have any owner references", object)
	}
	ro, ok := owner.(runtime.Object)
	if !ok {
		return fmt.Errorf("%T is not a runtime.Object, cannot call RemoveOwnerReference", owner)
	}
	gvk, err := apiutil.GVKForObject(ro, scheme)
	if err != nil {
		return err
	}

	index := indexOwnerRef(owners, metav1.OwnerReference{
		APIVersion: gvk.GroupVersion().String(),
		Name:       owner.GetName(),
		Kind:       gvk.Kind,
	})
	if index == -1 {
		return fmt.Errorf("%T does not have an owner reference for %T", object, owner)
	}

	owners = append(owners[:index], owners[index+1:]...)
	object.SetOwnerReferences(owners)
	return nil
}

// HasControllerReference returns true if the object
// has an owner ref with controller equal to true
func HasControllerReference(object metav1.Object) bool {
	owners := object.GetOwnerReferences()
	for _, owner := range owners {
		isTrue := owner.Controller
		if owner.Controller != nil && *isTrue {
			return true
		}
	}
	return false
}

// HasOwnerReference returns true if the owners list contains an owner reference
// that matches the object's group, kind, and name.
func HasOwnerReference(ownerRefs []metav1.OwnerReference, obj client.Object, scheme *runtime.Scheme) (bool, error) {
	gvk, err := apiutil.GVKForObject(obj, scheme)
	if err != nil {
		return false, err
	}
	idx := indexOwnerRef(ownerRefs, metav1.OwnerReference{
		APIVersion: gvk.GroupVersion().String(),
		Name:       obj.GetName(),
		Kind:       gvk.Kind,
	})
	return idx != -1, nil
}

// RemoveControllerReference removes an owner reference where the controller
// equals true
func RemoveControllerReference(owner, object metav1.Object, scheme *runtime.Scheme) error {
	if ok := HasControllerReference(object); !ok {
		return fmt.Errorf("%T does not have a owner reference with controller equals true", object)
	}
	ro, ok := owner.(runtime.Object)
	if !ok {
		return fmt.Errorf("%T is not a runtime.Object, cannot call RemoveControllerReference", owner)
	}
	gvk, err := apiutil.GVKForObject(ro, scheme)
	if err != nil {
		return err
	}
	ownerRefs := object.GetOwnerReferences()
	index := indexOwnerRef(ownerRefs, metav1.OwnerReference{
		APIVersion: gvk.GroupVersion().String(),
		Name:       owner.GetName(),
		Kind:       gvk.Kind,
	})

	if index == -1 {
		return fmt.Errorf("%T does not have an controller reference for %T", object, owner)
	}

	if ownerRefs[index].Controller == nil || !*ownerRefs[index].Controller {
		return fmt.Errorf("%T owner is not the controller reference for %T", owner, object)
	}

	ownerRefs = append(ownerRefs[:index], ownerRefs[index+1:]...)
	object.SetOwnerReferences(ownerRefs)
	return nil
}

func upsertOwnerRef(ref metav1.OwnerReference, object metav1.Object) {
	owners := object.GetOwnerReferences()
	if idx := indexOwnerRef(owners, ref); idx == -1 {
		owners = append(owners, ref)
	} else {
		owners[idx] = ref
	}
	object.SetOwnerReferences(owners)
}

// indexOwnerRef returns the index of the owner reference in the slice if found, or -1.
func indexOwnerRef(ownerReferences []metav1.OwnerReference, ref metav1.OwnerReference) int {
	for index, r := range ownerReferences {
		if referSameObject(r, ref) {
			return index
		}
	}
	return -1
}

func validateOwner(owner, object metav1.Object) error {
	ownerNs := owner.GetNamespace()
	if ownerNs != "" {
		objNs := object.GetNamespace()
		if objNs == "" {
			return fmt.Errorf("cluster-scoped resource must not have a namespace-scoped owner, owner's namespace %s", ownerNs)
		}
		if ownerNs != objNs {
			return fmt.Errorf("cross-namespace owner references are disallowed, owner's namespace %s, obj's namespace %s", owner.GetNamespace(), object.GetNamespace())
		}
	}
	return nil
}

// Returns true if a and b point to the same object.
func referSameObject(a, b metav1.OwnerReference) bool {
	aGV, err := schema.ParseGroupVersion(a.APIVersion)
	if err != nil {
		return false
	}

	bGV, err := schema.ParseGroupVersion(b.APIVersion)
	if err != nil {
		return false
	}
	return aGV.Group == bGV.Group && a.Kind == b.Kind && a.Name == b.Name
}

// OperationResult is the action result of a CreateOrUpdate call.
type OperationResult string

const ( // They should complete the sentence "Deployment default/foo has been ..."
	// OperationResultNone means that the resource has not been changed.
	OperationResultNone OperationResult = "unchanged"
	// OperationResultCreated means that a new resource is created.
	OperationResultCreated OperationResult = "created"
	// OperationResultUpdated means that an existing resource is updated.
	OperationResultUpdated OperationResult = "updated"
	// OperationResultUpdatedStatus means that an existing resource and its status is updated.
	OperationResultUpdatedStatus OperationResult = "updatedStatus"
	// OperationResultUpdatedStatusOnly means that only an existing status is updated.
	OperationResultUpdatedStatusOnly OperationResult = "updatedStatusOnly"
)

// CreateOrUpdate creates or updates the given object in the Kubernetes
// cluster. The object's desired state must be reconciled with the existing
// state inside the passed in callback MutateFn.
//
// The MutateFn is called regardless of creating or updating an object.
//
// It returns the executed operation and an error.
//
// Note: changes made by MutateFn to any sub-resource (status...), will be
// discarded.
func CreateOrUpdate(ctx context.Context, c client.Client, obj client.Object, f MutateFn) (OperationResult, error) {
	key := client.ObjectKeyFromObject(obj)
	if err := c.Get(ctx, key, obj); err != nil {
		if !apierrors.IsNotFound(err) {
			return OperationResultNone, err
		}
		if err := mutate(f, key, obj); err != nil {
			return OperationResultNone, err
		}
		if err := c.Create(ctx, obj); err != nil {
			return OperationResultNone, err
		}
		return OperationResultCreated, nil
	}

	existing := obj.DeepCopyObject()
	if err := mutate(f, key, obj); err != nil {
		return OperationResultNone, err
	}

	if equality.Semantic.DeepEqual(existing, obj) {
		return OperationResultNone, nil
	}

	if err := c.Update(ctx, obj); err != nil {
		return OperationResultNone, err
	}
	return OperationResultUpdated, nil
}

// CreateOrPatch creates or patches the given object in the Kubernetes
// cluster. The object's desired state must be reconciled with the before
// state inside the passed in callback MutateFn.
//
// The MutateFn is called regardless of creating or updating an object.
//
// It returns the executed operation and an error.
//
// Note: changes to any sub-resource other than status will be ignored.
// Changes to the status sub-resource will only be applied if the object
// already exist. To change the status on object creation, the easiest
// way is to requeue the object in the controller if OperationResult is
// OperationResultCreated
func CreateOrPatch(ctx context.Context, c client.Client, obj client.Object, f MutateFn) (OperationResult, error) {
	key := client.ObjectKeyFromObject(obj)
	if err := c.Get(ctx, key, obj); err != nil {
		if !apierrors.IsNotFound(err) {
			return OperationResultNone, err
		}
		if f != nil {
			if err := mutate(f, key, obj); err != nil {
				return OperationResultNone, err
			}
		}
		if err := c.Create(ctx, obj); err != nil {
			return OperationResultNone, err
		}
		return OperationResultCreated, nil
	}

	// Create patches for the object and its possible status.
	objPatch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	statusPatch := client.MergeFrom(obj.DeepCopyObject().(client.Object))

	// Create a copy of the original object as well as converting that copy to
	// unstructured data.
	before, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj.DeepCopyObject())
	if err != nil {
		return OperationResultNone, err
	}

	// Attempt to extract the status from the resource for easier comparison later
	beforeStatus, hasBeforeStatus, err := unstructured.NestedFieldCopy(before, "status")
	if err != nil {
		return OperationResultNone, err
	}

	// If the resource contains a status then remove it from the unstructured
	// copy to avoid unnecessary patching later.
	if hasBeforeStatus {
		unstructured.RemoveNestedField(before, "status")
	}

	// Mutate the original object.
	if f != nil {
		if err := mutate(f, key, obj); err != nil {
			return OperationResultNone, err
		}
	}

	// Convert the resource to unstructured to compare against our before copy.
	after, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return OperationResultNone, err
	}

	// Attempt to extract the status from the resource for easier comparison later
	afterStatus, hasAfterStatus, err := unstructured.NestedFieldCopy(after, "status")
	if err != nil {
		return OperationResultNone, err
	}

	// If the resource contains a status then remove it from the unstructured
	// copy to avoid unnecessary patching later.
	if hasAfterStatus {
		unstructured.RemoveNestedField(after, "status")
	}

	result := OperationResultNone

	if !reflect.DeepEqual(before, after) {
		// Only issue a Patch if the before and after resources (minus status) differ
		if err := c.Patch(ctx, obj, objPatch); err != nil {
			return result, err
		}
		result = OperationResultUpdated
	}

	if (hasBeforeStatus || hasAfterStatus) && !reflect.DeepEqual(beforeStatus, afterStatus) {
		// Only issue a Status Patch if the resource has a status and the beforeStatus
		// and afterStatus copies differ
		if result == OperationResultUpdated {
			// If Status was replaced by Patch before, set it to afterStatus
			objectAfterPatch, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
			if err != nil {
				return result, err
			}
			if err = unstructured.SetNestedField(objectAfterPatch, afterStatus, "status"); err != nil {
				return result, err
			}
			// If Status was replaced by Patch before, restore patched structure to the obj
			if err = runtime.DefaultUnstructuredConverter.FromUnstructured(objectAfterPatch, obj); err != nil {
				return result, err
			}
		}
		if err := c.Status().Patch(ctx, obj, statusPatch); err != nil {
			return result, err
		}
		if result == OperationResultUpdated {
			result = OperationResultUpdatedStatus
		} else {
			result = OperationResultUpdatedStatusOnly
		}
	}

	return result, nil
}

// mutate wraps a MutateFn and applies validation to its result.
func mutate(f MutateFn, key client.ObjectKey, obj client.Object) error {
	if err := f(); err != nil {
		return err
	}
	if newKey := client.ObjectKeyFromObject(obj); key != newKey {
		return fmt.Errorf("MutateFn cannot mutate object name and/or object namespace")
	}
	return nil
}

// MutateFn is a function which mutates the existing object into its desired state.
type MutateFn func() error

// AddFinalizer accepts an Object and adds the provided finalizer if not present.
// It returns an indication of whether it updated the object's list of finalizers.
func AddFinalizer(o client.Object, finalizer string) (finalizersUpdated bool) {
	f := o.GetFinalizers()
	for _, e := range f {
		if e == finalizer {
			return false
		}
	}
	o.SetFinalizers(append(f, finalizer))
	return true
}

// RemoveFinalizer accepts an Object and removes the provided finalizer if present.
// It returns an indication of whether it updated the object's list of finalizers.
func RemoveFinalizer(o client.Object, finalizer string) (finalizersUpdated bool) {
	f := o.GetFinalizers()
	length := len(f)

	index := 0
	for i := 0; i < length; i++ {
		if f[i] == finalizer {
			continue
		}
		f[index] = f[i]
		index++
	}
	o.SetFinalizers(f[:index])
	return length != index
}

// ContainsFinalizer checks an Object that the provided finalizer is present.
func ContainsFinalizer(o client.Object, finalizer string) bool {
	f := o.GetFinalizers()
	for _, e := range f {
		if e == finalizer {
			return true
		}
	}
	return false
}
