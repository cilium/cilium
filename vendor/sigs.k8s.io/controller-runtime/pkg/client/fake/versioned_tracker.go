/*
Copyright 2025 The Kubernetes Authors.

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

package fake

import (
	"bytes"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var _ testing.ObjectTracker = (*versionedTracker)(nil)

type versionedTracker struct {
	upstream                      testing.ObjectTracker
	scheme                        *runtime.Scheme
	withStatusSubresource         sets.Set[schema.GroupVersionKind]
	usesFieldManagedObjectTracker bool
}

func (t versionedTracker) Add(obj runtime.Object) error {
	var objects []runtime.Object
	if meta.IsListType(obj) {
		var err error
		objects, err = meta.ExtractList(obj)
		if err != nil {
			return err
		}
	} else {
		objects = []runtime.Object{obj}
	}
	for _, obj := range objects {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return fmt.Errorf("failed to get accessor for object: %w", err)
		}
		if accessor.GetDeletionTimestamp() != nil && len(accessor.GetFinalizers()) == 0 {
			return fmt.Errorf("refusing to create obj %s with metadata.deletionTimestamp but no finalizers", accessor.GetName())
		}
		if accessor.GetResourceVersion() == "" {
			// We use a "magic" value of 999 here because this field
			// is parsed as uint and and 0 is already used in Update.
			// As we can't go lower, go very high instead so this can
			// be recognized
			accessor.SetResourceVersion(trackerAddResourceVersion)
		}

		obj, err = convertFromUnstructuredIfNecessary(t.scheme, obj)
		if err != nil {
			return err
		}

		// If the fieldManager can not decode fields, it will just silently clear them. This is pretty
		// much guaranteed not to be what someone that initializes a fake client with objects that
		// have them set wants, so validate them here.
		// Ref https://github.com/kubernetes/kubernetes/blob/a956ef4862993b825bcd524a19260192ff1da72d/staging/src/k8s.io/apimachinery/pkg/util/managedfields/internal/fieldmanager.go#L105
		if t.usesFieldManagedObjectTracker {
			if err := managedfields.ValidateManagedFields(accessor.GetManagedFields()); err != nil {
				return fmt.Errorf("invalid managedFields on %T: %w", obj, err)
			}
		}
		if err := t.upstream.Add(obj); err != nil {
			return err
		}
	}

	return nil
}

func (t versionedTracker) Create(gvr schema.GroupVersionResource, obj runtime.Object, ns string, opts ...metav1.CreateOptions) error {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("failed to get accessor for object: %w", err)
	}
	if accessor.GetName() == "" {
		gvk, _ := apiutil.GVKForObject(obj, t.scheme)
		return apierrors.NewInvalid(
			gvk.GroupKind(),
			accessor.GetName(),
			field.ErrorList{field.Required(field.NewPath("metadata.name"), "name is required")})
	}
	if accessor.GetResourceVersion() != "" {
		return apierrors.NewBadRequest("resourceVersion can not be set for Create requests")
	}
	accessor.SetResourceVersion("1")
	obj, err = convertFromUnstructuredIfNecessary(t.scheme, obj)
	if err != nil {
		return err
	}
	if err := t.upstream.Create(gvr, obj, ns, opts...); err != nil {
		accessor.SetResourceVersion("")
		return err
	}

	return nil
}

func (t versionedTracker) Update(gvr schema.GroupVersionResource, obj runtime.Object, ns string, opts ...metav1.UpdateOptions) error {
	updateOpts, err := getSingleOrZeroOptions(opts)
	if err != nil {
		return err
	}

	return t.update(gvr, obj, ns, false, false, updateOpts)
}

func (t versionedTracker) update(gvr schema.GroupVersionResource, obj runtime.Object, ns string, isStatus, deleting bool, opts metav1.UpdateOptions) error {
	gvk, err := apiutil.GVKForObject(obj, t.scheme)
	if err != nil {
		return err
	}
	obj, needsCreate, err := t.updateObject(gvr, gvk, obj, ns, isStatus, deleting, allowsCreateOnUpdate(gvk), opts.DryRun)
	if err != nil {
		return err
	}

	if needsCreate {
		opts := metav1.CreateOptions{DryRun: opts.DryRun, FieldManager: opts.FieldManager}
		return t.Create(gvr, obj, ns, opts)
	}

	if obj == nil { // Object was deleted in updateObject
		return nil
	}

	if u, unstructured := obj.(*unstructured.Unstructured); unstructured {
		u.SetGroupVersionKind(gvk)
	}

	return t.upstream.Update(gvr, obj, ns, opts)
}

func (t versionedTracker) Patch(gvr schema.GroupVersionResource, obj runtime.Object, ns string, opts ...metav1.PatchOptions) error {
	patchOptions, err := getSingleOrZeroOptions(opts)
	if err != nil {
		return err
	}

	gvk, err := apiutil.GVKForObject(obj, t.scheme)
	if err != nil {
		return err
	}

	// We apply patches using a client-go reaction that ends up calling the trackers Patch. As we can't change
	// that reaction, we use the callstack to figure out if this originated from the status client.
	isStatus := bytes.Contains(debug.Stack(), []byte("sigs.k8s.io/controller-runtime/pkg/client/fake.(*fakeSubResourceClient).statusPatch"))

	obj, needsCreate, err := t.updateObject(gvr, gvk, obj, ns, isStatus, false, allowsCreateOnUpdate(gvk), patchOptions.DryRun)
	if err != nil {
		return err
	}
	if needsCreate {
		opts := metav1.CreateOptions{DryRun: patchOptions.DryRun, FieldManager: patchOptions.FieldManager}
		return t.Create(gvr, obj, ns, opts)
	}

	if obj == nil { // Object was deleted in updateObject
		return nil
	}

	return t.upstream.Patch(gvr, obj, ns, patchOptions)
}

// updateObject performs a number of validations and changes related to
// object updates, such as checking and updating the resourceVersion.
func (t versionedTracker) updateObject(
	gvr schema.GroupVersionResource,
	gvk schema.GroupVersionKind,
	obj runtime.Object,
	ns string,
	isStatus bool,
	deleting bool,
	allowCreateOnUpdate bool,
	dryRun []string,
) (result runtime.Object, needsCreate bool, _ error) {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get accessor for object: %w", err)
	}

	if accessor.GetName() == "" {
		return nil, false, apierrors.NewInvalid(
			gvk.GroupKind(),
			accessor.GetName(),
			field.ErrorList{field.Required(field.NewPath("metadata.name"), "name is required")})
	}

	oldObject, err := t.Get(gvr, ns, accessor.GetName())
	if err != nil {
		// If the resource is not found and the resource allows create on update, issue a
		// create instead.
		if apierrors.IsNotFound(err) && allowCreateOnUpdate {
			// Pass this info to the caller rather than create, because in the SSA case it
			// must be created by calling Apply in the upstream tracker, not Create.
			// This is because SSA considers Apply and Non-Apply operations to be different
			// even when they use the same fieldManager. This behavior is also observable
			// with a real Kubernetes apiserver.
			//
			// Ref https://kubernetes.slack.com/archives/C0EG7JC6T/p1757868204458989?thread_ts=1757808656.002569&cid=C0EG7JC6T
			return obj, true, nil
		}
		return obj, false, err
	}

	if t.withStatusSubresource.Has(gvk) {
		if isStatus { // copy everything but status, managedFields and metadata.ResourceVersion from original object
			if err := copyStatusFrom(obj, oldObject); err != nil {
				return nil, false, fmt.Errorf("failed to copy non-status field for object with status subresouce: %w", err)
			}
			passedRV := accessor.GetResourceVersion()
			passedManagedFields := accessor.GetManagedFields()
			if err := copyFrom(oldObject, obj); err != nil {
				return nil, false, fmt.Errorf("failed to restore non-status fields: %w", err)
			}
			accessor.SetResourceVersion(passedRV)
			accessor.SetManagedFields(passedManagedFields)
		} else { // copy status from original object
			if err := copyStatusFrom(oldObject, obj); err != nil {
				return nil, false, fmt.Errorf("failed to copy the status for object with status subresource: %w", err)
			}
		}
	} else if isStatus {
		return nil, false, apierrors.NewNotFound(gvr.GroupResource(), accessor.GetName())
	}

	oldAccessor, err := meta.Accessor(oldObject)
	if err != nil {
		return nil, false, err
	}

	// If the new object does not have the resource version set and it allows unconditional update,
	// default it to the resource version of the existing resource
	if accessor.GetResourceVersion() == "" {
		switch {
		case allowsUnconditionalUpdate(gvk):
			accessor.SetResourceVersion(oldAccessor.GetResourceVersion())
			// This is needed because if the patch explicitly sets the RV to null, the client-go reaction we use
			// to apply it and whose output we process here will have it unset. It is not clear why the Kubernetes
			// apiserver accepts such a patch, but it does so we just copy that behavior.
			// Kubernetes apiserver behavior can be checked like this:
			// `kubectl patch configmap foo --patch '{"metadata":{"annotations":{"foo":"bar"},"resourceVersion":null}}' -v=9`
		case bytes.Contains(debug.Stack(), []byte("sigs.k8s.io/controller-runtime/pkg/client/fake.(*fakeClient).Patch")):
			// We apply patches using a client-go reaction that ends up calling the trackers Update. As we can't change
			// that reaction, we use the callstack to figure out if this originated from the "fakeClient.Patch" func.
			accessor.SetResourceVersion(oldAccessor.GetResourceVersion())
		case bytes.Contains(debug.Stack(), []byte("sigs.k8s.io/controller-runtime/pkg/client/fake.(*fakeClient).Apply")):
			// We apply patches using a client-go reaction that ends up calling the trackers Update. As we can't change
			// that reaction, we use the callstack to figure out if this originated from the "fakeClient.Apply" func.
			accessor.SetResourceVersion(oldAccessor.GetResourceVersion())
		}
	}

	if accessor.GetResourceVersion() != oldAccessor.GetResourceVersion() {
		return nil, false, apierrors.NewConflict(gvr.GroupResource(), accessor.GetName(), errors.New("object was modified"))
	}
	if oldAccessor.GetResourceVersion() == "" {
		oldAccessor.SetResourceVersion("0")
	}
	intResourceVersion, err := strconv.ParseUint(oldAccessor.GetResourceVersion(), 10, 64)
	if err != nil {
		return nil, false, fmt.Errorf("can not convert resourceVersion %q to int: %w", oldAccessor.GetResourceVersion(), err)
	}
	intResourceVersion++
	accessor.SetResourceVersion(strconv.FormatUint(intResourceVersion, 10))

	if !deleting && !deletionTimestampEqual(accessor, oldAccessor) {
		return nil, false, fmt.Errorf("error: Unable to edit %s: metadata.deletionTimestamp field is immutable", accessor.GetName())
	}

	if !accessor.GetDeletionTimestamp().IsZero() && len(accessor.GetFinalizers()) == 0 {
		return nil, false, t.Delete(gvr, accessor.GetNamespace(), accessor.GetName(), metav1.DeleteOptions{DryRun: dryRun})
	}

	obj, err = convertFromUnstructuredIfNecessary(t.scheme, obj)
	return obj, false, err
}

func (t versionedTracker) Apply(gvr schema.GroupVersionResource, applyConfiguration runtime.Object, ns string, opts ...metav1.PatchOptions) error {
	patchOptions, err := getSingleOrZeroOptions(opts)
	if err != nil {
		return err
	}
	gvk, err := apiutil.GVKForObject(applyConfiguration, t.scheme)
	if err != nil {
		return err
	}
	isStatus := bytes.Contains(debug.Stack(), []byte("sigs.k8s.io/controller-runtime/pkg/client/fake.(*fakeSubResourceClient).statusPatch"))

	applyConfiguration, needsCreate, err := t.updateObject(gvr, gvk, applyConfiguration, ns, isStatus, false, true, patchOptions.DryRun)
	if err != nil {
		return err
	}

	if needsCreate {
		//		https://github.com/kubernetes/kubernetes/blob/81affffa1b8d8079836f4cac713ea8d1b2bbf10f/staging/src/k8s.io/apiserver/pkg/endpoints/handlers/patch.go#L606
		accessor, err := meta.Accessor(applyConfiguration)
		if err != nil {
			return fmt.Errorf("failed to get accessor for object: %w", err)
		}
		if accessor.GetUID() != "" {
			return apierrors.NewConflict(gvr.GroupResource(), accessor.GetName(), fmt.Errorf("uid mismatch: the provided object specified uid %s, and no existing object was found", accessor.GetUID()))
		}

		if t.withStatusSubresource.Has(gvk) {
			// Clear out status for create, for update this is handled in updateObject
			if err := copyStatusFrom(&unstructured.Unstructured{}, applyConfiguration); err != nil {
				return err
			}
		}
	}

	if applyConfiguration == nil { // Object was deleted in updateObject
		return nil
	}

	if isStatus {
		// We restore everything but status from the tracker where we don't put GVK
		// into the object but it must be set for the ManagedFieldsObjectTracker
		applyConfiguration.GetObjectKind().SetGroupVersionKind(gvk)
	}
	return t.upstream.Apply(gvr, applyConfiguration, ns, opts...)
}

func (t versionedTracker) Delete(gvr schema.GroupVersionResource, ns, name string, opts ...metav1.DeleteOptions) error {
	return t.upstream.Delete(gvr, ns, name, opts...)
}

func (t versionedTracker) Get(gvr schema.GroupVersionResource, ns, name string, opts ...metav1.GetOptions) (runtime.Object, error) {
	return t.upstream.Get(gvr, ns, name, opts...)
}

func (t versionedTracker) List(gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, ns string, opts ...metav1.ListOptions) (runtime.Object, error) {
	return t.upstream.List(gvr, gvk, ns, opts...)
}

func (t versionedTracker) Watch(gvr schema.GroupVersionResource, ns string, opts ...metav1.ListOptions) (watch.Interface, error) {
	return t.upstream.Watch(gvr, ns, opts...)
}
