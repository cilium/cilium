/*
Copyright 2014 The Kubernetes Authors.

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

package resttest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/validation/path"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
)

type Tester struct {
	*testing.T
	storage             rest.Storage
	clusterScope        bool
	createOnUpdate      bool
	generatesName       bool
	returnDeletedObject bool
	namer               func(int) string
	scheme              *runtime.Scheme
}

func New(t *testing.T, storage rest.Storage, scheme *runtime.Scheme) *Tester {
	return &Tester{
		T:       t,
		storage: storage,
		namer:   defaultNamer,
		scheme:  scheme,
	}
}

func defaultNamer(i int) string {
	return fmt.Sprintf("foo%d", i)
}

// Namer allows providing a custom name maker
// By default "foo%d" is used
func (t *Tester) Namer(namer func(int) string) *Tester {
	t.namer = namer
	return t
}

func (t *Tester) ClusterScope() *Tester {
	t.clusterScope = true
	return t
}

func (t *Tester) AllowCreateOnUpdate() *Tester {
	t.createOnUpdate = true
	return t
}

func (t *Tester) GeneratesName() *Tester {
	t.generatesName = true
	return t
}

func (t *Tester) ReturnDeletedObject() *Tester {
	t.returnDeletedObject = true
	return t
}

// TestNamespace returns the namespace that will be used when creating contexts.
// Returns NamespaceNone for cluster-scoped objects.
func (t *Tester) TestNamespace() string {
	if t.clusterScope {
		return metav1.NamespaceNone
	}
	return "test"
}

// TestContext returns a namespaced context that will be used when making storage calls.
// Namespace is determined by TestNamespace()
func (t *Tester) TestContext() genericapirequest.Context {
	if t.clusterScope {
		return genericapirequest.NewContext()
	}
	return genericapirequest.WithNamespace(genericapirequest.NewContext(), t.TestNamespace())
}

func (t *Tester) getObjectMetaOrFail(obj runtime.Object) metav1.Object {
	objMeta, err := meta.Accessor(obj)
	if err != nil {
		t.Fatalf("object does not have ObjectMeta: %v\n%#v", err, obj)
	}
	return objMeta
}

func (t *Tester) setObjectMeta(obj runtime.Object, name string) {
	meta := t.getObjectMetaOrFail(obj)
	meta.SetName(name)
	if t.clusterScope {
		meta.SetNamespace(metav1.NamespaceNone)
	} else {
		meta.SetNamespace(genericapirequest.NamespaceValue(t.TestContext()))
	}
	meta.SetGenerateName("")
	meta.SetGeneration(1)
}

type AssignFunc func([]runtime.Object) []runtime.Object
type EmitFunc func(runtime.Object, string) error
type GetFunc func(genericapirequest.Context, runtime.Object) (runtime.Object, error)
type InitWatchFunc func()
type InjectErrFunc func(err error)
type IsErrorFunc func(err error) bool
type CreateFunc func(genericapirequest.Context, runtime.Object) error
type SetRVFunc func(uint64)
type UpdateFunc func(runtime.Object) runtime.Object

// Test creating an object.
func (t *Tester) TestCreate(valid runtime.Object, createFn CreateFunc, getFn GetFunc, invalid ...runtime.Object) {
	t.testCreateHasMetadata(valid.DeepCopyObject())
	if !t.generatesName {
		t.testCreateGeneratesName(valid.DeepCopyObject())
	}
	t.testCreateEquals(valid.DeepCopyObject(), getFn)
	t.testCreateAlreadyExisting(valid.DeepCopyObject(), createFn)
	if t.clusterScope {
		t.testCreateDiscardsObjectNamespace(valid.DeepCopyObject())
		t.testCreateIgnoresContextNamespace(valid.DeepCopyObject())
		t.testCreateIgnoresMismatchedNamespace(valid.DeepCopyObject())
		t.testCreateResetsUserData(valid.DeepCopyObject())
	} else {
		t.testCreateRejectsMismatchedNamespace(valid.DeepCopyObject())
	}
	t.testCreateInvokesValidation(invalid...)
	t.testCreateValidatesNames(valid.DeepCopyObject())
	t.testCreateIgnoreClusterName(valid.DeepCopyObject())
}

// Test updating an object.
func (t *Tester) TestUpdate(valid runtime.Object, createFn CreateFunc, getFn GetFunc, updateFn UpdateFunc, invalidUpdateFn ...UpdateFunc) {
	t.testUpdateEquals(valid.DeepCopyObject(), createFn, getFn, updateFn)
	t.testUpdateFailsOnVersionTooOld(valid.DeepCopyObject(), createFn, getFn)
	t.testUpdateOnNotFound(valid.DeepCopyObject())
	if !t.clusterScope {
		t.testUpdateRejectsMismatchedNamespace(valid.DeepCopyObject(), createFn, getFn)
	}
	t.testUpdateInvokesValidation(valid.DeepCopyObject(), createFn, invalidUpdateFn...)
	t.testUpdateWithWrongUID(valid.DeepCopyObject(), createFn, getFn)
	t.testUpdateRetrievesOldObject(valid.DeepCopyObject(), createFn, getFn)
	t.testUpdatePropagatesUpdatedObjectError(valid.DeepCopyObject(), createFn, getFn)
	t.testUpdateIgnoreGenerationUpdates(valid.DeepCopyObject(), createFn, getFn)
	t.testUpdateIgnoreClusterName(valid.DeepCopyObject(), createFn, getFn)
}

// Test deleting an object.
func (t *Tester) TestDelete(valid runtime.Object, createFn CreateFunc, getFn GetFunc, isNotFoundFn IsErrorFunc) {
	t.testDeleteNonExist(valid.DeepCopyObject())
	t.testDeleteNoGraceful(valid.DeepCopyObject(), createFn, getFn, isNotFoundFn)
	t.testDeleteWithUID(valid.DeepCopyObject(), createFn, getFn, isNotFoundFn)
}

// Test gracefully deleting an object.
func (t *Tester) TestDeleteGraceful(valid runtime.Object, createFn CreateFunc, getFn GetFunc, expectedGrace int64) {
	t.testDeleteGracefulHasDefault(valid.DeepCopyObject(), createFn, getFn, expectedGrace)
	t.testDeleteGracefulWithValue(valid.DeepCopyObject(), createFn, getFn, expectedGrace)
	t.testDeleteGracefulUsesZeroOnNil(valid.DeepCopyObject(), createFn, expectedGrace)
	t.testDeleteGracefulExtend(valid.DeepCopyObject(), createFn, getFn, expectedGrace)
	t.testDeleteGracefulShorten(valid.DeepCopyObject(), createFn, getFn, expectedGrace)
	t.testDeleteGracefulImmediate(valid.DeepCopyObject(), createFn, getFn, expectedGrace)
}

// Test getting object.
func (t *Tester) TestGet(valid runtime.Object) {
	t.testGetFound(valid.DeepCopyObject())
	t.testGetNotFound(valid.DeepCopyObject())
	t.testGetMimatchedNamespace(valid.DeepCopyObject())
	if !t.clusterScope {
		t.testGetDifferentNamespace(valid.DeepCopyObject())
	}
}

// Test listing objects.
func (t *Tester) TestList(valid runtime.Object, assignFn AssignFunc) {
	t.testListNotFound(assignFn)
	t.testListFound(valid.DeepCopyObject(), assignFn)
	t.testListMatchLabels(valid.DeepCopyObject(), assignFn)
	t.testListTableConversion(valid.DeepCopyObject(), assignFn)
}

// Test watching objects.
func (t *Tester) TestWatch(
	valid runtime.Object, emitFn EmitFunc,
	labelsPass, labelsFail []labels.Set, fieldsPass, fieldsFail []fields.Set, actions []string) {
	t.testWatchLabels(valid.DeepCopyObject(), emitFn, labelsPass, labelsFail, actions)
	t.testWatchFields(valid.DeepCopyObject(), emitFn, fieldsPass, fieldsFail, actions)
}

// =============================================================================
// Creation tests.

func (t *Tester) delete(ctx genericapirequest.Context, obj runtime.Object) error {
	objectMeta, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	deleter, ok := t.storage.(rest.GracefulDeleter)
	if !ok {
		return fmt.Errorf("Expected deleting storage, got %v", t.storage)
	}
	_, _, err = deleter.Delete(ctx, objectMeta.GetName(), nil)
	return err
}

func (t *Tester) testCreateAlreadyExisting(obj runtime.Object, createFn CreateFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(1))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer t.delete(ctx, foo)

	_, err := t.storage.(rest.Creater).Create(ctx, foo, false)
	if !errors.IsAlreadyExists(err) {
		t.Errorf("expected already exists err, got %v", err)
	}
}

func (t *Tester) testCreateEquals(obj runtime.Object, getFn GetFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(2))

	created, err := t.storage.(rest.Creater).Create(ctx, foo, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer t.delete(ctx, created)

	got, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Set resource version which might be unset in created object.
	createdMeta := t.getObjectMetaOrFail(created)
	gotMeta := t.getObjectMetaOrFail(got)
	createdMeta.SetResourceVersion(gotMeta.GetResourceVersion())

	if e, a := created, got; !apiequality.Semantic.DeepEqual(e, a) {
		t.Errorf("unexpected obj: %#v, expected %#v", e, a)
	}
}

func (t *Tester) testCreateDiscardsObjectNamespace(valid runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(valid)

	// Ignore non-empty namespace in object meta
	objectMeta.SetNamespace("not-default")

	// Ideally, we'd get an error back here, but at least verify the namespace wasn't persisted
	created, err := t.storage.(rest.Creater).Create(t.TestContext(), valid.DeepCopyObject(), false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer t.delete(t.TestContext(), created)
	createdObjectMeta := t.getObjectMetaOrFail(created)
	if createdObjectMeta.GetNamespace() != metav1.NamespaceNone {
		t.Errorf("Expected empty namespace on created object, got '%v'", createdObjectMeta.GetNamespace())
	}
}

func (t *Tester) testCreateGeneratesName(valid runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(valid)
	objectMeta.SetName("")
	objectMeta.SetGenerateName("test-")

	created, err := t.storage.(rest.Creater).Create(t.TestContext(), valid, false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer t.delete(t.TestContext(), created)
	if objectMeta.GetName() == "test-" || !strings.HasPrefix(objectMeta.GetName(), "test-") {
		t.Errorf("unexpected name: %#v", valid)
	}
}

func (t *Tester) testCreateHasMetadata(valid runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(valid)
	objectMeta.SetName(t.namer(1))
	objectMeta.SetNamespace(t.TestNamespace())

	obj, err := t.storage.(rest.Creater).Create(t.TestContext(), valid, false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if obj == nil {
		t.Fatalf("Unexpected object from result: %#v", obj)
	}
	defer t.delete(t.TestContext(), obj)
	if !metav1.HasObjectMetaSystemFieldValues(objectMeta) {
		t.Errorf("storage did not populate object meta field values")
	}
}

func (t *Tester) testCreateIgnoresContextNamespace(valid runtime.Object) {
	// Ignore non-empty namespace in context
	ctx := genericapirequest.WithNamespace(genericapirequest.NewContext(), "not-default2")

	// Ideally, we'd get an error back here, but at least verify the namespace wasn't persisted
	created, err := t.storage.(rest.Creater).Create(ctx, valid.DeepCopyObject(), false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer t.delete(ctx, created)
	createdObjectMeta := t.getObjectMetaOrFail(created)
	if createdObjectMeta.GetNamespace() != metav1.NamespaceNone {
		t.Errorf("Expected empty namespace on created object, got '%v'", createdObjectMeta.GetNamespace())
	}
}

func (t *Tester) testCreateIgnoresMismatchedNamespace(valid runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(valid)

	// Ignore non-empty namespace in object meta
	objectMeta.SetNamespace("not-default")
	ctx := genericapirequest.WithNamespace(genericapirequest.NewContext(), "not-default2")

	// Ideally, we'd get an error back here, but at least verify the namespace wasn't persisted
	created, err := t.storage.(rest.Creater).Create(ctx, valid.DeepCopyObject(), false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer t.delete(ctx, created)
	createdObjectMeta := t.getObjectMetaOrFail(created)
	if createdObjectMeta.GetNamespace() != metav1.NamespaceNone {
		t.Errorf("Expected empty namespace on created object, got '%v'", createdObjectMeta.GetNamespace())
	}
}

func (t *Tester) testCreateValidatesNames(valid runtime.Object) {
	for _, invalidName := range path.NameMayNotBe {
		objCopy := valid.DeepCopyObject()
		objCopyMeta := t.getObjectMetaOrFail(objCopy)
		objCopyMeta.SetName(invalidName)

		ctx := t.TestContext()
		_, err := t.storage.(rest.Creater).Create(ctx, objCopy, false)
		if !errors.IsInvalid(err) {
			t.Errorf("%s: Expected to get an invalid resource error, got '%v'", invalidName, err)
		}
	}

	for _, invalidSuffix := range path.NameMayNotContain {
		objCopy := valid.DeepCopyObject()
		objCopyMeta := t.getObjectMetaOrFail(objCopy)
		objCopyMeta.SetName(objCopyMeta.GetName() + invalidSuffix)

		ctx := t.TestContext()
		_, err := t.storage.(rest.Creater).Create(ctx, objCopy, false)
		if !errors.IsInvalid(err) {
			t.Errorf("%s: Expected to get an invalid resource error, got '%v'", invalidSuffix, err)
		}
	}
}

func (t *Tester) testCreateInvokesValidation(invalid ...runtime.Object) {
	for i, obj := range invalid {
		ctx := t.TestContext()
		_, err := t.storage.(rest.Creater).Create(ctx, obj, false)
		if !errors.IsInvalid(err) {
			t.Errorf("%d: Expected to get an invalid resource error, got %v", i, err)
		}
	}
}

func (t *Tester) testCreateRejectsMismatchedNamespace(valid runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(valid)
	objectMeta.SetNamespace("not-default")

	_, err := t.storage.(rest.Creater).Create(t.TestContext(), valid, false)
	if err == nil {
		t.Errorf("Expected an error, but we didn't get one")
	} else if !strings.Contains(err.Error(), "does not match the namespace sent on the request") {
		t.Errorf("Expected 'does not match the namespace sent on the request' error, got '%v'", err.Error())
	}
}

func (t *Tester) testCreateResetsUserData(valid runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(valid)
	now := metav1.Now()
	objectMeta.SetUID("bad-uid")
	objectMeta.SetCreationTimestamp(now)

	obj, err := t.storage.(rest.Creater).Create(t.TestContext(), valid, false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if obj == nil {
		t.Fatalf("Unexpected object from result: %#v", obj)
	}
	defer t.delete(t.TestContext(), obj)
	if objectMeta.GetUID() == "bad-uid" || objectMeta.GetCreationTimestamp() == now {
		t.Errorf("ObjectMeta did not reset basic fields: %#v", objectMeta)
	}
}

func (t *Tester) testCreateIgnoreClusterName(valid runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(valid)
	objectMeta.SetName(t.namer(3))
	objectMeta.SetClusterName("clustername-to-ignore")

	obj, err := t.storage.(rest.Creater).Create(t.TestContext(), valid.DeepCopyObject(), false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer t.delete(t.TestContext(), obj)
	createdObjectMeta := t.getObjectMetaOrFail(obj)
	if len(createdObjectMeta.GetClusterName()) != 0 {
		t.Errorf("Expected empty clusterName on created object, got '%v'", createdObjectMeta.GetClusterName())
	}
}

// =============================================================================
// Update tests.

func (t *Tester) testUpdateEquals(obj runtime.Object, createFn CreateFunc, getFn GetFunc, updateFn UpdateFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(2))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	toUpdate, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	toUpdate = updateFn(toUpdate)
	toUpdateMeta := t.getObjectMetaOrFail(toUpdate)
	updated, created, err := t.storage.(rest.Updater).Update(ctx, toUpdateMeta.GetName(), rest.DefaultUpdatedObjectInfo(toUpdate, t.scheme))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if created {
		t.Errorf("unexpected creation")
	}
	got, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Set resource version which might be unset in created object.
	updatedMeta := t.getObjectMetaOrFail(updated)
	gotMeta := t.getObjectMetaOrFail(got)
	updatedMeta.SetResourceVersion(gotMeta.GetResourceVersion())

	if e, a := updated, got; !apiequality.Semantic.DeepEqual(e, a) {
		t.Errorf("unexpected obj: %#v, expected %#v", e, a)
	}
}

func (t *Tester) testUpdateFailsOnVersionTooOld(obj runtime.Object, createFn CreateFunc, getFn GetFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(3))

	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	storedFoo, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	older := storedFoo.DeepCopyObject()
	olderMeta := t.getObjectMetaOrFail(older)
	olderMeta.SetResourceVersion("1")

	_, _, err = t.storage.(rest.Updater).Update(t.TestContext(), olderMeta.GetName(), rest.DefaultUpdatedObjectInfo(older, t.scheme))
	if err == nil {
		t.Errorf("Expected an error, but we didn't get one")
	} else if !errors.IsConflict(err) {
		t.Errorf("Expected Conflict error, got '%v'", err)
	}
}

func (t *Tester) testUpdateInvokesValidation(obj runtime.Object, createFn CreateFunc, invalidUpdateFn ...UpdateFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(4))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	for _, update := range invalidUpdateFn {
		toUpdate := update(foo.DeepCopyObject())
		toUpdateMeta := t.getObjectMetaOrFail(toUpdate)
		got, created, err := t.storage.(rest.Updater).Update(t.TestContext(), toUpdateMeta.GetName(), rest.DefaultUpdatedObjectInfo(toUpdate, t.scheme))
		if got != nil || created {
			t.Errorf("expected nil object and no creation for object: %v", toUpdate)
		}
		if !errors.IsInvalid(err) && !errors.IsBadRequest(err) {
			t.Errorf("expected invalid or bad request error, got %v", err)
		}
	}
}

func (t *Tester) testUpdateWithWrongUID(obj runtime.Object, createFn CreateFunc, getFn GetFunc) {
	ctx := t.TestContext()
	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(5))
	objectMeta := t.getObjectMetaOrFail(foo)
	objectMeta.SetUID(types.UID("UID0000"))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	objectMeta.SetUID(types.UID("UID1111"))

	obj, created, err := t.storage.(rest.Updater).Update(ctx, objectMeta.GetName(), rest.DefaultUpdatedObjectInfo(foo, t.scheme))
	if created || obj != nil {
		t.Errorf("expected nil object and no creation for object: %v", foo)
	}
	if err == nil || !errors.IsConflict(err) {
		t.Errorf("unexpected error: %v", err)
	}
}

func (t *Tester) testUpdateRetrievesOldObject(obj runtime.Object, createFn CreateFunc, getFn GetFunc) {
	ctx := t.TestContext()
	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(6))
	objectMeta := t.getObjectMetaOrFail(foo)
	objectMeta.SetAnnotations(map[string]string{"A": "1"})
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	storedFoo, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	storedFooWithUpdates := storedFoo.DeepCopyObject()
	objectMeta = t.getObjectMetaOrFail(storedFooWithUpdates)
	objectMeta.SetAnnotations(map[string]string{"A": "2"})

	// Make sure a custom transform is called, and sees the expected updatedObject and oldObject
	// This tests the mechanism used to pass the old and new object to admission
	calledUpdatedObject := 0
	noopTransform := func(_ genericapirequest.Context, updatedObject runtime.Object, oldObject runtime.Object) (runtime.Object, error) {
		if !reflect.DeepEqual(storedFoo, oldObject) {
			t.Errorf("Expected\n\t%#v\ngot\n\t%#v", storedFoo, oldObject)
		}
		if !reflect.DeepEqual(storedFooWithUpdates, updatedObject) {
			t.Errorf("Expected\n\t%#v\ngot\n\t%#v", storedFooWithUpdates, updatedObject)
		}
		calledUpdatedObject++
		return updatedObject, nil
	}

	updatedObj, created, err := t.storage.(rest.Updater).Update(ctx, objectMeta.GetName(), rest.DefaultUpdatedObjectInfo(storedFooWithUpdates, t.scheme, noopTransform))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	if created {
		t.Errorf("expected no creation for object")
		return
	}
	if updatedObj == nil {
		t.Errorf("expected non-nil object from update")
		return
	}
	if calledUpdatedObject != 1 {
		t.Errorf("expected UpdatedObject() to be called 1 time, was called %d", calledUpdatedObject)
		return
	}
}

func (t *Tester) testUpdatePropagatesUpdatedObjectError(obj runtime.Object, createFn CreateFunc, getFn GetFunc) {
	ctx := t.TestContext()
	foo := obj.DeepCopyObject()
	name := t.namer(7)
	t.setObjectMeta(foo, name)
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Make sure our transform is called, and sees the expected updatedObject and oldObject
	propagateErr := fmt.Errorf("custom updated object error for %v", foo)
	noopTransform := func(_ genericapirequest.Context, updatedObject runtime.Object, oldObject runtime.Object) (runtime.Object, error) {
		return nil, propagateErr
	}

	_, _, err := t.storage.(rest.Updater).Update(ctx, name, rest.DefaultUpdatedObjectInfo(foo, t.scheme, noopTransform))
	if err != propagateErr {
		t.Errorf("expected propagated error, got %#v", err)
	}
}

func (t *Tester) testUpdateIgnoreGenerationUpdates(obj runtime.Object, createFn CreateFunc, getFn GetFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	name := t.namer(8)
	t.setObjectMeta(foo, name)

	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	storedFoo, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	older := storedFoo.DeepCopyObject()
	olderMeta := t.getObjectMetaOrFail(older)
	olderMeta.SetGeneration(2)

	_, _, err = t.storage.(rest.Updater).Update(t.TestContext(), olderMeta.GetName(), rest.DefaultUpdatedObjectInfo(older, t.scheme))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	updatedFoo, err := getFn(ctx, older)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if exp, got := int64(1), t.getObjectMetaOrFail(updatedFoo).GetGeneration(); exp != got {
		t.Errorf("Unexpected generation update: expected %d, got %d", exp, got)
	}
}

func (t *Tester) testUpdateOnNotFound(obj runtime.Object) {
	t.setObjectMeta(obj, t.namer(0))
	_, created, err := t.storage.(rest.Updater).Update(t.TestContext(), t.namer(0), rest.DefaultUpdatedObjectInfo(obj, t.scheme))
	if t.createOnUpdate {
		if err != nil {
			t.Errorf("creation allowed on updated, but got an error: %v", err)
		}
		if !created {
			t.Errorf("creation allowed on update, but object not created")
		}
	} else {
		if err == nil {
			t.Errorf("Expected an error, but we didn't get one")
		} else if !errors.IsNotFound(err) {
			t.Errorf("Expected NotFound error, got '%v'", err)
		}
	}
}

func (t *Tester) testUpdateRejectsMismatchedNamespace(obj runtime.Object, createFn CreateFunc, getFn GetFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(1))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	storedFoo, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	objectMeta := t.getObjectMetaOrFail(storedFoo)
	objectMeta.SetName(t.namer(1))
	objectMeta.SetNamespace("not-default")

	obj, updated, err := t.storage.(rest.Updater).Update(t.TestContext(), "foo1", rest.DefaultUpdatedObjectInfo(storedFoo, t.scheme))
	if obj != nil || updated {
		t.Errorf("expected nil object and not updated")
	}
	if err == nil {
		t.Errorf("expected an error, but didn't get one")
	} else if !strings.Contains(err.Error(), "does not match the namespace sent on the request") {
		t.Errorf("expected 'does not match the namespace sent on the request' error, got '%v'", err.Error())
	}
}

func (t *Tester) testUpdateIgnoreClusterName(obj runtime.Object, createFn CreateFunc, getFn GetFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	name := t.namer(9)
	t.setObjectMeta(foo, name)

	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	storedFoo, err := getFn(ctx, foo)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	older := storedFoo.DeepCopyObject()
	olderMeta := t.getObjectMetaOrFail(older)
	olderMeta.SetClusterName("clustername-to-ignore")

	_, _, err = t.storage.(rest.Updater).Update(t.TestContext(), olderMeta.GetName(), rest.DefaultUpdatedObjectInfo(older, t.scheme))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	updatedFoo, err := getFn(ctx, older)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if clusterName := t.getObjectMetaOrFail(updatedFoo).GetClusterName(); len(clusterName) != 0 {
		t.Errorf("Unexpected clusterName update: expected empty, got %v", clusterName)
	}

}

// =============================================================================
// Deletion tests.

func (t *Tester) testDeleteNoGraceful(obj runtime.Object, createFn CreateFunc, getFn GetFunc, isNotFoundFn IsErrorFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(1))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	objectMeta := t.getObjectMetaOrFail(foo)
	obj, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(10))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !wasDeleted {
		t.Errorf("unexpected, object %s should have been deleted immediately", objectMeta.GetName())
	}
	if !t.returnDeletedObject {
		if status, ok := obj.(*metav1.Status); !ok {
			t.Errorf("expected status of delete, got %v", status)
		} else if status.Status != metav1.StatusSuccess {
			t.Errorf("expected success, got: %v", status.Status)
		}
	}

	_, err = getFn(ctx, foo)
	if err == nil || !isNotFoundFn(err) {
		t.Errorf("unexpected error: %v", err)
	}
}

func (t *Tester) testDeleteNonExist(obj runtime.Object) {
	objectMeta := t.getObjectMetaOrFail(obj)

	_, _, err := t.storage.(rest.GracefulDeleter).Delete(t.TestContext(), objectMeta.GetName(), nil)
	if err == nil || !errors.IsNotFound(err) {
		t.Errorf("unexpected error: %v", err)
	}

}

//  This test the fast-fail path. We test that the precondition gets verified
//  again before deleting the object in tests of pkg/storage/etcd.
func (t *Tester) testDeleteWithUID(obj runtime.Object, createFn CreateFunc, getFn GetFunc, isNotFoundFn IsErrorFunc) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(1))
	objectMeta := t.getObjectMetaOrFail(foo)
	objectMeta.SetUID(types.UID("UID0000"))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	obj, _, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewPreconditionDeleteOptions("UID1111"))
	if err == nil || !errors.IsConflict(err) {
		t.Errorf("unexpected error: %v", err)
	}

	obj, _, err = t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewPreconditionDeleteOptions("UID0000"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !t.returnDeletedObject {
		if status, ok := obj.(*metav1.Status); !ok {
			t.Errorf("expected status of delete, got %v", status)
		} else if status.Status != metav1.StatusSuccess {
			t.Errorf("expected success, got: %v", status.Status)
		}
	}

	_, err = getFn(ctx, foo)
	if err == nil || !isNotFoundFn(err) {
		t.Errorf("unexpected error: %v", err)
	}
}

// =============================================================================
// Graceful Deletion tests.

func (t *Tester) testDeleteGracefulHasDefault(obj runtime.Object, createFn CreateFunc, getFn GetFunc, expectedGrace int64) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(1))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	objectMeta := t.getObjectMetaOrFail(foo)
	generation := objectMeta.GetGeneration()
	_, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), &metav1.DeleteOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted {
		t.Errorf("unexpected, object %s should not have been deleted immediately", objectMeta.GetName())
	}
	if _, err := getFn(ctx, foo); err != nil {
		t.Fatalf("did not gracefully delete resource: %v", err)
	}

	object, err := t.storage.(rest.Getter).Get(ctx, objectMeta.GetName(), &metav1.GetOptions{})
	if err != nil {
		t.Fatalf("unexpected error, object should exist: %v", err)
	}
	objectMeta = t.getObjectMetaOrFail(object)
	if objectMeta.GetDeletionTimestamp() == nil || objectMeta.GetDeletionGracePeriodSeconds() == nil || *objectMeta.GetDeletionGracePeriodSeconds() != expectedGrace {
		t.Errorf("unexpected deleted meta: %#v", objectMeta)
	}
	if generation >= objectMeta.GetGeneration() {
		t.Error("Generation wasn't bumped when deletion timestamp was set")
	}
}

func (t *Tester) testDeleteGracefulWithValue(obj runtime.Object, createFn CreateFunc, getFn GetFunc, expectedGrace int64) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(2))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	objectMeta := t.getObjectMetaOrFail(foo)
	generation := objectMeta.GetGeneration()
	_, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(expectedGrace+2))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted {
		t.Errorf("unexpected, object %s should not have been deleted immediately", objectMeta.GetName())
	}
	if _, err := getFn(ctx, foo); err != nil {
		t.Fatalf("did not gracefully delete resource: %v", err)
	}

	object, err := t.storage.(rest.Getter).Get(ctx, objectMeta.GetName(), &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error, object should exist: %v", err)
	}
	objectMeta = t.getObjectMetaOrFail(object)
	if objectMeta.GetDeletionTimestamp() == nil || objectMeta.GetDeletionGracePeriodSeconds() == nil || *objectMeta.GetDeletionGracePeriodSeconds() != expectedGrace+2 {
		t.Errorf("unexpected deleted meta: %#v", objectMeta)
	}
	if generation >= objectMeta.GetGeneration() {
		t.Error("Generation wasn't bumped when deletion timestamp was set")
	}
}

func (t *Tester) testDeleteGracefulExtend(obj runtime.Object, createFn CreateFunc, getFn GetFunc, expectedGrace int64) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(3))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	objectMeta := t.getObjectMetaOrFail(foo)
	generation := objectMeta.GetGeneration()
	_, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(expectedGrace))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted {
		t.Errorf("unexpected, object %s should not have been deleted immediately", objectMeta.GetName())
	}
	if _, err := getFn(ctx, foo); err != nil {
		t.Fatalf("did not gracefully delete resource: %v", err)
	}

	// second delete duration is ignored
	_, wasDeleted, err = t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(expectedGrace+2))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted {
		t.Errorf("unexpected, object %s should not have been deleted immediately", objectMeta.GetName())
	}
	object, err := t.storage.(rest.Getter).Get(ctx, objectMeta.GetName(), &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error, object should exist: %v", err)
	}
	objectMeta = t.getObjectMetaOrFail(object)
	if objectMeta.GetDeletionTimestamp() == nil || objectMeta.GetDeletionGracePeriodSeconds() == nil || *objectMeta.GetDeletionGracePeriodSeconds() != expectedGrace {
		t.Errorf("unexpected deleted meta: %#v", objectMeta)
	}
	if generation >= objectMeta.GetGeneration() {
		t.Error("Generation wasn't bumped when deletion timestamp was set")
	}
}

func (t *Tester) testDeleteGracefulImmediate(obj runtime.Object, createFn CreateFunc, getFn GetFunc, expectedGrace int64) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, "foo4")
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	objectMeta := t.getObjectMetaOrFail(foo)
	generation := objectMeta.GetGeneration()
	_, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(expectedGrace))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted {
		t.Errorf("unexpected, object %s should not have been deleted immediately", objectMeta.GetName())
	}
	if _, err := getFn(ctx, foo); err != nil {
		t.Fatalf("did not gracefully delete resource: %v", err)
	}

	// second delete is immediate, resource is deleted
	out, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(0))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted != true {
		t.Errorf("unexpected, object %s should have been deleted immediately", objectMeta.GetName())
	}
	_, err = t.storage.(rest.Getter).Get(ctx, objectMeta.GetName(), &metav1.GetOptions{})
	if !errors.IsNotFound(err) {
		t.Errorf("unexpected error, object should be deleted immediately: %v", err)
	}
	objectMeta = t.getObjectMetaOrFail(out)
	// the second delete shouldn't update the object, so the objectMeta.GetDeletionGracePeriodSeconds() should eqaul to the value set in the first delete.
	if objectMeta.GetDeletionTimestamp() == nil || objectMeta.GetDeletionGracePeriodSeconds() == nil || *objectMeta.GetDeletionGracePeriodSeconds() != 0 {
		t.Errorf("unexpected deleted meta: %#v", objectMeta)
	}
	if generation >= objectMeta.GetGeneration() {
		t.Error("Generation wasn't bumped when deletion timestamp was set")
	}
}

func (t *Tester) testDeleteGracefulUsesZeroOnNil(obj runtime.Object, createFn CreateFunc, expectedGrace int64) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(5))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	objectMeta := t.getObjectMetaOrFail(foo)
	_, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !wasDeleted {
		t.Errorf("unexpected, object %s should have been deleted immediately", objectMeta.GetName())
	}
	if _, err := t.storage.(rest.Getter).Get(ctx, objectMeta.GetName(), &metav1.GetOptions{}); !errors.IsNotFound(err) {
		t.Errorf("unexpected error, object should not exist: %v", err)
	}
}

// Regression test for bug discussed in #27539
func (t *Tester) testDeleteGracefulShorten(obj runtime.Object, createFn CreateFunc, getFn GetFunc, expectedGrace int64) {
	ctx := t.TestContext()

	foo := obj.DeepCopyObject()
	t.setObjectMeta(foo, t.namer(6))
	if err := createFn(ctx, foo); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	bigGrace := int64(time.Hour)
	if expectedGrace > bigGrace {
		bigGrace = 2 * expectedGrace
	}
	objectMeta := t.getObjectMetaOrFail(foo)
	_, wasDeleted, err := t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(bigGrace))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted {
		t.Errorf("unexpected, object %s should not have been deleted immediately", objectMeta.GetName())
	}
	object, err := getFn(ctx, foo)
	if err != nil {
		t.Fatalf("did not gracefully delete resource: %v", err)
	}
	objectMeta = t.getObjectMetaOrFail(object)
	deletionTimestamp := *objectMeta.GetDeletionTimestamp()

	// second delete duration is ignored
	_, wasDeleted, err = t.storage.(rest.GracefulDeleter).Delete(ctx, objectMeta.GetName(), metav1.NewDeleteOptions(expectedGrace))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if wasDeleted {
		t.Errorf("unexpected, object %s should not have been deleted immediately", objectMeta.GetName())
	}
	object, err = t.storage.(rest.Getter).Get(ctx, objectMeta.GetName(), &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error, object should exist: %v", err)
	}
	objectMeta = t.getObjectMetaOrFail(object)
	if objectMeta.GetDeletionTimestamp() == nil || objectMeta.GetDeletionGracePeriodSeconds() == nil ||
		*objectMeta.GetDeletionGracePeriodSeconds() != expectedGrace || !objectMeta.GetDeletionTimestamp().Before(&deletionTimestamp) {
		t.Errorf("unexpected deleted meta: %#v", objectMeta)
	}
}

// =============================================================================
// Get tests.

// testGetDifferentNamespace ensures same-name objects in different namespaces do not clash
func (t *Tester) testGetDifferentNamespace(obj runtime.Object) {
	if t.clusterScope {
		t.Fatalf("the test does not work in in cluster-scope")
	}

	objMeta := t.getObjectMetaOrFail(obj)
	objMeta.SetName(t.namer(5))

	ctx1 := genericapirequest.WithNamespace(genericapirequest.NewContext(), "bar3")
	objMeta.SetNamespace(genericapirequest.NamespaceValue(ctx1))
	_, err := t.storage.(rest.Creater).Create(ctx1, obj, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ctx2 := genericapirequest.WithNamespace(genericapirequest.NewContext(), "bar4")
	objMeta.SetNamespace(genericapirequest.NamespaceValue(ctx2))
	_, err = t.storage.(rest.Creater).Create(ctx2, obj, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	got1, err := t.storage.(rest.Getter).Get(ctx1, objMeta.GetName(), &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	got1Meta := t.getObjectMetaOrFail(got1)
	if got1Meta.GetName() != objMeta.GetName() {
		t.Errorf("unexpected name of object: %#v, expected: %s", got1, objMeta.GetName())
	}
	if got1Meta.GetNamespace() != genericapirequest.NamespaceValue(ctx1) {
		t.Errorf("unexpected namespace of object: %#v, expected: %s", got1, genericapirequest.NamespaceValue(ctx1))
	}

	got2, err := t.storage.(rest.Getter).Get(ctx2, objMeta.GetName(), &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	got2Meta := t.getObjectMetaOrFail(got2)
	if got2Meta.GetName() != objMeta.GetName() {
		t.Errorf("unexpected name of object: %#v, expected: %s", got2, objMeta.GetName())
	}
	if got2Meta.GetNamespace() != genericapirequest.NamespaceValue(ctx2) {
		t.Errorf("unexpected namespace of object: %#v, expected: %s", got2, genericapirequest.NamespaceValue(ctx2))
	}
}

func (t *Tester) testGetFound(obj runtime.Object) {
	ctx := t.TestContext()
	t.setObjectMeta(obj, t.namer(1))

	existing, err := t.storage.(rest.Creater).Create(ctx, obj, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	existingMeta := t.getObjectMetaOrFail(existing)

	got, err := t.storage.(rest.Getter).Get(ctx, t.namer(1), &metav1.GetOptions{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	gotMeta := t.getObjectMetaOrFail(got)
	gotMeta.SetResourceVersion(existingMeta.GetResourceVersion())
	if e, a := existing, got; !apiequality.Semantic.DeepEqual(e, a) {
		t.Errorf("unexpected obj: %#v, expected %#v", e, a)
	}
}

func (t *Tester) testGetMimatchedNamespace(obj runtime.Object) {
	ctx1 := genericapirequest.WithNamespace(genericapirequest.NewContext(), "bar1")
	ctx2 := genericapirequest.WithNamespace(genericapirequest.NewContext(), "bar2")
	objMeta := t.getObjectMetaOrFail(obj)
	objMeta.SetName(t.namer(4))
	objMeta.SetNamespace(genericapirequest.NamespaceValue(ctx1))
	_, err := t.storage.(rest.Creater).Create(ctx1, obj, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	_, err = t.storage.(rest.Getter).Get(ctx2, t.namer(4), &metav1.GetOptions{})
	if t.clusterScope {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	} else {
		if !errors.IsNotFound(err) {
			t.Errorf("unexpected error returned: %#v", err)
		}
	}
}

func (t *Tester) testGetNotFound(obj runtime.Object) {
	ctx := t.TestContext()
	t.setObjectMeta(obj, t.namer(2))
	_, err := t.storage.(rest.Creater).Create(ctx, obj, false)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	_, err = t.storage.(rest.Getter).Get(ctx, t.namer(3), &metav1.GetOptions{})
	if !errors.IsNotFound(err) {
		t.Errorf("unexpected error returned: %#v", err)
	}
}

// =============================================================================
// List tests.

func listToItems(listObj runtime.Object) ([]runtime.Object, error) {
	v, err := conversion.EnforcePtr(listObj)
	if err != nil {
		return nil, fmt.Errorf("unexpected error: %v", err)
	}
	items := v.FieldByName("Items")
	if !items.IsValid() {
		return nil, fmt.Errorf("unexpected Items field in %v", listObj)
	}
	if items.Type().Kind() != reflect.Slice {
		return nil, fmt.Errorf("unexpected Items field type: %v", items.Type().Kind())
	}
	result := make([]runtime.Object, items.Len())
	for i := 0; i < items.Len(); i++ {
		result[i] = items.Index(i).Addr().Interface().(runtime.Object)
	}
	return result, nil
}

func (t *Tester) testListFound(obj runtime.Object, assignFn AssignFunc) {
	ctx := t.TestContext()

	foo1 := obj.DeepCopyObject()
	t.setObjectMeta(foo1, t.namer(1))
	foo2 := obj.DeepCopyObject()
	t.setObjectMeta(foo2, t.namer(2))

	existing := assignFn([]runtime.Object{foo1, foo2})

	listObj, err := t.storage.(rest.Lister).List(ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	items, err := listToItems(listObj)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(items) != len(existing) {
		t.Errorf("unexpected number of items: %v", len(items))
	}
	if !apiequality.Semantic.DeepEqual(existing, items) {
		t.Errorf("expected: %#v, got: %#v", existing, items)
	}
}

func (t *Tester) testListMatchLabels(obj runtime.Object, assignFn AssignFunc) {
	ctx := t.TestContext()
	testLabels := map[string]string{"key": "value"}

	foo3 := obj.DeepCopyObject()
	t.setObjectMeta(foo3, "foo3")
	foo4 := obj.DeepCopyObject()
	foo4Meta := t.getObjectMetaOrFail(foo4)
	foo4Meta.SetName("foo4")
	foo4Meta.SetNamespace(genericapirequest.NamespaceValue(ctx))
	foo4Meta.SetLabels(testLabels)

	objs := ([]runtime.Object{foo3, foo4})

	assignFn(objs)
	filtered := []runtime.Object{objs[1]}

	selector := labels.SelectorFromSet(labels.Set(testLabels))
	options := &metainternalversion.ListOptions{LabelSelector: selector}
	listObj, err := t.storage.(rest.Lister).List(ctx, options)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	items, err := listToItems(listObj)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(items) != len(filtered) {
		t.Errorf("unexpected number of items: %v", len(items))
	}
	if !apiequality.Semantic.DeepEqual(filtered, items) {
		t.Errorf("expected: %#v, got: %#v", filtered, items)
	}
}

func (t *Tester) testListNotFound(assignFn AssignFunc) {
	ctx := t.TestContext()
	_ = assignFn([]runtime.Object{})

	listObj, err := t.storage.(rest.Lister).List(ctx, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	items, err := listToItems(listObj)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("unexpected items: %#v", items)
	}
}

// testListTableConversion verifies a set of known bounds and expected limitations for the values
// returned from a TableList. These conditions may be changed if necessary with adequate review.
func (t *Tester) testListTableConversion(obj runtime.Object, assignFn AssignFunc) {
	ctx := t.TestContext()
	testLabels := map[string]string{"key": "value"}

	foo3 := obj.DeepCopyObject()
	t.setObjectMeta(foo3, "foo3")
	foo4 := obj.DeepCopyObject()
	foo4Meta := t.getObjectMetaOrFail(foo4)
	foo4Meta.SetName("foo4")
	foo4Meta.SetNamespace(genericapirequest.NamespaceValue(ctx))
	foo4Meta.SetLabels(testLabels)

	objs := ([]runtime.Object{foo3, foo4})

	assignFn(objs)

	options := &metainternalversion.ListOptions{}
	listObj, err := t.storage.(rest.Lister).List(ctx, options)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	items, err := listToItems(listObj)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(items) != len(objs) {
		t.Errorf("unexpected number of items: %v", len(items))
	}
	if !apiequality.Semantic.DeepEqual(objs, items) {
		t.Errorf("expected: %#v, got: %#v", objs, items)
	}

	table, err := t.storage.(rest.TableConvertor).ConvertToTable(ctx, listObj, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(table.Rows) != len(items) {
		t.Errorf("unexpected number of rows: %v", len(table.Rows))
	}
	columns := table.ColumnDefinitions
	if len(columns) == 0 {
		t.Errorf("unexpected number of columns: %v", len(columns))
	}
	if columns[0].Name != "Name" || columns[0].Type != "string" || columns[0].Format != "name" {
		t.Errorf("expect column 0 to be the name column: %#v", columns[0])
	}
	for j, column := range columns {
		if len(column.Name) == 0 {
			t.Errorf("column %d has no name", j)
		}
		switch column.Type {
		case "string", "date", "integer":
		default:
			t.Errorf("column %d has unexpected type: %q", j, column.Type)
		}
		switch {
		case column.Format == "":
		case column.Format == "name" && column.Type == "string":
		default:
			t.Errorf("column %d has unexpected format: %q with type %q", j, column.Format, column.Type)
		}
		if column.Priority < 0 || column.Priority > 2 {
			t.Errorf("column %d has unexpected priority", j, column.Priority)
		}
		if len(column.Description) == 0 {
			t.Errorf("column %d has no description", j)
		}
		if column.Name == "Created At" && column.Type != "date" && column.Format != "" {
			t.Errorf("column %d looks like a created at column, but has a different type and format: %#v", j, column)
		}
	}
	for i, row := range table.Rows {
		if len(row.Cells) != len(table.ColumnDefinitions) {
			t.Errorf("row %d did not have the correct number of cells: %d in %v", len(table.ColumnDefinitions), row.Cells)
		}
		for j, cell := range row.Cells {
			// do not add to this test without discussion - may break clients
			switch cell.(type) {
			case float64, int64, int32, int, string, bool:
			case []interface{}:
			default:
				t.Errorf("row %d, cell %d has an unrecognized type, only JSON serialization safe types are allowed: %T ", i, j, cell)
			}
		}
		if len(row.Cells) != len(table.ColumnDefinitions) {
		}
	}
}

// =============================================================================
// Watching tests.

func (t *Tester) testWatchFields(obj runtime.Object, emitFn EmitFunc, fieldsPass, fieldsFail []fields.Set, actions []string) {
	ctx := t.TestContext()

	for _, field := range fieldsPass {
		for _, action := range actions {
			options := &metainternalversion.ListOptions{FieldSelector: field.AsSelector(), ResourceVersion: "1"}
			watcher, err := t.storage.(rest.Watcher).Watch(ctx, options)
			if err != nil {
				t.Errorf("unexpected error: %v, %v", err, action)
			}

			if err := emitFn(obj, action); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			select {
			case _, ok := <-watcher.ResultChan():
				if !ok {
					t.Errorf("watch channel should be open")
				}
			case <-time.After(wait.ForeverTestTimeout):
				t.Errorf("unexpected timeout from result channel")
			}
			watcher.Stop()
		}
	}

	for _, field := range fieldsFail {
		for _, action := range actions {
			options := &metainternalversion.ListOptions{FieldSelector: field.AsSelector(), ResourceVersion: "1"}
			watcher, err := t.storage.(rest.Watcher).Watch(ctx, options)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if err := emitFn(obj, action); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			select {
			case <-watcher.ResultChan():
				t.Errorf("unexpected result from result channel")
			case <-time.After(time.Millisecond * 500):
				// expected case
			}
			watcher.Stop()
		}
	}
}

func (t *Tester) testWatchLabels(obj runtime.Object, emitFn EmitFunc, labelsPass, labelsFail []labels.Set, actions []string) {
	ctx := t.TestContext()

	for _, label := range labelsPass {
		for _, action := range actions {
			options := &metainternalversion.ListOptions{LabelSelector: label.AsSelector(), ResourceVersion: "1"}
			watcher, err := t.storage.(rest.Watcher).Watch(ctx, options)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if err := emitFn(obj, action); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			select {
			case _, ok := <-watcher.ResultChan():
				if !ok {
					t.Errorf("watch channel should be open")
				}
			case <-time.After(wait.ForeverTestTimeout):
				t.Errorf("unexpected timeout from result channel")
			}
			watcher.Stop()
		}
	}

	for _, label := range labelsFail {
		for _, action := range actions {
			options := &metainternalversion.ListOptions{LabelSelector: label.AsSelector(), ResourceVersion: "1"}
			watcher, err := t.storage.(rest.Watcher).Watch(ctx, options)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if err := emitFn(obj, action); err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			select {
			case <-watcher.ResultChan():
				t.Errorf("unexpected result from result channel")
			case <-time.After(time.Millisecond * 500):
				// expected case
			}
			watcher.Stop()
		}
	}
}
