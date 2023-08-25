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

package fake

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	// Using v4 to match upstream
	jsonpatch "github.com/evanphx/json-patch"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/internal/field/selector"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/internal/objectutil"
)

type versionedTracker struct {
	testing.ObjectTracker
	scheme                *runtime.Scheme
	withStatusSubresource sets.Set[schema.GroupVersionKind]
}

type fakeClient struct {
	tracker               versionedTracker
	scheme                *runtime.Scheme
	restMapper            meta.RESTMapper
	withStatusSubresource sets.Set[schema.GroupVersionKind]

	// indexes maps each GroupVersionKind (GVK) to the indexes registered for that GVK.
	// The inner map maps from index name to IndexerFunc.
	indexes map[schema.GroupVersionKind]map[string]client.IndexerFunc

	schemeWriteLock sync.Mutex
}

var _ client.WithWatch = &fakeClient{}

const (
	maxNameLength          = 63
	randomLength           = 5
	maxGeneratedNameLength = maxNameLength - randomLength
)

// NewFakeClient creates a new fake client for testing.
// You can choose to initialize it with a slice of runtime.Object.
//
// Deprecated: Please use NewClientBuilder instead.
func NewFakeClient(initObjs ...runtime.Object) client.WithWatch {
	return NewClientBuilder().WithRuntimeObjects(initObjs...).Build()
}

// NewFakeClientWithScheme creates a new fake client with the given scheme
// for testing.
// You can choose to initialize it with a slice of runtime.Object.
//
// Deprecated: Please use NewClientBuilder instead.
func NewFakeClientWithScheme(clientScheme *runtime.Scheme, initObjs ...runtime.Object) client.WithWatch {
	return NewClientBuilder().WithScheme(clientScheme).WithRuntimeObjects(initObjs...).Build()
}

// NewClientBuilder returns a new builder to create a fake client.
func NewClientBuilder() *ClientBuilder {
	return &ClientBuilder{}
}

// ClientBuilder builds a fake client.
type ClientBuilder struct {
	scheme                *runtime.Scheme
	restMapper            meta.RESTMapper
	initObject            []client.Object
	initLists             []client.ObjectList
	initRuntimeObjects    []runtime.Object
	withStatusSubresource []client.Object
	objectTracker         testing.ObjectTracker
	interceptorFuncs      *interceptor.Funcs

	// indexes maps each GroupVersionKind (GVK) to the indexes registered for that GVK.
	// The inner map maps from index name to IndexerFunc.
	indexes map[schema.GroupVersionKind]map[string]client.IndexerFunc
}

// WithScheme sets this builder's internal scheme.
// If not set, defaults to client-go's global scheme.Scheme.
func (f *ClientBuilder) WithScheme(scheme *runtime.Scheme) *ClientBuilder {
	f.scheme = scheme
	return f
}

// WithRESTMapper sets this builder's restMapper.
// The restMapper is directly set as mapper in the Client. This can be used for example
// with a meta.DefaultRESTMapper to provide a static rest mapping.
// If not set, defaults to an empty meta.DefaultRESTMapper.
func (f *ClientBuilder) WithRESTMapper(restMapper meta.RESTMapper) *ClientBuilder {
	f.restMapper = restMapper
	return f
}

// WithObjects can be optionally used to initialize this fake client with client.Object(s).
func (f *ClientBuilder) WithObjects(initObjs ...client.Object) *ClientBuilder {
	f.initObject = append(f.initObject, initObjs...)
	return f
}

// WithLists can be optionally used to initialize this fake client with client.ObjectList(s).
func (f *ClientBuilder) WithLists(initLists ...client.ObjectList) *ClientBuilder {
	f.initLists = append(f.initLists, initLists...)
	return f
}

// WithRuntimeObjects can be optionally used to initialize this fake client with runtime.Object(s).
func (f *ClientBuilder) WithRuntimeObjects(initRuntimeObjs ...runtime.Object) *ClientBuilder {
	f.initRuntimeObjects = append(f.initRuntimeObjects, initRuntimeObjs...)
	return f
}

// WithObjectTracker can be optionally used to initialize this fake client with testing.ObjectTracker.
func (f *ClientBuilder) WithObjectTracker(ot testing.ObjectTracker) *ClientBuilder {
	f.objectTracker = ot
	return f
}

// WithIndex can be optionally used to register an index with name `field` and indexer `extractValue`
// for API objects of the same GroupVersionKind (GVK) as `obj` in the fake client.
// It can be invoked multiple times, both with objects of the same GVK or different ones.
// Invoking WithIndex twice with the same `field` and GVK (via `obj`) arguments will panic.
// WithIndex retrieves the GVK of `obj` using the scheme registered via WithScheme if
// WithScheme was previously invoked, the default scheme otherwise.
func (f *ClientBuilder) WithIndex(obj runtime.Object, field string, extractValue client.IndexerFunc) *ClientBuilder {
	objScheme := f.scheme
	if objScheme == nil {
		objScheme = scheme.Scheme
	}

	gvk, err := apiutil.GVKForObject(obj, objScheme)
	if err != nil {
		panic(err)
	}

	// If this is the first index being registered, we initialize the map storing all the indexes.
	if f.indexes == nil {
		f.indexes = make(map[schema.GroupVersionKind]map[string]client.IndexerFunc)
	}

	// If this is the first index being registered for the GroupVersionKind of `obj`, we initialize
	// the map storing the indexes for that GroupVersionKind.
	if f.indexes[gvk] == nil {
		f.indexes[gvk] = make(map[string]client.IndexerFunc)
	}

	if _, fieldAlreadyIndexed := f.indexes[gvk][field]; fieldAlreadyIndexed {
		panic(fmt.Errorf("indexer conflict: field %s for GroupVersionKind %v is already indexed",
			field, gvk))
	}

	f.indexes[gvk][field] = extractValue

	return f
}

// WithStatusSubresource configures the passed object with a status subresource, which means
// calls to Update and Patch will not alter its status.
func (f *ClientBuilder) WithStatusSubresource(o ...client.Object) *ClientBuilder {
	f.withStatusSubresource = append(f.withStatusSubresource, o...)
	return f
}

// WithInterceptorFuncs configures the client methods to be intercepted using the provided interceptor.Funcs.
func (f *ClientBuilder) WithInterceptorFuncs(interceptorFuncs interceptor.Funcs) *ClientBuilder {
	f.interceptorFuncs = &interceptorFuncs
	return f
}

// Build builds and returns a new fake client.
func (f *ClientBuilder) Build() client.WithWatch {
	if f.scheme == nil {
		f.scheme = scheme.Scheme
	}
	if f.restMapper == nil {
		f.restMapper = meta.NewDefaultRESTMapper([]schema.GroupVersion{})
	}

	var tracker versionedTracker

	withStatusSubResource := sets.New(inTreeResourcesWithStatus()...)
	for _, o := range f.withStatusSubresource {
		gvk, err := apiutil.GVKForObject(o, f.scheme)
		if err != nil {
			panic(fmt.Errorf("failed to get gvk for object %T: %w", withStatusSubResource, err))
		}
		withStatusSubResource.Insert(gvk)
	}

	if f.objectTracker == nil {
		tracker = versionedTracker{ObjectTracker: testing.NewObjectTracker(f.scheme, scheme.Codecs.UniversalDecoder()), scheme: f.scheme, withStatusSubresource: withStatusSubResource}
	} else {
		tracker = versionedTracker{ObjectTracker: f.objectTracker, scheme: f.scheme, withStatusSubresource: withStatusSubResource}
	}

	for _, obj := range f.initObject {
		if err := tracker.Add(obj); err != nil {
			panic(fmt.Errorf("failed to add object %v to fake client: %w", obj, err))
		}
	}
	for _, obj := range f.initLists {
		if err := tracker.Add(obj); err != nil {
			panic(fmt.Errorf("failed to add list %v to fake client: %w", obj, err))
		}
	}
	for _, obj := range f.initRuntimeObjects {
		if err := tracker.Add(obj); err != nil {
			panic(fmt.Errorf("failed to add runtime object %v to fake client: %w", obj, err))
		}
	}

	var result client.WithWatch = &fakeClient{
		tracker:               tracker,
		scheme:                f.scheme,
		restMapper:            f.restMapper,
		indexes:               f.indexes,
		withStatusSubresource: withStatusSubResource,
	}

	if f.interceptorFuncs != nil {
		result = interceptor.NewClient(result, *f.interceptorFuncs)
	}

	return result
}

const trackerAddResourceVersion = "999"

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
		if err := t.ObjectTracker.Add(obj); err != nil {
			return err
		}
	}

	return nil
}

func (t versionedTracker) Create(gvr schema.GroupVersionResource, obj runtime.Object, ns string) error {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("failed to get accessor for object: %w", err)
	}
	if accessor.GetName() == "" {
		return apierrors.NewInvalid(
			obj.GetObjectKind().GroupVersionKind().GroupKind(),
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
	if err := t.ObjectTracker.Create(gvr, obj, ns); err != nil {
		accessor.SetResourceVersion("")
		return err
	}

	return nil
}

// convertFromUnstructuredIfNecessary will convert runtime.Unstructured for a GVK that is recognized
// by the schema into the whatever the schema produces with New() for said GVK.
// This is required because the tracker unconditionally saves on manipulations, but its List() implementation
// tries to assign whatever it finds into a ListType it gets from schema.New() - Thus we have to ensure
// we save as the very same type, otherwise subsequent List requests will fail.
func convertFromUnstructuredIfNecessary(s *runtime.Scheme, o runtime.Object) (runtime.Object, error) {
	gvk := o.GetObjectKind().GroupVersionKind()

	u, isUnstructured := o.(runtime.Unstructured)
	if !isUnstructured || !s.Recognizes(gvk) {
		return o, nil
	}

	typed, err := s.New(gvk)
	if err != nil {
		return nil, fmt.Errorf("scheme recognizes %s but failed to produce an object for it: %w", gvk, err)
	}

	unstructuredSerialized, err := json.Marshal(u)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize %T: %w", unstructuredSerialized, err)
	}
	if err := json.Unmarshal(unstructuredSerialized, typed); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the content of %T into %T: %w", u, typed, err)
	}

	return typed, nil
}

func (t versionedTracker) Update(gvr schema.GroupVersionResource, obj runtime.Object, ns string) error {
	isStatus := false
	// We apply patches using a client-go reaction that ends up calling the trackers Update. As we can't change
	// that reaction, we use the callstack to figure out if this originated from the status client.
	if bytes.Contains(debug.Stack(), []byte("sigs.k8s.io/controller-runtime/pkg/client/fake.(*fakeSubResourceClient).Patch")) {
		isStatus = true
	}
	return t.update(gvr, obj, ns, isStatus, false)
}

func (t versionedTracker) update(gvr schema.GroupVersionResource, obj runtime.Object, ns string, isStatus bool, deleting bool) error {
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return fmt.Errorf("failed to get accessor for object: %w", err)
	}

	if accessor.GetName() == "" {
		return apierrors.NewInvalid(
			obj.GetObjectKind().GroupVersionKind().GroupKind(),
			accessor.GetName(),
			field.ErrorList{field.Required(field.NewPath("metadata.name"), "name is required")})
	}

	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Empty() {
		gvk, err = apiutil.GVKForObject(obj, t.scheme)
		if err != nil {
			return err
		}
	}

	oldObject, err := t.ObjectTracker.Get(gvr, ns, accessor.GetName())
	if err != nil {
		// If the resource is not found and the resource allows create on update, issue a
		// create instead.
		if apierrors.IsNotFound(err) && allowsCreateOnUpdate(gvk) {
			return t.Create(gvr, obj, ns)
		}
		return err
	}

	if t.withStatusSubresource.Has(gvk) {
		if isStatus { // copy everything but status and metadata.ResourceVersion from original object
			if err := copyNonStatusFrom(oldObject, obj); err != nil {
				return fmt.Errorf("failed to copy non-status field for object with status subresouce: %w", err)
			}
		} else { // copy status from original object
			if err := copyStatusFrom(oldObject, obj); err != nil {
				return fmt.Errorf("failed to copy the status for object with status subresource: %w", err)
			}
		}
	} else if isStatus {
		return apierrors.NewNotFound(gvr.GroupResource(), accessor.GetName())
	}

	oldAccessor, err := meta.Accessor(oldObject)
	if err != nil {
		return err
	}

	// If the new object does not have the resource version set and it allows unconditional update,
	// default it to the resource version of the existing resource
	if accessor.GetResourceVersion() == "" && allowsUnconditionalUpdate(gvk) {
		accessor.SetResourceVersion(oldAccessor.GetResourceVersion())
	}
	if accessor.GetResourceVersion() != oldAccessor.GetResourceVersion() {
		return apierrors.NewConflict(gvr.GroupResource(), accessor.GetName(), errors.New("object was modified"))
	}
	if oldAccessor.GetResourceVersion() == "" {
		oldAccessor.SetResourceVersion("0")
	}
	intResourceVersion, err := strconv.ParseUint(oldAccessor.GetResourceVersion(), 10, 64)
	if err != nil {
		return fmt.Errorf("can not convert resourceVersion %q to int: %w", oldAccessor.GetResourceVersion(), err)
	}
	intResourceVersion++
	accessor.SetResourceVersion(strconv.FormatUint(intResourceVersion, 10))

	if !deleting && !deletionTimestampEqual(accessor, oldAccessor) {
		return fmt.Errorf("error: Unable to edit %s: metadata.deletionTimestamp field is immutable", accessor.GetName())
	}

	if !accessor.GetDeletionTimestamp().IsZero() && len(accessor.GetFinalizers()) == 0 {
		return t.ObjectTracker.Delete(gvr, accessor.GetNamespace(), accessor.GetName())
	}
	obj, err = convertFromUnstructuredIfNecessary(t.scheme, obj)
	if err != nil {
		return err
	}
	return t.ObjectTracker.Update(gvr, obj, ns)
}

func (c *fakeClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	o, err := c.tracker.Get(gvr, key.Namespace, key.Name)
	if err != nil {
		return err
	}

	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}
	ta, err := meta.TypeAccessor(o)
	if err != nil {
		return err
	}
	ta.SetKind(gvk.Kind)
	ta.SetAPIVersion(gvk.GroupVersion().String())

	j, err := json.Marshal(o)
	if err != nil {
		return err
	}
	decoder := scheme.Codecs.UniversalDecoder()
	zero(obj)
	_, _, err = decoder.Decode(j, nil, obj)
	return err
}

func (c *fakeClient) Watch(ctx context.Context, list client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
	gvk, err := apiutil.GVKForObject(list, c.scheme)
	if err != nil {
		return nil, err
	}

	gvk.Kind = strings.TrimSuffix(gvk.Kind, "List")

	listOpts := client.ListOptions{}
	listOpts.ApplyOptions(opts)

	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	return c.tracker.Watch(gvr, listOpts.Namespace)
}

func (c *fakeClient) List(ctx context.Context, obj client.ObjectList, opts ...client.ListOption) error {
	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}

	originalKind := gvk.Kind

	gvk.Kind = strings.TrimSuffix(gvk.Kind, "List")

	if _, isUnstructuredList := obj.(runtime.Unstructured); isUnstructuredList && !c.scheme.Recognizes(gvk) {
		// We need to register the ListKind with UnstructuredList:
		// https://github.com/kubernetes/kubernetes/blob/7b2776b89fb1be28d4e9203bdeec079be903c103/staging/src/k8s.io/client-go/dynamic/fake/simple.go#L44-L51
		c.schemeWriteLock.Lock()
		c.scheme.AddKnownTypeWithName(gvk.GroupVersion().WithKind(gvk.Kind+"List"), &unstructured.UnstructuredList{})
		c.schemeWriteLock.Unlock()
	}

	listOpts := client.ListOptions{}
	listOpts.ApplyOptions(opts)

	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	o, err := c.tracker.List(gvr, gvk, listOpts.Namespace)
	if err != nil {
		return err
	}

	ta, err := meta.TypeAccessor(o)
	if err != nil {
		return err
	}
	ta.SetKind(originalKind)
	ta.SetAPIVersion(gvk.GroupVersion().String())

	j, err := json.Marshal(o)
	if err != nil {
		return err
	}
	decoder := scheme.Codecs.UniversalDecoder()
	zero(obj)
	_, _, err = decoder.Decode(j, nil, obj)
	if err != nil {
		return err
	}

	if listOpts.LabelSelector == nil && listOpts.FieldSelector == nil {
		return nil
	}

	// If we're here, either a label or field selector are specified (or both), so before we return
	// the list we must filter it. If both selectors are set, they are ANDed.
	objs, err := meta.ExtractList(obj)
	if err != nil {
		return err
	}

	filteredList, err := c.filterList(objs, gvk, listOpts.LabelSelector, listOpts.FieldSelector)
	if err != nil {
		return err
	}

	return meta.SetList(obj, filteredList)
}

func (c *fakeClient) filterList(list []runtime.Object, gvk schema.GroupVersionKind, ls labels.Selector, fs fields.Selector) ([]runtime.Object, error) {
	// Filter the objects with the label selector
	filteredList := list
	if ls != nil {
		objsFilteredByLabel, err := objectutil.FilterWithLabels(list, ls)
		if err != nil {
			return nil, err
		}
		filteredList = objsFilteredByLabel
	}

	// Filter the result of the previous pass with the field selector
	if fs != nil {
		objsFilteredByField, err := c.filterWithFields(filteredList, gvk, fs)
		if err != nil {
			return nil, err
		}
		filteredList = objsFilteredByField
	}

	return filteredList, nil
}

func (c *fakeClient) filterWithFields(list []runtime.Object, gvk schema.GroupVersionKind, fs fields.Selector) ([]runtime.Object, error) {
	// We only allow filtering on the basis of a single field to ensure consistency with the
	// behavior of the cache reader (which we're faking here).
	fieldKey, fieldVal, requiresExact := selector.RequiresExactMatch(fs)
	if !requiresExact {
		return nil, fmt.Errorf("field selector %s is not in one of the two supported forms \"key==val\" or \"key=val\"",
			fs)
	}

	// Field selection is mimicked via indexes, so there's no sane answer this function can give
	// if there are no indexes registered for the GroupVersionKind of the objects in the list.
	indexes := c.indexes[gvk]
	if len(indexes) == 0 || indexes[fieldKey] == nil {
		return nil, fmt.Errorf("List on GroupVersionKind %v specifies selector on field %s, but no "+
			"index with name %s has been registered for GroupVersionKind %v", gvk, fieldKey, fieldKey, gvk)
	}

	indexExtractor := indexes[fieldKey]
	filteredList := make([]runtime.Object, 0, len(list))
	for _, obj := range list {
		if c.objMatchesFieldSelector(obj, indexExtractor, fieldVal) {
			filteredList = append(filteredList, obj)
		}
	}
	return filteredList, nil
}

func (c *fakeClient) objMatchesFieldSelector(o runtime.Object, extractIndex client.IndexerFunc, val string) bool {
	obj, isClientObject := o.(client.Object)
	if !isClientObject {
		panic(fmt.Errorf("expected object %v to be of type client.Object, but it's not", o))
	}

	for _, extractedVal := range extractIndex(obj) {
		if extractedVal == val {
			return true
		}
	}

	return false
}

func (c *fakeClient) Scheme() *runtime.Scheme {
	return c.scheme
}

func (c *fakeClient) RESTMapper() meta.RESTMapper {
	return c.restMapper
}

// GroupVersionKindFor returns the GroupVersionKind for the given object.
func (c *fakeClient) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return apiutil.GVKForObject(obj, c.scheme)
}

// IsObjectNamespaced returns true if the GroupVersionKind of the object is namespaced.
func (c *fakeClient) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return apiutil.IsObjectNamespaced(obj, c.scheme, c.restMapper)
}

func (c *fakeClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	createOptions := &client.CreateOptions{}
	createOptions.ApplyOptions(opts)

	for _, dryRunOpt := range createOptions.DryRun {
		if dryRunOpt == metav1.DryRunAll {
			return nil
		}
	}

	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return err
	}

	if accessor.GetName() == "" && accessor.GetGenerateName() != "" {
		base := accessor.GetGenerateName()
		if len(base) > maxGeneratedNameLength {
			base = base[:maxGeneratedNameLength]
		}
		accessor.SetName(fmt.Sprintf("%s%s", base, utilrand.String(randomLength)))
	}
	// Ignore attempts to set deletion timestamp
	if !accessor.GetDeletionTimestamp().IsZero() {
		accessor.SetDeletionTimestamp(nil)
	}

	return c.tracker.Create(gvr, obj, accessor.GetNamespace())
}

func (c *fakeClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	delOptions := client.DeleteOptions{}
	delOptions.ApplyOptions(opts)

	for _, dryRunOpt := range delOptions.DryRun {
		if dryRunOpt == metav1.DryRunAll {
			return nil
		}
	}

	// Check the ResourceVersion if that Precondition was specified.
	if delOptions.Preconditions != nil && delOptions.Preconditions.ResourceVersion != nil {
		name := accessor.GetName()
		dbObj, err := c.tracker.Get(gvr, accessor.GetNamespace(), name)
		if err != nil {
			return err
		}
		oldAccessor, err := meta.Accessor(dbObj)
		if err != nil {
			return err
		}
		actualRV := oldAccessor.GetResourceVersion()
		expectRV := *delOptions.Preconditions.ResourceVersion
		if actualRV != expectRV {
			msg := fmt.Sprintf(
				"the ResourceVersion in the precondition (%s) does not match the ResourceVersion in record (%s). "+
					"The object might have been modified",
				expectRV, actualRV)
			return apierrors.NewConflict(gvr.GroupResource(), name, errors.New(msg))
		}
	}

	return c.deleteObject(gvr, accessor)
}

func (c *fakeClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}

	dcOptions := client.DeleteAllOfOptions{}
	dcOptions.ApplyOptions(opts)

	for _, dryRunOpt := range dcOptions.DryRun {
		if dryRunOpt == metav1.DryRunAll {
			return nil
		}
	}

	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	o, err := c.tracker.List(gvr, gvk, dcOptions.Namespace)
	if err != nil {
		return err
	}

	objs, err := meta.ExtractList(o)
	if err != nil {
		return err
	}
	filteredObjs, err := objectutil.FilterWithLabels(objs, dcOptions.LabelSelector)
	if err != nil {
		return err
	}
	for _, o := range filteredObjs {
		accessor, err := meta.Accessor(o)
		if err != nil {
			return err
		}
		err = c.deleteObject(gvr, accessor)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *fakeClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return c.update(obj, false, opts...)
}

func (c *fakeClient) update(obj client.Object, isStatus bool, opts ...client.UpdateOption) error {
	updateOptions := &client.UpdateOptions{}
	updateOptions.ApplyOptions(opts)

	for _, dryRunOpt := range updateOptions.DryRun {
		if dryRunOpt == metav1.DryRunAll {
			return nil
		}
	}

	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	return c.tracker.update(gvr, obj, accessor.GetNamespace(), isStatus, false)
}

func (c *fakeClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	return c.patch(obj, patch, opts...)
}

func (c *fakeClient) patch(obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	patchOptions := &client.PatchOptions{}
	patchOptions.ApplyOptions(opts)

	for _, dryRunOpt := range patchOptions.DryRun {
		if dryRunOpt == metav1.DryRunAll {
			return nil
		}
	}

	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return err
	}
	data, err := patch.Data(obj)
	if err != nil {
		return err
	}

	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}

	oldObj, err := c.tracker.Get(gvr, accessor.GetNamespace(), accessor.GetName())
	if err != nil {
		return err
	}
	oldAccessor, err := meta.Accessor(oldObj)
	if err != nil {
		return err
	}

	// Apply patch without updating object.
	// To remain in accordance with the behavior of k8s api behavior,
	// a patch must not allow for changes to the deletionTimestamp of an object.
	// The reaction() function applies the patch to the object and calls Update(),
	// whereas dryPatch() replicates this behavior but skips the call to Update().
	// This ensures that the patch may be rejected if a deletionTimestamp is modified, prior
	// to updating the object.
	action := testing.NewPatchAction(gvr, accessor.GetNamespace(), accessor.GetName(), patch.Type(), data)
	o, err := dryPatch(action, c.tracker)
	if err != nil {
		return err
	}
	newObj, err := meta.Accessor(o)
	if err != nil {
		return err
	}

	// Validate that deletionTimestamp has not been changed
	if !deletionTimestampEqual(newObj, oldAccessor) {
		return fmt.Errorf("rejected patch, metadata.deletionTimestamp immutable")
	}

	reaction := testing.ObjectReaction(c.tracker)
	handled, o, err := reaction(action)
	if err != nil {
		return err
	}
	if !handled {
		panic("tracker could not handle patch method")
	}
	ta, err := meta.TypeAccessor(o)
	if err != nil {
		return err
	}
	ta.SetKind(gvk.Kind)
	ta.SetAPIVersion(gvk.GroupVersion().String())

	j, err := json.Marshal(o)
	if err != nil {
		return err
	}
	decoder := scheme.Codecs.UniversalDecoder()
	zero(obj)
	_, _, err = decoder.Decode(j, nil, obj)
	return err
}

// Applying a patch results in a deletionTimestamp that is truncated to the nearest second.
// Check that the diff between a new and old deletion timestamp is within a reasonable threshold
// to be considered unchanged.
func deletionTimestampEqual(newObj metav1.Object, obj metav1.Object) bool {
	newTime := newObj.GetDeletionTimestamp()
	oldTime := obj.GetDeletionTimestamp()

	if newTime == nil || oldTime == nil {
		return newTime == oldTime
	}
	return newTime.Time.Sub(oldTime.Time).Abs() < time.Second
}

// The behavior of applying the patch is pulled out into dryPatch(),
// which applies the patch and returns an object, but does not Update() the object.
// This function returns a patched runtime object that may then be validated before a call to Update() is executed.
// This results in some code duplication, but was found to be a cleaner alternative than unmarshalling and introspecting the patch data
// and easier than refactoring the k8s client-go method upstream.
// Duplicate of upstream: https://github.com/kubernetes/client-go/blob/783d0d33626e59d55d52bfd7696b775851f92107/testing/fixture.go#L146-L194
func dryPatch(action testing.PatchActionImpl, tracker testing.ObjectTracker) (runtime.Object, error) {
	ns := action.GetNamespace()
	gvr := action.GetResource()

	obj, err := tracker.Get(gvr, ns, action.GetName())
	if err != nil {
		return nil, err
	}

	old, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	// reset the object in preparation to unmarshal, since unmarshal does not guarantee that fields
	// in obj that are removed by patch are cleared
	value := reflect.ValueOf(obj)
	value.Elem().Set(reflect.New(value.Type().Elem()).Elem())

	switch action.GetPatchType() {
	case types.JSONPatchType:
		patch, err := jsonpatch.DecodePatch(action.GetPatch())
		if err != nil {
			return nil, err
		}
		modified, err := patch.Apply(old)
		if err != nil {
			return nil, err
		}

		if err = json.Unmarshal(modified, obj); err != nil {
			return nil, err
		}
	case types.MergePatchType:
		modified, err := jsonpatch.MergePatch(old, action.GetPatch())
		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(modified, obj); err != nil {
			return nil, err
		}
	case types.StrategicMergePatchType, types.ApplyPatchType:
		mergedByte, err := strategicpatch.StrategicMergePatch(old, action.GetPatch(), obj)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(mergedByte, obj); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("PatchType is not supported")
	}
	return obj, nil
}

func copyNonStatusFrom(old, new runtime.Object) error {
	newClientObject, ok := new.(client.Object)
	if !ok {
		return fmt.Errorf("%T is not a client.Object", new)
	}
	// The only thing other than status we have to retain
	rv := newClientObject.GetResourceVersion()

	oldMapStringAny, err := toMapStringAny(old)
	if err != nil {
		return fmt.Errorf("failed to convert old to *unstructured.Unstructured: %w", err)
	}
	newMapStringAny, err := toMapStringAny(new)
	if err != nil {
		return fmt.Errorf("failed to convert new to *unststructured.Unstructured: %w", err)
	}

	// delete everything other than status in case it has fields that were not present in
	// the old object
	for k := range newMapStringAny {
		if k != "status" {
			delete(newMapStringAny, k)
		}
	}
	// copy everything other than status from the old object
	for k := range oldMapStringAny {
		if k != "status" {
			newMapStringAny[k] = oldMapStringAny[k]
		}
	}

	if err := fromMapStringAny(newMapStringAny, new); err != nil {
		return fmt.Errorf("failed to convert back from map[string]any: %w", err)
	}
	newClientObject.SetResourceVersion(rv)

	return nil
}

// copyStatusFrom copies the status from old into new
func copyStatusFrom(old, new runtime.Object) error {
	oldMapStringAny, err := toMapStringAny(old)
	if err != nil {
		return fmt.Errorf("failed to convert old to *unstructured.Unstructured: %w", err)
	}
	newMapStringAny, err := toMapStringAny(new)
	if err != nil {
		return fmt.Errorf("failed to convert new to *unststructured.Unstructured: %w", err)
	}

	newMapStringAny["status"] = oldMapStringAny["status"]

	if err := fromMapStringAny(newMapStringAny, new); err != nil {
		return fmt.Errorf("failed to convert back from map[string]any: %w", err)
	}

	return nil
}

func toMapStringAny(obj runtime.Object) (map[string]any, error) {
	if unstructured, isUnstructured := obj.(*unstructured.Unstructured); isUnstructured {
		return unstructured.Object, nil
	}

	serialized, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	u := map[string]any{}
	return u, json.Unmarshal(serialized, &u)
}

func fromMapStringAny(u map[string]any, target runtime.Object) error {
	if targetUnstructured, isUnstructured := target.(*unstructured.Unstructured); isUnstructured {
		targetUnstructured.Object = u
		return nil
	}

	serialized, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("failed to serialize: %w", err)
	}

	if err := json.Unmarshal(serialized, &target); err != nil {
		return fmt.Errorf("failed to deserialize: %w", err)
	}

	return nil
}

func (c *fakeClient) Status() client.SubResourceWriter {
	return c.SubResource("status")
}

func (c *fakeClient) SubResource(subResource string) client.SubResourceClient {
	return &fakeSubResourceClient{client: c, subResource: subResource}
}

func (c *fakeClient) deleteObject(gvr schema.GroupVersionResource, accessor metav1.Object) error {
	old, err := c.tracker.Get(gvr, accessor.GetNamespace(), accessor.GetName())
	if err == nil {
		oldAccessor, err := meta.Accessor(old)
		if err == nil {
			if len(oldAccessor.GetFinalizers()) > 0 {
				now := metav1.Now()
				oldAccessor.SetDeletionTimestamp(&now)
				// Call update directly with mutability parameter set to true to allow
				// changes to deletionTimestamp
				return c.tracker.update(gvr, old, accessor.GetNamespace(), false, true)
			}
		}
	}

	//TODO: implement propagation
	return c.tracker.Delete(gvr, accessor.GetNamespace(), accessor.GetName())
}

func getGVRFromObject(obj runtime.Object, scheme *runtime.Scheme) (schema.GroupVersionResource, error) {
	gvk, err := apiutil.GVKForObject(obj, scheme)
	if err != nil {
		return schema.GroupVersionResource{}, err
	}
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	return gvr, nil
}

type fakeSubResourceClient struct {
	client      *fakeClient
	subResource string
}

func (sw *fakeSubResourceClient) Get(ctx context.Context, obj, subResource client.Object, opts ...client.SubResourceGetOption) error {
	panic("fakeSubResourceClient does not support get")
}

func (sw *fakeSubResourceClient) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	switch sw.subResource {
	case "eviction":
		_, isEviction := subResource.(*policyv1beta1.Eviction)
		if !isEviction {
			_, isEviction = subResource.(*policyv1.Eviction)
		}
		if !isEviction {
			return apierrors.NewBadRequest(fmt.Sprintf("got invalid type %t, expected Eviction", subResource))
		}
		if _, isPod := obj.(*corev1.Pod); !isPod {
			return apierrors.NewNotFound(schema.GroupResource{}, "")
		}

		return sw.client.Delete(ctx, obj)
	default:
		return fmt.Errorf("fakeSubResourceWriter does not support create for %s", sw.subResource)
	}
}

func (sw *fakeSubResourceClient) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	updateOptions := client.SubResourceUpdateOptions{}
	updateOptions.ApplyOptions(opts)

	body := obj
	if updateOptions.SubResourceBody != nil {
		body = updateOptions.SubResourceBody
	}
	return sw.client.update(body, true, &updateOptions.UpdateOptions)
}

func (sw *fakeSubResourceClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	patchOptions := client.SubResourcePatchOptions{}
	patchOptions.ApplyOptions(opts)

	body := obj
	if patchOptions.SubResourceBody != nil {
		body = patchOptions.SubResourceBody
	}

	return sw.client.patch(body, patch, &patchOptions.PatchOptions)
}

func allowsUnconditionalUpdate(gvk schema.GroupVersionKind) bool {
	switch gvk.Group {
	case "apps":
		switch gvk.Kind {
		case "ControllerRevision", "DaemonSet", "Deployment", "ReplicaSet", "StatefulSet":
			return true
		}
	case "autoscaling":
		switch gvk.Kind {
		case "HorizontalPodAutoscaler":
			return true
		}
	case "batch":
		switch gvk.Kind {
		case "CronJob", "Job":
			return true
		}
	case "certificates":
		switch gvk.Kind {
		case "Certificates":
			return true
		}
	case "flowcontrol":
		switch gvk.Kind {
		case "FlowSchema", "PriorityLevelConfiguration":
			return true
		}
	case "networking":
		switch gvk.Kind {
		case "Ingress", "IngressClass", "NetworkPolicy":
			return true
		}
	case "policy":
		switch gvk.Kind {
		case "PodSecurityPolicy":
			return true
		}
	case "rbac":
		switch gvk.Kind {
		case "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding":
			return true
		}
	case "scheduling":
		switch gvk.Kind {
		case "PriorityClass":
			return true
		}
	case "settings":
		switch gvk.Kind {
		case "PodPreset":
			return true
		}
	case "storage":
		switch gvk.Kind {
		case "StorageClass":
			return true
		}
	case "":
		switch gvk.Kind {
		case "ConfigMap", "Endpoint", "Event", "LimitRange", "Namespace", "Node",
			"PersistentVolume", "PersistentVolumeClaim", "Pod", "PodTemplate",
			"ReplicationController", "ResourceQuota", "Secret", "Service",
			"ServiceAccount", "EndpointSlice":
			return true
		}
	}

	return false
}

func allowsCreateOnUpdate(gvk schema.GroupVersionKind) bool {
	switch gvk.Group {
	case "coordination":
		switch gvk.Kind {
		case "Lease":
			return true
		}
	case "node":
		switch gvk.Kind {
		case "RuntimeClass":
			return true
		}
	case "rbac":
		switch gvk.Kind {
		case "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding":
			return true
		}
	case "":
		switch gvk.Kind {
		case "Endpoint", "Event", "LimitRange", "Service":
			return true
		}
	}

	return false
}

func inTreeResourcesWithStatus() []schema.GroupVersionKind {
	return []schema.GroupVersionKind{
		{Version: "v1", Kind: "Namespace"},
		{Version: "v1", Kind: "Node"},
		{Version: "v1", Kind: "PersistentVolumeClaim"},
		{Version: "v1", Kind: "PersistentVolume"},
		{Version: "v1", Kind: "Pod"},
		{Version: "v1", Kind: "ReplicationController"},
		{Version: "v1", Kind: "Service"},

		{Group: "apps", Version: "v1", Kind: "Deployment"},
		{Group: "apps", Version: "v1", Kind: "DaemonSet"},
		{Group: "apps", Version: "v1", Kind: "ReplicaSet"},
		{Group: "apps", Version: "v1", Kind: "StatefulSet"},

		{Group: "autoscaling", Version: "v1", Kind: "HorizontalPodAutoscaler"},

		{Group: "batch", Version: "v1", Kind: "CronJob"},
		{Group: "batch", Version: "v1", Kind: "Job"},

		{Group: "certificates.k8s.io", Version: "v1", Kind: "CertificateSigningRequest"},

		{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"},
		{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"},

		{Group: "policy", Version: "v1", Kind: "PodDisruptionBudget"},

		{Group: "storage.k8s.io", Version: "v1", Kind: "VolumeAttachment"},

		{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"},

		{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta2", Kind: "FlowSchema"},
		{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta2", Kind: "PriorityLevelConfiguration"},
	}
}

// zero zeros the value of a pointer.
func zero(x interface{}) {
	if x == nil {
		return
	}
	res := reflect.ValueOf(x).Elem()
	res.Set(reflect.Zero(res.Type()))
}
