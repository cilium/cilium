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
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	/*
	  Stick with gopkg.in/evanphx/json-patch.v4 here to match
	  upstream Kubernetes code and avoid breaking changes introduced in v5.
	  - Kubernetes itself remains on json-patch v4 to avoid compatibility issues
	    tied to v5’s stricter RFC6902 compliance.
	  - The fake client code is adapted from client-go’s testing fixture, which also
	    relies on json-patch v4.
	  See:
	    https://github.com/kubernetes/kubernetes/pull/91622 (discussion of why K8s
	    stays on v4)
	    https://github.com/kubernetes/kubernetes/pull/120326 (v5.6.0+incompatible
	    missing a critical fix)
	*/

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/managedfields"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/watch"
	clientgoapplyconfigurations "k8s.io/client-go/applyconfigurations"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/internal/field/selector"
	"sigs.k8s.io/controller-runtime/pkg/internal/objectutil"
)

type fakeClient struct {
	// trackerWriteLock must be acquired before writing to
	// the tracker or performing reads that affect a following
	// write.
	trackerWriteLock sync.Mutex
	tracker          versionedTracker

	schemeLock sync.RWMutex
	scheme     *runtime.Scheme

	restMapper            meta.RESTMapper
	withStatusSubresource sets.Set[schema.GroupVersionKind]

	// indexes maps each GroupVersionKind (GVK) to the indexes registered for that GVK.
	// The inner map maps from index name to IndexerFunc.
	indexes map[schema.GroupVersionKind]map[string]client.IndexerFunc
	// indexesLock must be held when accessing indexes.
	indexesLock sync.RWMutex

	returnManagedFields bool
}

var _ client.WithWatch = &fakeClient{}

const (
	maxNameLength          = 63
	randomLength           = 5
	maxGeneratedNameLength = maxNameLength - randomLength

	subResourceScale = "scale"
)

// NewFakeClient creates a new fake client for testing.
// You can choose to initialize it with a slice of runtime.Object.
func NewFakeClient(initObjs ...runtime.Object) client.WithWatch {
	return NewClientBuilder().WithRuntimeObjects(initObjs...).Build()
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
	typeConverters        []managedfields.TypeConverter
	returnManagedFields   bool
	isBuilt               bool

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
// Setting this is incompatible with setting WithTypeConverters, as they are a setting on the
// tracker.
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

// WithTypeConverters sets the type converters for the fake client. The list is ordered and the first
// non-erroring converter is used. A type converter must be provided for all types the client is used
// for, otherwise it will error.
//
// This setting is incompatible with WithObjectTracker, as the type converters are a setting on the tracker.
//
// If unset, this defaults to:
// * clientgoapplyconfigurations.NewTypeConverter(scheme.Scheme),
// * managedfields.NewDeducedTypeConverter(),
//
// Be aware that the behavior of the `NewDeducedTypeConverter` might not match the behavior of the
// Kubernetes APIServer, it is recommended to provide a type converter for your types. TypeConverters
// are generated along with ApplyConfigurations.
func (f *ClientBuilder) WithTypeConverters(typeConverters ...managedfields.TypeConverter) *ClientBuilder {
	f.typeConverters = append(f.typeConverters, typeConverters...)
	return f
}

// WithReturnManagedFields configures the fake client to return managedFields
// on objects.
func (f *ClientBuilder) WithReturnManagedFields() *ClientBuilder {
	f.returnManagedFields = true
	return f
}

// Build builds and returns a new fake client.
func (f *ClientBuilder) Build() client.WithWatch {
	if f.isBuilt {
		panic("Build() must not be called multiple times when creating a ClientBuilder")
	}
	if f.scheme == nil {
		f.scheme = scheme.Scheme
	}
	if f.restMapper == nil {
		f.restMapper = meta.NewDefaultRESTMapper([]schema.GroupVersion{})
	}

	withStatusSubResource := sets.New(inTreeResourcesWithStatus()...)
	for _, o := range f.withStatusSubresource {
		gvk, err := apiutil.GVKForObject(o, f.scheme)
		if err != nil {
			panic(fmt.Errorf("failed to get gvk for object %T: %w", withStatusSubResource, err))
		}
		withStatusSubResource.Insert(gvk)
	}

	if f.objectTracker != nil && len(f.typeConverters) > 0 {
		panic(errors.New("WithObjectTracker and WithTypeConverters are incompatible"))
	}

	var usesFieldManagedObjectTracker bool
	if f.objectTracker == nil {
		if len(f.typeConverters) == 0 {
			// Use corresponding scheme to ensure the converter error
			// for types it can't handle.
			clientGoScheme := runtime.NewScheme()
			if err := scheme.AddToScheme(clientGoScheme); err != nil {
				panic(fmt.Sprintf("failed to construct client-go scheme: %v", err))
			}
			f.typeConverters = []managedfields.TypeConverter{
				clientgoapplyconfigurations.NewTypeConverter(clientGoScheme),
				managedfields.NewDeducedTypeConverter(),
			}
		}
		f.objectTracker = testing.NewFieldManagedObjectTracker(
			f.scheme,
			serializer.NewCodecFactory(f.scheme).UniversalDecoder(),
			multiTypeConverter{upstream: f.typeConverters},
		)
		usesFieldManagedObjectTracker = true
	}
	tracker := versionedTracker{
		upstream:                      f.objectTracker,
		scheme:                        f.scheme,
		withStatusSubresource:         withStatusSubResource,
		usesFieldManagedObjectTracker: usesFieldManagedObjectTracker,
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
		returnManagedFields:   f.returnManagedFields,
	}

	if f.interceptorFuncs != nil {
		result = interceptor.NewClient(result, *f.interceptorFuncs)
	}

	f.isBuilt = true
	return result
}

const trackerAddResourceVersion = "999"

// convertFromUnstructuredIfNecessary will convert runtime.Unstructured for a GVK that is recognized
// by the schema into the whatever the schema produces with New() for said GVK.
// This is required because the tracker unconditionally saves on manipulations, but its List() implementation
// tries to assign whatever it finds into a ListType it gets from schema.New() - Thus we have to ensure
// we save as the very same type, otherwise subsequent List requests will fail.
func convertFromUnstructuredIfNecessary(s *runtime.Scheme, o runtime.Object) (runtime.Object, error) {
	u, isUnstructured := o.(runtime.Unstructured)
	if !isUnstructured {
		return o, nil
	}
	gvk := o.GetObjectKind().GroupVersionKind()
	if !s.Recognizes(gvk) {
		return o, nil
	}

	typed, err := s.New(gvk)
	if err != nil {
		return nil, fmt.Errorf("scheme recognizes %s but failed to produce an object for it: %w", gvk, err)
	}
	if _, isTypedUnstructured := typed.(runtime.Unstructured); isTypedUnstructured {
		return o, nil
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

func (c *fakeClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(obj); err != nil {
		return err
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()
	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}
	o, err := c.tracker.Get(gvr, key.Namespace, key.Name)
	if err != nil {
		return err
	}

	ta, err := meta.TypeAccessor(o)
	if err != nil {
		return err
	}

	// If the final object is unstructuctured, the json
	// representation must contain GVK or the apimachinery
	// json serializer will error out.
	ta.SetAPIVersion(gvk.GroupVersion().String())
	ta.SetKind(gvk.Kind)

	j, err := json.Marshal(o)
	if err != nil {
		return err
	}
	zero(obj)
	if err := json.Unmarshal(j, obj); err != nil {
		return err
	}

	if !c.returnManagedFields {
		obj.SetManagedFields(nil)
	}

	return ensureTypeMeta(obj, gvk)
}

func (c *fakeClient) Watch(ctx context.Context, list client.ObjectList, opts ...client.ListOption) (watch.Interface, error) {
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(list); err != nil {
		return nil, err
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()

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
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(obj); err != nil {
		return err
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()
	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}

	originalGVK := gvk
	gvk.Kind = strings.TrimSuffix(gvk.Kind, "List")
	listGVK := gvk
	listGVK.Kind += "List"

	if _, isUnstructuredList := obj.(runtime.Unstructured); isUnstructuredList && !c.scheme.Recognizes(listGVK) {
		// We need to register the ListKind with UnstructuredList:
		// https://github.com/kubernetes/kubernetes/blob/7b2776b89fb1be28d4e9203bdeec079be903c103/staging/src/k8s.io/client-go/dynamic/fake/simple.go#L44-L51
		c.schemeLock.RUnlock()
		c.schemeLock.Lock()
		c.scheme.AddKnownTypeWithName(gvk.GroupVersion().WithKind(gvk.Kind+"List"), &unstructured.UnstructuredList{})
		c.schemeLock.Unlock()
		c.schemeLock.RLock()
	}

	listOpts := client.ListOptions{}
	listOpts.ApplyOptions(opts)

	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	o, err := c.tracker.List(gvr, gvk, listOpts.Namespace)
	if err != nil {
		return err
	}

	j, err := json.Marshal(o)
	if err != nil {
		return err
	}
	zero(obj)
	if err := ensureTypeMeta(obj, originalGVK); err != nil {
		return err
	}
	objCopy := obj.DeepCopyObject().(client.ObjectList)
	if err := json.Unmarshal(j, objCopy); err != nil {
		return err
	}

	objs, err := meta.ExtractList(objCopy)
	if err != nil {
		return err
	}

	for _, o := range objs {
		if err := ensureTypeMeta(o, gvk); err != nil {
			return err
		}

		if !c.returnManagedFields {
			o.(metav1.Object).SetManagedFields(nil)
		}
	}

	if listOpts.LabelSelector == nil && listOpts.FieldSelector == nil {
		return meta.SetList(obj, objs)
	}

	// If we're here, either a label or field selector are specified (or both), so before we return
	// the list we must filter it. If both selectors are set, they are ANDed.
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
	requiresExact := selector.RequiresExactMatch(fs)
	if !requiresExact {
		return nil, fmt.Errorf(`field selector %s is not in one of the two supported forms "key==val" or "key=val"`, fs)
	}

	c.indexesLock.RLock()
	defer c.indexesLock.RUnlock()
	// Field selection is mimicked via indexes, so there's no sane answer this function can give
	// if there are no indexes registered for the GroupVersionKind of the objects in the list.
	indexes := c.indexes[gvk]
	for _, req := range fs.Requirements() {
		if len(indexes) == 0 || indexes[req.Field] == nil {
			return nil, fmt.Errorf("List on GroupVersionKind %v specifies selector on field %s, but no "+
				"index with name %s has been registered for GroupVersionKind %v", gvk, req.Field, req.Field, gvk)
		}
	}

	filteredList := make([]runtime.Object, 0, len(list))
	for _, obj := range list {
		matches := true
		for _, req := range fs.Requirements() {
			indexExtractor := indexes[req.Field]
			if !c.objMatchesFieldSelector(obj, indexExtractor, req.Value) {
				matches = false
				break
			}
		}
		if matches {
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

	return slices.Contains(extractIndex(obj), val)
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
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(obj); err != nil {
		return err
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()

	createOptions := &client.CreateOptions{}
	createOptions.ApplyOptions(opts)

	if slices.Contains(createOptions.DryRun, metav1.DryRunAll) {
		return nil
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

	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}

	c.trackerWriteLock.Lock()
	defer c.trackerWriteLock.Unlock()

	if err := c.tracker.Create(gvr, obj, accessor.GetNamespace(), *createOptions.AsCreateOptions()); err != nil {
		// The managed fields tracker sets gvk even on errors
		_ = ensureTypeMeta(obj, gvk)
		return err
	}

	if !c.returnManagedFields {
		obj.SetManagedFields(nil)
	}

	return ensureTypeMeta(obj, gvk)
}

func (c *fakeClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(obj); err != nil {
		return err
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()

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

	if slices.Contains(delOptions.DryRun, metav1.DryRunAll) {
		return nil
	}

	c.trackerWriteLock.Lock()
	defer c.trackerWriteLock.Unlock()
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

	return c.deleteObjectLocked(gvr, accessor)
}

func (c *fakeClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(obj); err != nil {
		return err
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()

	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}

	dcOptions := client.DeleteAllOfOptions{}
	dcOptions.ApplyOptions(opts)

	if slices.Contains(dcOptions.DryRun, metav1.DryRunAll) {
		return nil
	}

	c.trackerWriteLock.Lock()
	defer c.trackerWriteLock.Unlock()

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
		err = c.deleteObjectLocked(gvr, accessor)
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
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(obj); err != nil {
		return err
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()

	updateOptions := &client.UpdateOptions{}
	updateOptions.ApplyOptions(opts)

	if slices.Contains(updateOptions.DryRun, metav1.DryRunAll) {
		return nil
	}

	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return err
	}

	c.trackerWriteLock.Lock()
	defer c.trackerWriteLock.Unlock()

	// Retain managed fields
	// We can ignore all errors here since update will fail if we encounter an error.
	obj.SetManagedFields(nil)
	current, _ := c.tracker.Get(gvr, accessor.GetNamespace(), accessor.GetName())
	if currentMetaObj, ok := current.(metav1.Object); ok {
		obj.SetManagedFields(currentMetaObj.GetManagedFields())
	}

	if err := c.tracker.update(gvr, obj, accessor.GetNamespace(), isStatus, false, *updateOptions.AsUpdateOptions()); err != nil {
		return err
	}

	if !c.returnManagedFields {
		obj.SetManagedFields(nil)
	}

	return ensureTypeMeta(obj, gvk)
}

func (c *fakeClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	return c.patch(obj, patch, opts...)
}

func (c *fakeClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	applyOpts := &client.ApplyOptions{}
	applyOpts.ApplyOptions(opts)

	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal apply configuration: %w", err)
	}

	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, u); err != nil {
		return fmt.Errorf("failed to unmarshal apply configuration: %w", err)
	}

	applyPatch := &fakeApplyPatch{}

	patchOpts := &client.PatchOptions{}
	patchOpts.Raw = applyOpts.AsPatchOptions()

	if err := c.patch(u, applyPatch, patchOpts); err != nil {
		return err
	}

	acJSON, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("failed to marshal patched object: %w", err)
	}

	// We have to zero the object in case it contained a status and there is a
	// status subresource. If its the private `unstructuredApplyConfiguration`
	// we can not zero all of it, as that will cause the embedded Unstructured
	// to be nil which then causes a NPD in the json.Unmarshal below.
	switch reflect.TypeOf(obj).String() {
	case "*client.unstructuredApplyConfiguration":
		zero(reflect.ValueOf(obj).Elem().FieldByName("Unstructured").Interface())
	default:
		zero(obj)
	}
	if err := json.Unmarshal(acJSON, obj); err != nil {
		return fmt.Errorf("failed to unmarshal patched object: %w", err)
	}

	return nil
}

type fakeApplyPatch struct{}

func (p *fakeApplyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p *fakeApplyPatch) Data(obj client.Object) ([]byte, error) {
	return json.Marshal(obj)
}

func (c *fakeClient) patch(obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := c.addToSchemeIfUnknownAndUnstructuredOrPartial(obj); err != nil {
		return err
	}

	patchOptions := &client.PatchOptions{}
	patchOptions.ApplyOptions(opts)

	if errs := validation.ValidatePatchOptions(patchOptions.AsPatchOptions(), patch.Type()); len(errs) > 0 {
		return apierrors.NewInvalid(schema.GroupKind{Group: "meta.k8s.io", Kind: "PatchOptions"}, "", errs)
	}

	c.schemeLock.RLock()
	defer c.schemeLock.RUnlock()

	if slices.Contains(patchOptions.DryRun, metav1.DryRunAll) {
		return nil
	}

	gvr, err := getGVRFromObject(obj, c.scheme)
	if err != nil {
		return err
	}
	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}
	accessor, err := meta.Accessor(obj)
	if err != nil {
		return err
	}

	var isApplyCreate bool
	c.trackerWriteLock.Lock()
	defer c.trackerWriteLock.Unlock()
	oldObj, err := c.tracker.Get(gvr, accessor.GetNamespace(), accessor.GetName())
	if err != nil {
		if !apierrors.IsNotFound(err) || patch.Type() != types.ApplyPatchType {
			return err
		}
		oldObj = &unstructured.Unstructured{}
		isApplyCreate = true
	}
	oldAccessor, err := meta.Accessor(oldObj)
	if err != nil {
		return err
	}

	if patch.Type() == types.ApplyPatchType {
		if isApplyCreate {
			// Overwrite it unconditionally, this matches the apiserver behavior
			// which allows to set it on create, but will then ignore it.
			obj.SetResourceVersion("1")
		} else {
			// SSA deletionTimestamp updates are silently ignored
			obj.SetDeletionTimestamp(oldAccessor.GetDeletionTimestamp())
		}
	}

	data, err := patch.Data(obj)
	if err != nil {
		return err
	}

	action := testing.NewPatchActionWithOptions(
		gvr,
		accessor.GetNamespace(),
		accessor.GetName(),
		patch.Type(),
		data,
		*patchOptions.AsPatchOptions(),
	)

	// Apply is implemented in the tracker and calling it has side-effects
	// such as bumping RV and updating managedFields timestamps, hence we
	// can not dry-run it. Luckily, the only validation we use it for
	// doesn't apply to SSA - Creating objects with non-nil deletionTimestamp
	// through SSA is possible and updating the deletionTimestamp is valid,
	// but has no effect.
	if patch.Type() != types.ApplyPatchType {
		// Apply patch without updating object.
		// To remain in accordance with the behavior of k8s api behavior,
		// a patch must not allow for changes to the deletionTimestamp of an object.
		// The reaction() function applies the patch to the object and calls Update(),
		// whereas dryPatch() replicates this behavior but skips the call to Update().
		// This ensures that the patch may be rejected if a deletionTimestamp is modified, prior
		// to updating the object.
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
	}

	reaction := testing.ObjectReaction(c.tracker)
	handled, o, err := reaction(action)
	if err != nil {
		// The reaction calls tracker.Get after tracker.Apply to return the object,
		// but we may have deleted it in tracker.Apply if there was no finalizer
		// left.
		if apierrors.IsNotFound(err) &&
			patch.Type() == types.ApplyPatchType &&
			oldAccessor.GetDeletionTimestamp() != nil &&
			len(obj.GetFinalizers()) == 0 {
			return nil
		}
		return err
	}
	if !handled {
		panic("tracker could not handle patch method")
	}

	ta, err := meta.TypeAccessor(o)
	if err != nil {
		return err
	}

	ta.SetAPIVersion(gvk.GroupVersion().String())
	ta.SetKind(gvk.Kind)

	j, err := json.Marshal(o)
	if err != nil {
		return err
	}
	zero(obj)
	if err := json.Unmarshal(j, obj); err != nil {
		return err
	}

	if !c.returnManagedFields {
		obj.SetManagedFields(nil)
	}

	return ensureTypeMeta(obj, gvk)
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
		if apierrors.IsNotFound(err) && action.GetPatchType() == types.ApplyPatchType {
			return &unstructured.Unstructured{}, nil
		}
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
	case types.StrategicMergePatchType:
		mergedByte, err := strategicpatch.StrategicMergePatch(old, action.GetPatch(), obj)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(mergedByte, obj); err != nil {
			return nil, err
		}
	case types.ApplyCBORPatchType:
		return nil, errors.New("apply CBOR patches are not supported in the fake client")
	case types.ApplyPatchType:
		return nil, errors.New("bug in controller-runtime: should not end up in dryPatch for SSA")
	default:
		return nil, fmt.Errorf("%s PatchType is not supported", action.GetPatchType())
	}
	return obj, nil
}

// copyStatusFrom copies the status from old into new
func copyStatusFrom(old, n runtime.Object) error {
	oldMapStringAny, err := toMapStringAny(old)
	if err != nil {
		return fmt.Errorf("failed to convert old to *unstructured.Unstructured: %w", err)
	}
	newMapStringAny, err := toMapStringAny(n)
	if err != nil {
		return fmt.Errorf("failed to convert new to *unststructured.Unstructured: %w", err)
	}

	newMapStringAny["status"] = oldMapStringAny["status"]

	if err := fromMapStringAny(newMapStringAny, n); err != nil {
		return fmt.Errorf("failed to convert back from map[string]any: %w", err)
	}

	return nil
}

// copyFrom copies from old into new
func copyFrom(old, n runtime.Object) error {
	oldMapStringAny, err := toMapStringAny(old)
	if err != nil {
		return fmt.Errorf("failed to convert old to *unstructured.Unstructured: %w", err)
	}
	if err := fromMapStringAny(oldMapStringAny, n); err != nil {
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

	zero(target)
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

func (c *fakeClient) deleteObjectLocked(gvr schema.GroupVersionResource, accessor metav1.Object) error {
	old, err := c.tracker.Get(gvr, accessor.GetNamespace(), accessor.GetName())
	if err == nil {
		oldAccessor, err := meta.Accessor(old)
		if err == nil {
			if len(oldAccessor.GetFinalizers()) > 0 {
				now := metav1.Now()
				oldAccessor.SetDeletionTimestamp(&now)
				// Call update directly with mutability parameter set to true to allow
				// changes to deletionTimestamp
				return c.tracker.update(gvr, old, accessor.GetNamespace(), false, true, metav1.UpdateOptions{})
			}
		}
	}

	// TODO: implement propagation
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
	switch sw.subResource {
	case subResourceScale:
		// Actual client looks up resource, then extracts the scale sub-resource:
		// https://github.com/kubernetes/kubernetes/blob/fb6bbc9781d11a87688c398778525c4e1dcb0f08/pkg/registry/apps/deployment/storage/storage.go#L307
		if err := sw.client.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
			return err
		}
		scale, isScale := subResource.(*autoscalingv1.Scale)
		if !isScale {
			return apierrors.NewBadRequest(fmt.Sprintf("expected Scale, got %T", subResource))
		}
		scaleOut, err := extractScale(obj)
		if err != nil {
			return err
		}
		*scale = *scaleOut
		return nil
	default:
		return fmt.Errorf("fakeSubResourceClient does not support get for %s", sw.subResource)
	}
}

func (sw *fakeSubResourceClient) Create(ctx context.Context, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
	switch sw.subResource {
	case "eviction":
		_, isEviction := subResource.(*policyv1beta1.Eviction)
		if !isEviction {
			_, isEviction = subResource.(*policyv1.Eviction)
		}
		if !isEviction {
			return apierrors.NewBadRequest(fmt.Sprintf("got invalid type %T, expected Eviction", subResource))
		}
		if _, isPod := obj.(*corev1.Pod); !isPod {
			return apierrors.NewNotFound(schema.GroupResource{}, "")
		}

		return sw.client.Delete(ctx, obj)
	case "token":
		tokenRequest, isTokenRequest := subResource.(*authenticationv1.TokenRequest)
		if !isTokenRequest {
			return apierrors.NewBadRequest(fmt.Sprintf("got invalid type %T, expected TokenRequest", subResource))
		}
		if _, isServiceAccount := obj.(*corev1.ServiceAccount); !isServiceAccount {
			return apierrors.NewNotFound(schema.GroupResource{}, "")
		}

		tokenRequest.Status.Token = "fake-token"
		tokenRequest.Status.ExpirationTimestamp = metav1.Date(6041, 1, 1, 0, 0, 0, 0, time.UTC)

		return sw.client.Get(ctx, client.ObjectKeyFromObject(obj), obj)
	default:
		return fmt.Errorf("fakeSubResourceWriter does not support create for %s", sw.subResource)
	}
}

func (sw *fakeSubResourceClient) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	updateOptions := client.SubResourceUpdateOptions{}
	updateOptions.ApplyOptions(opts)

	switch sw.subResource {
	case subResourceScale:
		if err := sw.client.Get(ctx, client.ObjectKeyFromObject(obj), obj.DeepCopyObject().(client.Object)); err != nil {
			return err
		}
		if updateOptions.SubResourceBody == nil {
			return apierrors.NewBadRequest("missing SubResourceBody")
		}

		scale, isScale := updateOptions.SubResourceBody.(*autoscalingv1.Scale)
		if !isScale {
			return apierrors.NewBadRequest(fmt.Sprintf("expected Scale, got %T", updateOptions.SubResourceBody))
		}
		if err := applyScale(obj, scale); err != nil {
			return err
		}
		return sw.client.update(obj, false, &updateOptions.UpdateOptions)
	default:
		body := obj
		if updateOptions.SubResourceBody != nil {
			body = updateOptions.SubResourceBody
		}
		return sw.client.update(body, true, &updateOptions.UpdateOptions)
	}
}

func (sw *fakeSubResourceClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	patchOptions := client.SubResourcePatchOptions{}
	patchOptions.ApplyOptions(opts)

	body := obj
	if patchOptions.SubResourceBody != nil {
		body = patchOptions.SubResourceBody
	}

	// this is necessary to identify that last call was made for status patch, through stack trace.
	if sw.subResource == "status" {
		return sw.statusPatch(body, patch, patchOptions)
	}

	return sw.client.patch(body, patch, &patchOptions.PatchOptions)
}

func (sw *fakeSubResourceClient) statusPatch(body client.Object, patch client.Patch, patchOptions client.SubResourcePatchOptions) error {
	return sw.client.patch(body, patch, &patchOptions.PatchOptions)
}

func (sw *fakeSubResourceClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	if sw.subResource != "status" {
		return errors.New("fakeSubResourceClient currently only supports Apply for status subresource")
	}

	applyOpts := &client.SubResourceApplyOptions{}
	applyOpts.ApplyOpts(opts)

	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal apply configuration: %w", err)
	}

	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, u); err != nil {
		return fmt.Errorf("failed to unmarshal apply configuration: %w", err)
	}

	patchOpts := &client.SubResourcePatchOptions{}
	patchOpts.Raw = applyOpts.AsPatchOptions()

	if applyOpts.SubResourceBody != nil {
		subResourceBodySerialized, err := json.Marshal(applyOpts.SubResourceBody)
		if err != nil {
			return fmt.Errorf("failed to serialize subresource body: %w", err)
		}
		subResourceBody := &unstructured.Unstructured{}
		if err := json.Unmarshal(subResourceBodySerialized, subResourceBody); err != nil {
			return fmt.Errorf("failed to unmarshal subresource body: %w", err)
		}
		patchOpts.SubResourceBody = subResourceBody
	}

	return sw.Patch(ctx, u, &fakeApplyPatch{}, patchOpts)
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
	case "rbac.authorization.k8s.io":
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
		{Group: "flowcontrol.apiserver.k8s.io", Version: "v1", Kind: "FlowSchema"},
		{Group: "flowcontrol.apiserver.k8s.io", Version: "v1", Kind: "PriorityLevelConfiguration"},
	}
}

// zero zeros the value of a pointer.
func zero(x any) {
	if x == nil {
		return
	}
	res := reflect.ValueOf(x).Elem()
	res.Set(reflect.Zero(res.Type()))
}

// getSingleOrZeroOptions returns the single options value in the slice, its
// zero value if the slice is empty, or an error if the slice contains more than
// one option value.
func getSingleOrZeroOptions[T any](opts []T) (opt T, err error) {
	switch len(opts) {
	case 0:
	case 1:
		opt = opts[0]
	default:
		err = fmt.Errorf("expected single or no options value, got %d values", len(opts))
	}
	return
}

func extractScale(obj client.Object) (*autoscalingv1.Scale, error) {
	switch obj := obj.(type) {
	case *appsv1.Deployment:
		var replicas int32 = 1
		if obj.Spec.Replicas != nil {
			replicas = *obj.Spec.Replicas
		}
		var selector string
		if obj.Spec.Selector != nil {
			selector = obj.Spec.Selector.String()
		}
		return &autoscalingv1.Scale{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         obj.Namespace,
				Name:              obj.Name,
				UID:               obj.UID,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp,
			},
			Spec: autoscalingv1.ScaleSpec{
				Replicas: replicas,
			},
			Status: autoscalingv1.ScaleStatus{
				Replicas: obj.Status.Replicas,
				Selector: selector,
			},
		}, nil
	case *appsv1.ReplicaSet:
		var replicas int32 = 1
		if obj.Spec.Replicas != nil {
			replicas = *obj.Spec.Replicas
		}
		var selector string
		if obj.Spec.Selector != nil {
			selector = obj.Spec.Selector.String()
		}
		return &autoscalingv1.Scale{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         obj.Namespace,
				Name:              obj.Name,
				UID:               obj.UID,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp,
			},
			Spec: autoscalingv1.ScaleSpec{
				Replicas: replicas,
			},
			Status: autoscalingv1.ScaleStatus{
				Replicas: obj.Status.Replicas,
				Selector: selector,
			},
		}, nil
	case *corev1.ReplicationController:
		var replicas int32 = 1
		if obj.Spec.Replicas != nil {
			replicas = *obj.Spec.Replicas
		}
		return &autoscalingv1.Scale{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         obj.Namespace,
				Name:              obj.Name,
				UID:               obj.UID,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp,
			},
			Spec: autoscalingv1.ScaleSpec{
				Replicas: replicas,
			},
			Status: autoscalingv1.ScaleStatus{
				Replicas: obj.Status.Replicas,
				Selector: labels.Set(obj.Spec.Selector).String(),
			},
		}, nil
	case *appsv1.StatefulSet:
		var replicas int32 = 1
		if obj.Spec.Replicas != nil {
			replicas = *obj.Spec.Replicas
		}
		var selector string
		if obj.Spec.Selector != nil {
			selector = obj.Spec.Selector.String()
		}
		return &autoscalingv1.Scale{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         obj.Namespace,
				Name:              obj.Name,
				UID:               obj.UID,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp,
			},
			Spec: autoscalingv1.ScaleSpec{
				Replicas: replicas,
			},
			Status: autoscalingv1.ScaleStatus{
				Replicas: obj.Status.Replicas,
				Selector: selector,
			},
		}, nil
	default:
		// TODO: CRDs https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#scale-subresource
		return nil, fmt.Errorf("unimplemented scale subresource for resource %T", obj)
	}
}

func applyScale(obj client.Object, scale *autoscalingv1.Scale) error {
	switch obj := obj.(type) {
	case *appsv1.Deployment:
		obj.Spec.Replicas = ptr.To(scale.Spec.Replicas)
	case *appsv1.ReplicaSet:
		obj.Spec.Replicas = ptr.To(scale.Spec.Replicas)
	case *corev1.ReplicationController:
		obj.Spec.Replicas = ptr.To(scale.Spec.Replicas)
	case *appsv1.StatefulSet:
		obj.Spec.Replicas = ptr.To(scale.Spec.Replicas)
	default:
		// TODO: CRDs https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#scale-subresource
		return fmt.Errorf("unimplemented scale subresource for resource %T", obj)
	}
	return nil
}

// AddIndex adds an index to a fake client. It will panic if used with a client that is not a fake client.
// It will error if there is already an index for given object with the same name as field.
//
// It can be used to test code that adds indexes to the cache at runtime.
func AddIndex(c client.Client, obj runtime.Object, field string, extractValue client.IndexerFunc) error {
	fakeClient, isFakeClient := c.(*fakeClient)
	if !isFakeClient {
		panic("AddIndex can only be used with a fake client")
	}
	fakeClient.indexesLock.Lock()
	defer fakeClient.indexesLock.Unlock()

	if fakeClient.indexes == nil {
		fakeClient.indexes = make(map[schema.GroupVersionKind]map[string]client.IndexerFunc, 1)
	}

	gvk, err := apiutil.GVKForObject(obj, fakeClient.scheme)
	if err != nil {
		return fmt.Errorf("failed to get gvk for %T: %w", obj, err)
	}

	if fakeClient.indexes[gvk] == nil {
		fakeClient.indexes[gvk] = make(map[string]client.IndexerFunc, 1)
	}

	if fakeClient.indexes[gvk][field] != nil {
		return fmt.Errorf("index %s already exists", field)
	}

	fakeClient.indexes[gvk][field] = extractValue

	return nil
}

func (c *fakeClient) addToSchemeIfUnknownAndUnstructuredOrPartial(obj runtime.Object) error {
	c.schemeLock.Lock()
	defer c.schemeLock.Unlock()

	_, isUnstructured := obj.(*unstructured.Unstructured)
	_, isUnstructuredList := obj.(*unstructured.UnstructuredList)
	_, isPartial := obj.(*metav1.PartialObjectMetadata)
	_, isPartialList := obj.(*metav1.PartialObjectMetadataList)
	if !isUnstructured && !isUnstructuredList && !isPartial && !isPartialList {
		return nil
	}

	gvk, err := apiutil.GVKForObject(obj, c.scheme)
	if err != nil {
		return err
	}

	if isUnstructuredList || isPartialList {
		if !strings.HasSuffix(gvk.Kind, "List") {
			gvk.Kind += "List"
		}
	}

	if !c.scheme.Recognizes(gvk) {
		c.scheme.AddKnownTypeWithName(gvk, obj)
	}

	return nil
}

func ensureTypeMeta(obj runtime.Object, gvk schema.GroupVersionKind) error {
	ta, err := meta.TypeAccessor(obj)
	if err != nil {
		return err
	}
	_, isUnstructured := obj.(runtime.Unstructured)
	_, isPartialObject := obj.(*metav1.PartialObjectMetadata)
	_, isPartialObjectList := obj.(*metav1.PartialObjectMetadataList)
	if !isUnstructured && !isPartialObject && !isPartialObjectList {
		ta.SetKind("")
		ta.SetAPIVersion("")
		return nil
	}

	ta.SetKind(gvk.Kind)
	ta.SetAPIVersion(gvk.GroupVersion().String())

	return nil
}
