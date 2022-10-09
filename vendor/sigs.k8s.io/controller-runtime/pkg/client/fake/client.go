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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/internal/objectutil"
)

type versionedTracker struct {
	testing.ObjectTracker
	scheme *runtime.Scheme
}

type fakeClient struct {
	tracker         versionedTracker
	scheme          *runtime.Scheme
	restMapper      meta.RESTMapper
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
	scheme             *runtime.Scheme
	restMapper         meta.RESTMapper
	initObject         []client.Object
	initLists          []client.ObjectList
	initRuntimeObjects []runtime.Object
	objectTracker      testing.ObjectTracker
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

// Build builds and returns a new fake client.
func (f *ClientBuilder) Build() client.WithWatch {
	if f.scheme == nil {
		f.scheme = scheme.Scheme
	}
	if f.restMapper == nil {
		f.restMapper = meta.NewDefaultRESTMapper([]schema.GroupVersion{})
	}

	var tracker versionedTracker

	if f.objectTracker == nil {
		tracker = versionedTracker{ObjectTracker: testing.NewObjectTracker(f.scheme, scheme.Codecs.UniversalDecoder()), scheme: f.scheme}
	} else {
		tracker = versionedTracker{ObjectTracker: f.objectTracker, scheme: f.scheme}
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
	return &fakeClient{
		tracker:    tracker,
		scheme:     f.scheme,
		restMapper: f.restMapper,
	}
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

// convertFromUnstructuredIfNecessary will convert *unstructured.Unstructured for a GVK that is recocnized
// by the schema into the whatever the schema produces with New() for said GVK.
// This is required because the tracker unconditionally saves on manipulations, but its List() implementation
// tries to assign whatever it finds into a ListType it gets from schema.New() - Thus we have to ensure
// we save as the very same type, otherwise subsequent List requests will fail.
func convertFromUnstructuredIfNecessary(s *runtime.Scheme, o runtime.Object) (runtime.Object, error) {
	u, isUnstructured := o.(*unstructured.Unstructured)
	if !isUnstructured || !s.Recognizes(u.GroupVersionKind()) {
		return o, nil
	}

	typed, err := s.New(u.GroupVersionKind())
	if err != nil {
		return nil, fmt.Errorf("scheme recognizes %s but failed to produce an object for it: %w", u.GroupVersionKind().String(), err)
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

	if _, isUnstructuredList := obj.(*unstructured.UnstructuredList); isUnstructuredList && !c.scheme.Recognizes(gvk) {
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

	if listOpts.LabelSelector != nil {
		objs, err := meta.ExtractList(obj)
		if err != nil {
			return err
		}
		filteredObjs, err := objectutil.FilterWithLabels(objs, listOpts.LabelSelector)
		if err != nil {
			return err
		}
		err = meta.SetList(obj, filteredObjs)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *fakeClient) Scheme() *runtime.Scheme {
	return c.scheme
}

func (c *fakeClient) RESTMapper() meta.RESTMapper {
	return c.restMapper
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
	return c.tracker.Update(gvr, obj, accessor.GetNamespace())
}

func (c *fakeClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
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

	reaction := testing.ObjectReaction(c.tracker)
	handled, o, err := reaction(testing.NewPatchAction(gvr, accessor.GetNamespace(), accessor.GetName(), patch.Type(), data))
	if err != nil {
		return err
	}
	if !handled {
		panic("tracker could not handle patch method")
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

func (c *fakeClient) Status() client.StatusWriter {
	return &fakeStatusWriter{client: c}
}

func (c *fakeClient) deleteObject(gvr schema.GroupVersionResource, accessor metav1.Object) error {
	old, err := c.tracker.Get(gvr, accessor.GetNamespace(), accessor.GetName())
	if err == nil {
		oldAccessor, err := meta.Accessor(old)
		if err == nil {
			if len(oldAccessor.GetFinalizers()) > 0 {
				now := metav1.Now()
				oldAccessor.SetDeletionTimestamp(&now)
				return c.tracker.Update(gvr, old, accessor.GetNamespace())
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

type fakeStatusWriter struct {
	client *fakeClient
}

func (sw *fakeStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	// TODO(droot): This results in full update of the obj (spec + status). Need
	// a way to update status field only.
	return sw.client.Update(ctx, obj, opts...)
}

func (sw *fakeStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	// TODO(droot): This results in full update of the obj (spec + status). Need
	// a way to update status field only.
	return sw.client.Patch(ctx, obj, patch, opts...)
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

// zero zeros the value of a pointer.
func zero(x interface{}) {
	if x == nil {
		return
	}
	res := reflect.ValueOf(x).Elem()
	res.Set(reflect.Zero(res.Type()))
}
