/*
Copyright The Kubernetes Authors.

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

package client

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache/cacheapi"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/internal/consistencyhandler"
	"sigs.k8s.io/controller-runtime/pkg/client/internal/writebarrier"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	consistencyClientWaitDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:                            "controller_runtime_client_consistency_wait_duration_seconds",
			Help:                            "Length of time waiting for the cache to observe writes before serving reads.",
			Buckets:                         []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 6, 8, 10},
			NativeHistogramBucketFactor:     1.1,
			NativeHistogramMaxBucketNumber:  100,
			NativeHistogramMinResetDuration: 1 * time.Hour,
		},
		[]string{"operation", "result"},
	)
)

func init() {
	crmetrics.Registry.MustRegister(
		consistencyClientWaitDuration,
	)
}

type consistentClientUpstream interface {
	Client

	delete(ctx context.Context, obj Object, opts ...DeleteOption) (*unstructured.Unstructured, error)
}

var _ Client = (*consistentClient)(nil)

func newConsistentClient(
	upstream consistentClientUpstream,
	informers cacheapi.Informers,
	newWriteBarrier func() writebarrier.WriteBarrier,
	log logr.Logger,
) *consistentClient {
	return &consistentClient{
		upstream:  upstream,
		informers: informers,
		writeBarriers: newThreadSafeMap[gvkAndRepresentation](func() writebarrier.WriteBarriers {
			return writebarrier.NewWriteBarriers(newWriteBarrier)
		}),
		consistencyHandlers: newThreadSafeMap[gvkAndRepresentation](func() *consistencyhandler.ConsistencyHandler {
			return consistencyhandler.NewHandler(log)
		}),
	}
}

type consistentClient struct {
	upstream  consistentClientUpstream
	informers cacheapi.Informers

	writeBarriers *threadSafeMap[gvkAndRepresentation, writebarrier.WriteBarriers]

	consistencyHandlers *threadSafeMap[gvkAndRepresentation, *consistencyhandler.ConsistencyHandler]
}

type gvkAndRepresentation struct {
	gvk            schema.GroupVersionKind
	representation representationID
}

func representationIDForObj(obj any) representationID {
	switch obj.(type) {
	case *unstructured.Unstructured, *unstructured.UnstructuredList:
		return representationIDUnstructured
	case *metav1.PartialObjectMetadata, *metav1.PartialObjectMetadataList:
		return representationIDPartialObjectMetadata
	default:
		return representationIDTyped
	}
}

type representationID int8

const (
	representationIDUnstructured representationID = iota
	representationIDPartialObjectMetadata
	representationIDTyped
)

func (c *consistentClient) getConsistencyHandler(
	ctx context.Context,
	gvkAndRepresentation gvkAndRepresentation,
	obj Object,
) (*consistencyhandler.ConsistencyHandler, error) {
	h := c.consistencyHandlers.getOrCreate(gvkAndRepresentation)
	if h.Registered() {
		return h, nil
	}

	informer, err := c.informers.GetInformer(ctx, obj, cacheapi.BlockUntilSynced(true))
	if err != nil {
		return nil, fmt.Errorf("failed to get informer for GVK %s: %w", gvkAndRepresentation.gvk, err)
	}

	if err := h.Register(ctx, informer); err != nil {
		return nil, fmt.Errorf("failed to register consistency handler on informer for GVK %s: %w", gvkAndRepresentation.gvk, err)
	}
	return h, nil
}

const consistencyClientWaitDurationResultSuccess = "success"

func consistencyClientWaitDurationResult(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case err != nil:
		return "error"
	default:
		return consistencyClientWaitDurationResultSuccess
	}
}

func (c *consistentClient) Get(ctx context.Context, key ObjectKey, obj Object, opts ...GetOption) (err error) {
	if (&GetOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency {
		return c.upstream.Get(ctx, key, obj, opts...)
	}

	start := time.Now()
	var waitDuration time.Duration
	var result string
	defer func() {
		if waitDuration == 0 {
			waitDuration = time.Since(start)
		}
		if result == "" {
			result = consistencyClientWaitDurationResult(err)
		}
		consistencyClientWaitDuration.
			WithLabelValues("get", result).
			Observe(waitDuration.Seconds())
	}()

	gvk, err := apiutil.GVKForObject(obj, c.upstream.Scheme())
	if err != nil {
		return fmt.Errorf("failed to get GVK for object %T: %w", obj, err)
	}
	gvkAndRepresentation := gvkAndRepresentation{gvk: gvk, representation: representationIDForObj(obj)}

	select {
	case <-c.writeBarriers.getOrCreate(gvkAndRepresentation).Seal(key):
	case <-ctx.Done():
		return ctx.Err()
	}

	h, err := c.getConsistencyHandler(ctx, gvkAndRepresentation, obj)
	if err != nil {
		return err
	}
	if err := h.WaitForGet(ctx, key); err != nil {
		return fmt.Errorf("failed to wait for cache to catch up: %w", err)
	}

	waitDuration = time.Since(start)
	result = consistencyClientWaitDurationResultSuccess
	return c.upstream.Get(ctx, key, obj, opts...)
}

func (c *consistentClient) List(ctx context.Context, list ObjectList, opts ...ListOption) (err error) {
	if (&ListOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency {
		return c.upstream.List(ctx, list, opts...)
	}

	start := time.Now()
	var waitDuration time.Duration
	var result string
	defer func() {
		if waitDuration == 0 {
			waitDuration = time.Since(start)
		}
		if result == "" {
			result = consistencyClientWaitDurationResult(err)
		}
		consistencyClientWaitDuration.
			WithLabelValues("list", result).
			Observe(waitDuration.Seconds())
	}()

	gvk, err := apiutil.GVKForObject(list, c.upstream.Scheme())
	if err != nil {
		return fmt.Errorf("failed to get GVK for list %T: %w", list, err)
	}
	gvk.Kind = strings.TrimSuffix(gvk.Kind, "List")
	gvkAndRepresentation := gvkAndRepresentation{gvk: gvk, representation: representationIDForObj(list)}

	for _, s := range c.writeBarriers.getOrCreate(gvkAndRepresentation).SealAll() {
		select {
		case <-s:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	var obj Object
	switch gvkAndRepresentation.representation {
	case representationIDUnstructured:
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(gvk)
		obj = u
	case representationIDPartialObjectMetadata:
		m := &metav1.PartialObjectMetadata{}
		m.SetGroupVersionKind(gvk)
		obj = m
	case representationIDTyped:
		raw, err := c.upstream.Scheme().New(gvk)
		if err != nil {
			return fmt.Errorf("failed to create object for GVK %s: %w", gvk, err)
		}
		asserted, ok := raw.(Object)
		if !ok {
			return fmt.Errorf("object of type %T for GVK %s does not implement Object", raw, gvk)
		}
		obj = asserted
	}

	h, err := c.getConsistencyHandler(ctx, gvkAndRepresentation, obj)
	if err != nil {
		return err
	}
	if err := h.WaitForList(ctx); err != nil {
		return fmt.Errorf("failed to wait for cache to catch up: %w", err)
	}

	waitDuration = time.Since(start)
	result = consistencyClientWaitDurationResultSuccess
	return c.upstream.List(ctx, list, opts...)
}

func (c *consistentClient) Create(ctx context.Context, obj Object, opts ...CreateOption) error {
	return c.writeAndRecordRV(ctx, obj, (&CreateOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency, func() error {
		return c.upstream.Create(ctx, obj, opts...)
	})
}

func (c *consistentClient) Update(ctx context.Context, obj Object, opts ...UpdateOption) error {
	return c.writeAndRecordRV(ctx, obj, (&UpdateOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency, func() error {
		return c.upstream.Update(ctx, obj, opts...)
	})
}

func (c *consistentClient) Patch(ctx context.Context, obj Object, patch Patch, opts ...PatchOption) error {
	return c.writeAndRecordRV(ctx, obj, (&PatchOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency, func() error {
		return c.upstream.Patch(ctx, obj, patch, opts...)
	})
}

func (c *consistentClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...ApplyOption) error {
	return c.writeAndRecordRV(ctx, obj, (&ApplyOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency, func() error {
		return c.upstream.Apply(ctx, obj, opts...)
	})
}

func writeTargetFor(obj any, scheme *runtime.Scheme) (gvkAndRepresentation, types.NamespacedName, Object, func() (string, error), error) {
	switch t := obj.(type) {
	case *unstructuredApplyConfiguration:
		return gvkAndRepresentation{gvk: t.Unstructured.GroupVersionKind(), representation: representationIDUnstructured},
			ObjectKeyFromObject(t),
			t.Unstructured,
			func() (string, error) { return t.Unstructured.GetResourceVersion(), nil },
			nil
	case applyConfiguration:
		gvk, err := gvkFromApplyConfiguration(t)
		if err != nil {
			return gvkAndRepresentation{}, types.NamespacedName{}, nil, nil, fmt.Errorf("failed to get GVK for apply configuration %T: %w", obj, err)
		}
		cacheObj, err := scheme.New(gvk)
		if err != nil {
			return gvkAndRepresentation{}, types.NamespacedName{}, nil, nil, fmt.Errorf("failed to create object for GVK %s: %w", gvk, err)
		}
		clientObj, ok := cacheObj.(Object)
		if !ok {
			return gvkAndRepresentation{}, types.NamespacedName{}, nil, nil, fmt.Errorf("object of type %T for GVK %s does not implement client.Object", cacheObj, gvk)
		}
		clientObj.SetName(ptr.Deref(t.GetName(), ""))
		clientObj.SetNamespace(ptr.Deref(t.GetNamespace(), ""))
		return gvkAndRepresentation{gvk: gvk, representation: representationIDTyped},
			ObjectKeyFromObject(clientObj),
			clientObj,
			func() (string, error) { return resourceVersionFromApplyConfiguration(t) },
			nil
	case *metav1.PartialObjectMetadata:
		return gvkAndRepresentation{gvk: t.GroupVersionKind(), representation: representationIDPartialObjectMetadata},
			ObjectKeyFromObject(t),
			t,
			func() (string, error) { return t.GetResourceVersion(), nil },
			nil
	case Object:
		gvk, err := apiutil.GVKForObject(t, scheme)
		if err != nil {
			return gvkAndRepresentation{}, types.NamespacedName{}, nil, nil, fmt.Errorf("failed to get GVK for object %T: %w", obj, err)
		}
		return gvkAndRepresentation{gvk: gvk, representation: representationIDTyped},
			ObjectKeyFromObject(t),
			t,
			func() (string, error) { return t.GetResourceVersion(), nil },
			nil
	default:
		return gvkAndRepresentation{}, types.NamespacedName{}, nil, nil, fmt.Errorf("unsupported type %T, must be either %T, %T or %T", obj, Object(nil), &unstructuredApplyConfiguration{}, applyConfiguration(nil))
	}
}

func (c *consistentClient) writeAndRecordRV(ctx context.Context, obj any, disableConsistency bool, write func() error) error {
	if disableConsistency {
		return write()
	}

	gvkAndRepresentation, namespacedName, cacheObj, getResourceVersion, err := writeTargetFor(obj, c.upstream.Scheme())
	if err != nil {
		return err
	}

	// We don't technically need an informer since the RV is monotonically increasing, but we want to fail
	// ASAP if the cache can not be setup.
	h, err := c.getConsistencyHandler(ctx, gvkAndRepresentation, cacheObj)
	if err != nil {
		return err
	}

	release := c.writeBarriers.getOrCreate(gvkAndRepresentation).Begin(namespacedName)
	defer release()

	if err := write(); err != nil {
		return err
	}

	rvRaw, err := getResourceVersion()
	if err != nil {
		return fmt.Errorf("failed to get resource version from %T: %w", obj, err)
	}
	rv, err := strconv.ParseInt(rvRaw, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse resource version %s: %w", rvRaw, err)
	}

	h.SetMinimumRV(ObjectKeyFromObject(cacheObj), rv)

	return nil
}

func resourceVersionFromApplyConfiguration(obj applyConfiguration) (string, error) {
	v := reflect.ValueOf(obj)
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return "", fmt.Errorf("expected struct, got %s", v.Kind())
	}
	rv := v.FieldByName("ResourceVersion")
	if !rv.IsValid() {
		return "", fmt.Errorf("type %T has no ResourceVersion field", obj)
	}
	if rv.Kind() != reflect.Pointer || rv.Type().Elem().Kind() != reflect.String {
		return "", fmt.Errorf("ResourceVersion field in %T is not *string", obj)
	}
	if rv.IsNil() {
		return "", fmt.Errorf("ResourceVersion field in %T is nil", obj)
	}
	return rv.Elem().String(), nil
}

func (c *consistentClient) Delete(ctx context.Context, obj Object, opts ...DeleteOption) error {
	if (&DeleteOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency {
		return c.upstream.Delete(ctx, obj, opts...)
	}

	gvk, err := apiutil.GVKForObject(obj, c.upstream.Scheme())
	if err != nil {
		return fmt.Errorf("failed to get GVK for object %v: %w", obj, err)
	}

	gvkAndRepresentation := gvkAndRepresentation{gvk: gvk, representation: representationIDForObj(obj)}
	h, err := c.getConsistencyHandler(ctx, gvkAndRepresentation, obj)
	if err != nil {
		return err
	}

	namespacedName := ObjectKeyFromObject(obj)
	uid, err := c.uidForDelete(ctx, gvk, namespacedName, obj, opts...)
	if err != nil {
		return err
	}

	release := c.writeBarriers.getOrCreate(gvkAndRepresentation).Begin(namespacedName)
	defer release()

	// Register the delete before we execute it, otherwise it may be in the cache
	// before we register it, causing a deadlock.
	h.AddPendingDelete(namespacedName, uid)

	response, err := c.upstream.delete(ctx, obj, opts...)
	if err != nil {
		h.RemovePendingDelete(namespacedName, uid)
		return err
	}

	// Prefer waiting for the RV rather than an actual event since that is likely to be more resilient.
	// This can only work if the response contains the RV which in turn only happens if the request did
	// not delete the object from storage, for example because it had a finalizer.
	if rvRaw := response.GetResourceVersion(); rvRaw != "" {
		rv, err := strconv.ParseInt(rvRaw, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse resource version %s: %w", rvRaw, err)
		}
		h.RemovePendingDelete(namespacedName, uid)
		h.SetMinimumRV(namespacedName, rv)
	}

	return nil
}

func (c *consistentClient) uidForDelete(ctx context.Context, gvk schema.GroupVersionKind, key ObjectKey, obj Object, opts ...DeleteOption) (types.UID, error) {
	deleteOptions := (&DeleteOptions{}).ApplyOptions(opts)
	if p := deleteOptions.Preconditions; p != nil && ptr.Deref(p.UID, "") != "" {
		return *p.UID, nil
	}

	if uid := obj.GetUID(); uid != "" {
		return uid, nil
	}

	existing, ok := obj.DeepCopyObject().(Object)
	if !ok {
		return "", fmt.Errorf("deepcopy of %T does not implement client.Object", obj)
	}
	if err := c.upstream.Get(ctx, key, existing); err != nil {
		return "", fmt.Errorf("failed to get %s %s to determine its uid: %w", gvk.Kind, key, err)
	}

	return existing.GetUID(), nil
}

func (c *consistentClient) DeleteAllOf(ctx context.Context, obj Object, opts ...DeleteAllOfOption) error {
	return errors.New("DeleteAllOf is not supported by consistentClient, please use List and Delete instead")
}

func (c *consistentClient) Status() SubResourceWriter {
	return c.SubResource("status")
}

func (c *consistentClient) Scheme() *runtime.Scheme {
	return c.upstream.Scheme()
}

func (c *consistentClient) RESTMapper() meta.RESTMapper {
	return c.upstream.RESTMapper()
}

func (c *consistentClient) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return c.upstream.GroupVersionKindFor(obj)
}

func (c *consistentClient) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return c.upstream.IsObjectNamespaced(obj)
}

func (c *consistentClient) SubResource(subResource string) SubResourceClient {
	return &consistentSubResourceClient{
		writeAndRecordRV: c.writeAndRecordRV,
		upstream:         c.upstream.SubResource(subResource),
	}
}

type consistentSubResourceClient struct {
	writeAndRecordRV func(ctx context.Context, obj any, disableConsistency bool, write func() error) error
	upstream         SubResourceClient
}

func (c *consistentSubResourceClient) Get(ctx context.Context, obj, subResource Object, opts ...SubResourceGetOption) error {
	return c.upstream.Get(ctx, obj, subResource, opts...)
}

// Create is excluded from read-your-writes consistency, because it either returns a
// status with no RV (pod/eviction, pod/binding) or a virtual resource that is not
// persisted (serviceaccount/token).
func (c *consistentSubResourceClient) Create(ctx context.Context, obj, subResource Object, opts ...SubResourceCreateOption) error {
	return c.upstream.Create(ctx, obj, subResource, opts...)
}

func (c *consistentSubResourceClient) Update(ctx context.Context, obj Object, opts ...SubResourceUpdateOption) error {
	return c.writeAndRecordRV(ctx, obj, (&SubResourceUpdateOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency, func() error {
		return c.upstream.Update(ctx, obj, opts...)
	})
}

func (c *consistentSubResourceClient) Patch(ctx context.Context, obj Object, patch Patch, opts ...SubResourcePatchOption) error {
	return c.writeAndRecordRV(ctx, obj, (&SubResourcePatchOptions{}).ApplyOptions(opts).DisableReadYourWritesConsistency, func() error {
		return c.upstream.Patch(ctx, obj, patch, opts...)
	})
}

func (c *consistentSubResourceClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...SubResourceApplyOption) error {
	return c.writeAndRecordRV(ctx, obj, (&SubResourceApplyOptions{}).ApplyOpts(opts).DisableReadYourWritesConsistency, func() error {
		return c.upstream.Apply(ctx, obj, opts...)
	})
}

func newThreadSafeMap[k comparable, v any](newValue func() v) *threadSafeMap[k, v] {
	return &threadSafeMap[k, v]{
		data:     map[k]v{},
		newValue: newValue,
	}
}

type threadSafeMap[k comparable, v any] struct {
	lock     sync.Mutex
	data     map[k]v
	newValue func() v
}

func (t *threadSafeMap[k, v]) getOrCreate(key k) v {
	t.lock.Lock()
	defer t.lock.Unlock()

	val, exists := t.data[key]
	if !exists {
		val = t.newValue()
		t.data[key] = val
	}

	return val
}
