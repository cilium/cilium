/*
Copyright 2019 The Kubernetes Authors.

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

package cache

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// a new global namespaced cache to handle cluster scoped resources.
const globalCache = "_cluster-scope"

func newMultiNamespaceCache(
	newCache newCacheFunc,
	scheme *runtime.Scheme,
	restMapper apimeta.RESTMapper,
	namespaces map[string]Config,
	globalConfig *Config, // may be nil in which case no cache for cluster-scoped objects will be created
) Cache {
	// Create every namespace cache.
	caches := map[string]Cache{}
	for namespace, config := range namespaces {
		caches[namespace] = newCache(config, namespace)
	}

	// Create a cache for cluster scoped resources if requested
	var clusterCache Cache
	if globalConfig != nil {
		clusterCache = newCache(*globalConfig, corev1.NamespaceAll)
	}

	return &multiNamespaceCache{
		namespaceToCache: caches,
		Scheme:           scheme,
		RESTMapper:       restMapper,
		clusterCache:     clusterCache,
	}
}

// multiNamespaceCache knows how to handle multiple namespaced caches
// Use this feature when scoping permissions for your
// operator to a list of namespaces instead of watching every namespace
// in the cluster.
type multiNamespaceCache struct {
	Scheme           *runtime.Scheme
	RESTMapper       apimeta.RESTMapper
	namespaceToCache map[string]Cache
	clusterCache     Cache
}

var _ Cache = &multiNamespaceCache{}

// Methods for multiNamespaceCache to conform to the Informers interface.

func (c *multiNamespaceCache) GetInformer(ctx context.Context, obj client.Object, opts ...InformerGetOption) (Informer, error) {
	// If the object is cluster scoped, get the informer from clusterCache,
	// if not use the namespaced caches.
	isNamespaced, err := apiutil.IsObjectNamespaced(obj, c.Scheme, c.RESTMapper)
	if err != nil {
		return nil, err
	}
	if !isNamespaced {
		clusterCacheInformer, err := c.clusterCache.GetInformer(ctx, obj, opts...)
		if err != nil {
			return nil, err
		}

		return &multiNamespaceInformer{
			namespaceToInformer: map[string]Informer{
				globalCache: clusterCacheInformer,
			},
		}, nil
	}

	namespaceToInformer := map[string]Informer{}
	for ns, cache := range c.namespaceToCache {
		informer, err := cache.GetInformer(ctx, obj, opts...)
		if err != nil {
			return nil, err
		}
		namespaceToInformer[ns] = informer
	}

	return &multiNamespaceInformer{namespaceToInformer: namespaceToInformer}, nil
}

func (c *multiNamespaceCache) RemoveInformer(ctx context.Context, obj client.Object) error {
	// If the object is clusterscoped, get the informer from clusterCache,
	// if not use the namespaced caches.
	isNamespaced, err := apiutil.IsObjectNamespaced(obj, c.Scheme, c.RESTMapper)
	if err != nil {
		return err
	}
	if !isNamespaced {
		return c.clusterCache.RemoveInformer(ctx, obj)
	}

	for _, cache := range c.namespaceToCache {
		err := cache.RemoveInformer(ctx, obj)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *multiNamespaceCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...InformerGetOption) (Informer, error) {
	// If the object is cluster scoped, get the informer from clusterCache,
	// if not use the namespaced caches.
	isNamespaced, err := apiutil.IsGVKNamespaced(gvk, c.RESTMapper)
	if err != nil {
		return nil, err
	}
	if !isNamespaced {
		clusterCacheInformer, err := c.clusterCache.GetInformerForKind(ctx, gvk, opts...)
		if err != nil {
			return nil, err
		}

		return &multiNamespaceInformer{
			namespaceToInformer: map[string]Informer{
				globalCache: clusterCacheInformer,
			},
		}, nil
	}

	namespaceToInformer := map[string]Informer{}
	for ns, cache := range c.namespaceToCache {
		informer, err := cache.GetInformerForKind(ctx, gvk, opts...)
		if err != nil {
			return nil, err
		}
		namespaceToInformer[ns] = informer
	}

	return &multiNamespaceInformer{namespaceToInformer: namespaceToInformer}, nil
}

func (c *multiNamespaceCache) Start(ctx context.Context) error {
	errs := make(chan error)
	// start global cache
	if c.clusterCache != nil {
		go func() {
			err := c.clusterCache.Start(ctx)
			if err != nil {
				errs <- fmt.Errorf("failed to start cluster-scoped cache: %w", err)
			}
		}()
	}

	// start namespaced caches
	for ns, cache := range c.namespaceToCache {
		go func(ns string, cache Cache) {
			if err := cache.Start(ctx); err != nil {
				errs <- fmt.Errorf("failed to start cache for namespace %s: %w", ns, err)
			}
		}(ns, cache)
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}

func (c *multiNamespaceCache) WaitForCacheSync(ctx context.Context) bool {
	synced := true
	for _, cache := range c.namespaceToCache {
		if !cache.WaitForCacheSync(ctx) {
			synced = false
		}
	}

	// check if cluster scoped cache has synced
	if c.clusterCache != nil && !c.clusterCache.WaitForCacheSync(ctx) {
		synced = false
	}
	return synced
}

func (c *multiNamespaceCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	isNamespaced, err := apiutil.IsObjectNamespaced(obj, c.Scheme, c.RESTMapper)
	if err != nil {
		return err
	}

	if !isNamespaced {
		return c.clusterCache.IndexField(ctx, obj, field, extractValue)
	}

	for _, cache := range c.namespaceToCache {
		if err := cache.IndexField(ctx, obj, field, extractValue); err != nil {
			return err
		}
	}
	return nil
}

func (c *multiNamespaceCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	isNamespaced, err := apiutil.IsObjectNamespaced(obj, c.Scheme, c.RESTMapper)
	if err != nil {
		return err
	}

	if !isNamespaced {
		// Look into the global cache to fetch the object
		return c.clusterCache.Get(ctx, key, obj)
	}

	cache, ok := c.namespaceToCache[key.Namespace]
	if !ok {
		if global, hasGlobal := c.namespaceToCache[metav1.NamespaceAll]; hasGlobal {
			return global.Get(ctx, key, obj, opts...)
		}
		return fmt.Errorf("unable to get: %v because of unknown namespace for the cache", key)
	}
	return cache.Get(ctx, key, obj, opts...)
}

// List multi namespace cache will get all the objects in the namespaces that the cache is watching if asked for all namespaces.
func (c *multiNamespaceCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	listOpts := client.ListOptions{}
	listOpts.ApplyOptions(opts)

	isNamespaced, err := apiutil.IsObjectNamespaced(list, c.Scheme, c.RESTMapper)
	if err != nil {
		return err
	}

	if !isNamespaced {
		// Look at the global cache to get the objects with the specified GVK
		return c.clusterCache.List(ctx, list, opts...)
	}

	if listOpts.Namespace != corev1.NamespaceAll {
		cache, ok := c.namespaceToCache[listOpts.Namespace]
		if !ok {
			if global, hasGlobal := c.namespaceToCache[AllNamespaces]; hasGlobal {
				return global.List(ctx, list, opts...)
			}
			return fmt.Errorf("unable to list: %v because of unknown namespace for the cache", listOpts.Namespace)
		}
		return cache.List(ctx, list, opts...)
	}

	listAccessor, err := apimeta.ListAccessor(list)
	if err != nil {
		return err
	}

	allItems, err := apimeta.ExtractList(list)
	if err != nil {
		return err
	}

	limitSet := listOpts.Limit > 0

	var resourceVersion string
	for _, cache := range c.namespaceToCache {
		listObj := list.DeepCopyObject().(client.ObjectList)
		err = cache.List(ctx, listObj, &listOpts)
		if err != nil {
			return err
		}
		items, err := apimeta.ExtractList(listObj)
		if err != nil {
			return err
		}
		accessor, err := apimeta.ListAccessor(listObj)
		if err != nil {
			return fmt.Errorf("object: %T must be a list type", list)
		}
		allItems = append(allItems, items...)

		// The last list call should have the most correct resource version.
		resourceVersion = accessor.GetResourceVersion()
		if limitSet {
			// decrement Limit by the number of items
			// fetched from the current namespace.
			listOpts.Limit -= int64(len(items))

			// if a Limit was set and the number of
			// items read has reached this set limit,
			// then stop reading.
			if listOpts.Limit == 0 {
				break
			}
		}
	}
	listAccessor.SetResourceVersion(resourceVersion)

	return apimeta.SetList(list, allItems)
}

// multiNamespaceInformer knows how to handle interacting with the underlying informer across multiple namespaces.
type multiNamespaceInformer struct {
	namespaceToInformer map[string]Informer
}

type handlerRegistration struct {
	handles map[string]toolscache.ResourceEventHandlerRegistration
}

type syncer interface {
	HasSynced() bool
}

// HasSynced asserts that the handler has been called for the full initial state of the informer.
// This uses syncer to be compatible between client-go 1.27+ and older versions when the interface changed.
func (h handlerRegistration) HasSynced() bool {
	for _, reg := range h.handles {
		if s, ok := reg.(syncer); ok {
			if !s.HasSynced() {
				return false
			}
		}
	}
	return true
}

var _ Informer = &multiNamespaceInformer{}

// AddEventHandler adds the handler to each informer.
func (i *multiNamespaceInformer) AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error) {
	handles := handlerRegistration{
		handles: make(map[string]toolscache.ResourceEventHandlerRegistration, len(i.namespaceToInformer)),
	}

	for ns, informer := range i.namespaceToInformer {
		registration, err := informer.AddEventHandler(handler)
		if err != nil {
			return nil, err
		}
		handles.handles[ns] = registration
	}

	return handles, nil
}

// AddEventHandlerWithResyncPeriod adds the handler with a resync period to each namespaced informer.
func (i *multiNamespaceInformer) AddEventHandlerWithResyncPeriod(handler toolscache.ResourceEventHandler, resyncPeriod time.Duration) (toolscache.ResourceEventHandlerRegistration, error) {
	handles := handlerRegistration{
		handles: make(map[string]toolscache.ResourceEventHandlerRegistration, len(i.namespaceToInformer)),
	}

	for ns, informer := range i.namespaceToInformer {
		registration, err := informer.AddEventHandlerWithResyncPeriod(handler, resyncPeriod)
		if err != nil {
			return nil, err
		}
		handles.handles[ns] = registration
	}

	return handles, nil
}

// RemoveEventHandler removes a previously added event handler given by its registration handle.
func (i *multiNamespaceInformer) RemoveEventHandler(h toolscache.ResourceEventHandlerRegistration) error {
	handles, ok := h.(handlerRegistration)
	if !ok {
		return fmt.Errorf("registration is not a registration returned by multiNamespaceInformer")
	}
	for ns, informer := range i.namespaceToInformer {
		registration, ok := handles.handles[ns]
		if !ok {
			continue
		}
		if err := informer.RemoveEventHandler(registration); err != nil {
			return err
		}
	}
	return nil
}

// AddIndexers adds the indexers to each informer.
func (i *multiNamespaceInformer) AddIndexers(indexers toolscache.Indexers) error {
	for _, informer := range i.namespaceToInformer {
		err := informer.AddIndexers(indexers)
		if err != nil {
			return err
		}
	}
	return nil
}

// HasSynced checks if each informer has synced.
func (i *multiNamespaceInformer) HasSynced() bool {
	for _, informer := range i.namespaceToInformer {
		if !informer.HasSynced() {
			return false
		}
	}
	return true
}

// IsStopped checks if each namespaced informer has stopped, returns false if any are still running.
func (i *multiNamespaceInformer) IsStopped() bool {
	for _, informer := range i.namespaceToInformer {
		if stopped := informer.IsStopped(); !stopped {
			return false
		}
	}
	return true
}
