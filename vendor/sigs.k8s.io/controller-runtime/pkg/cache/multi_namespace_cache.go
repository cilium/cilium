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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// a new global namespaced cache to handle cluster scoped resources.
const globalCache = "_cluster-scope"

// MultiNamespacedCacheBuilder - Builder function to create a new multi-namespaced cache.
// This will scope the cache to a list of namespaces. Listing for all namespaces
// will list for all the namespaces that this knows about. By default this will create
// a global cache for cluster scoped resource. Note that this is not intended
// to be used for excluding namespaces, this is better done via a Predicate. Also note that
// you may face performance issues when using this with a high number of namespaces.
//
// Deprecated: Use cache.Options.Namespaces instead.
func MultiNamespacedCacheBuilder(namespaces []string) NewCacheFunc {
	return func(config *rest.Config, opts Options) (Cache, error) {
		opts.Namespaces = namespaces
		return newMultiNamespaceCache(config, opts)
	}
}

func newMultiNamespaceCache(config *rest.Config, opts Options) (Cache, error) {
	if len(opts.Namespaces) < 2 {
		return nil, fmt.Errorf("must specify more than one namespace to use multi-namespace cache")
	}
	opts, err := defaultOpts(config, opts)
	if err != nil {
		return nil, err
	}

	// Create every namespace cache.
	caches := map[string]Cache{}
	for _, ns := range opts.Namespaces {
		opts.Namespaces = []string{ns}
		c, err := New(config, opts)
		if err != nil {
			return nil, err
		}
		caches[ns] = c
	}

	// Create a cache for cluster scoped resources.
	opts.Namespaces = []string{}
	gCache, err := New(config, opts)
	if err != nil {
		return nil, fmt.Errorf("error creating global cache: %w", err)
	}

	return &multiNamespaceCache{namespaceToCache: caches, Scheme: opts.Scheme, RESTMapper: opts.Mapper, clusterCache: gCache}, nil
}

// multiNamespaceCache knows how to handle multiple namespaced caches
// Use this feature when scoping permissions for your
// operator to a list of namespaces instead of watching every namespace
// in the cluster.
type multiNamespaceCache struct {
	namespaceToCache map[string]Cache
	Scheme           *runtime.Scheme
	RESTMapper       apimeta.RESTMapper
	clusterCache     Cache
}

var _ Cache = &multiNamespaceCache{}

// Methods for multiNamespaceCache to conform to the Informers interface.
func (c *multiNamespaceCache) GetInformer(ctx context.Context, obj client.Object) (Informer, error) {
	informers := map[string]Informer{}

	// If the object is clusterscoped, get the informer from clusterCache,
	// if not use the namespaced caches.
	isNamespaced, err := apiutil.IsObjectNamespaced(obj, c.Scheme, c.RESTMapper)
	if err != nil {
		return nil, err
	}
	if !isNamespaced {
		clusterCacheInf, err := c.clusterCache.GetInformer(ctx, obj)
		if err != nil {
			return nil, err
		}
		informers[globalCache] = clusterCacheInf

		return &multiNamespaceInformer{namespaceToInformer: informers}, nil
	}

	for ns, cache := range c.namespaceToCache {
		informer, err := cache.GetInformer(ctx, obj)
		if err != nil {
			return nil, err
		}
		informers[ns] = informer
	}

	return &multiNamespaceInformer{namespaceToInformer: informers}, nil
}

func (c *multiNamespaceCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind) (Informer, error) {
	informers := map[string]Informer{}

	// If the object is clusterscoped, get the informer from clusterCache,
	// if not use the namespaced caches.
	isNamespaced, err := apiutil.IsGVKNamespaced(gvk, c.RESTMapper)
	if err != nil {
		return nil, err
	}
	if !isNamespaced {
		clusterCacheInf, err := c.clusterCache.GetInformerForKind(ctx, gvk)
		if err != nil {
			return nil, err
		}
		informers[globalCache] = clusterCacheInf

		return &multiNamespaceInformer{namespaceToInformer: informers}, nil
	}

	for ns, cache := range c.namespaceToCache {
		informer, err := cache.GetInformerForKind(ctx, gvk)
		if err != nil {
			return nil, err
		}
		informers[ns] = informer
	}

	return &multiNamespaceInformer{namespaceToInformer: informers}, nil
}

func (c *multiNamespaceCache) Start(ctx context.Context) error {
	// start global cache
	go func() {
		err := c.clusterCache.Start(ctx)
		if err != nil {
			log.Error(err, "cluster scoped cache failed to start")
		}
	}()

	// start namespaced caches
	for ns, cache := range c.namespaceToCache {
		go func(ns string, cache Cache) {
			err := cache.Start(ctx)
			if err != nil {
				log.Error(err, "multinamespace cache failed to start namespaced informer", "namespace", ns)
			}
		}(ns, cache)
	}

	<-ctx.Done()
	return nil
}

func (c *multiNamespaceCache) WaitForCacheSync(ctx context.Context) bool {
	synced := true
	for _, cache := range c.namespaceToCache {
		if s := cache.WaitForCacheSync(ctx); !s {
			synced = s
		}
	}

	// check if cluster scoped cache has synced
	if !c.clusterCache.WaitForCacheSync(ctx) {
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
		return fmt.Errorf("unable to get: %v because of unknown namespace for the cache", key)
	}
	return cache.Get(ctx, key, obj)
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
			return fmt.Errorf("unable to get: %v because of unknown namespace for the cache", listOpts.Namespace)
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

// AddEventHandler adds the handler to each namespaced informer.
func (i *multiNamespaceInformer) AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error) {
	handles := handlerRegistration{handles: make(map[string]toolscache.ResourceEventHandlerRegistration, len(i.namespaceToInformer))}
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
	handles := handlerRegistration{handles: make(map[string]toolscache.ResourceEventHandlerRegistration, len(i.namespaceToInformer))}
	for ns, informer := range i.namespaceToInformer {
		registration, err := informer.AddEventHandlerWithResyncPeriod(handler, resyncPeriod)
		if err != nil {
			return nil, err
		}
		handles.handles[ns] = registration
	}
	return handles, nil
}

// RemoveEventHandler removes a formerly added event handler given by its registration handle.
func (i *multiNamespaceInformer) RemoveEventHandler(h toolscache.ResourceEventHandlerRegistration) error {
	handles, ok := h.(handlerRegistration)
	if !ok {
		return fmt.Errorf("it is not the registration returned by multiNamespaceInformer")
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

// AddIndexers adds the indexer for each namespaced informer.
func (i *multiNamespaceInformer) AddIndexers(indexers toolscache.Indexers) error {
	for _, informer := range i.namespaceToInformer {
		err := informer.AddIndexers(indexers)
		if err != nil {
			return err
		}
	}
	return nil
}

// HasSynced checks if each namespaced informer has synced.
func (i *multiNamespaceInformer) HasSynced() bool {
	for _, informer := range i.namespaceToInformer {
		if ok := informer.HasSynced(); !ok {
			return ok
		}
	}
	return true
}
