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

package internal

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/internal/syncs"
)

// InformersOpts configures an InformerMap.
type InformersOpts struct {
	HTTPClient            *http.Client
	Scheme                *runtime.Scheme
	Mapper                meta.RESTMapper
	ResyncPeriod          time.Duration
	Namespace             string
	NewInformer           *func(cache.ListerWatcher, runtime.Object, time.Duration, cache.Indexers) cache.SharedIndexInformer
	Selector              Selector
	Transform             cache.TransformFunc
	UnsafeDisableDeepCopy bool
	WatchErrorHandler     cache.WatchErrorHandler
}

// NewInformers creates a new InformersMap that can create informers under the hood.
func NewInformers(config *rest.Config, options *InformersOpts) *Informers {
	newInformer := cache.NewSharedIndexInformer
	if options.NewInformer != nil {
		newInformer = *options.NewInformer
	}
	return &Informers{
		config:     config,
		httpClient: options.HTTPClient,
		scheme:     options.Scheme,
		mapper:     options.Mapper,
		tracker: tracker{
			Structured:   make(map[schema.GroupVersionKind]*Cache),
			Unstructured: make(map[schema.GroupVersionKind]*Cache),
			Metadata:     make(map[schema.GroupVersionKind]*Cache),
		},
		codecs:                serializer.NewCodecFactory(options.Scheme),
		paramCodec:            runtime.NewParameterCodec(options.Scheme),
		resync:                options.ResyncPeriod,
		startWait:             make(chan struct{}),
		namespace:             options.Namespace,
		selector:              options.Selector,
		transform:             options.Transform,
		unsafeDisableDeepCopy: options.UnsafeDisableDeepCopy,
		newInformer:           newInformer,
		watchErrorHandler:     options.WatchErrorHandler,
	}
}

// Cache contains the cached data for an Cache.
type Cache struct {
	// Informer is the cached informer
	Informer cache.SharedIndexInformer

	// CacheReader wraps Informer and implements the CacheReader interface for a single type
	Reader CacheReader

	// Stop can be used to stop this individual informer.
	stop chan struct{}
}

// Start starts the informer managed by a MapEntry.
// Blocks until the informer stops. The informer can be stopped
// either individually (via the entry's stop channel) or globally
// via the provided stop argument.
func (c *Cache) Start(stop <-chan struct{}) {
	// Stop on either the whole map stopping or just this informer being removed.
	internalStop, cancel := syncs.MergeChans(stop, c.stop)
	defer cancel()
	c.Informer.Run(internalStop)
}

type tracker struct {
	Structured   map[schema.GroupVersionKind]*Cache
	Unstructured map[schema.GroupVersionKind]*Cache
	Metadata     map[schema.GroupVersionKind]*Cache
}

// GetOptions provides configuration to customize the behavior when
// getting an informer.
type GetOptions struct {
	// BlockUntilSynced controls if the informer retrieval will block until the informer is synced. Defaults to `true`.
	BlockUntilSynced *bool
}

// Informers create and caches Informers for (runtime.Object, schema.GroupVersionKind) pairs.
// It uses a standard parameter codec constructed based on the given generated Scheme.
type Informers struct {
	// httpClient is used to create a new REST client
	httpClient *http.Client

	// scheme maps runtime.Objects to GroupVersionKinds
	scheme *runtime.Scheme

	// config is used to talk to the apiserver
	config *rest.Config

	// mapper maps GroupVersionKinds to Resources
	mapper meta.RESTMapper

	// tracker tracks informers keyed by their type and groupVersionKind
	tracker tracker

	// codecs is used to create a new REST client
	codecs serializer.CodecFactory

	// paramCodec is used by list and watch
	paramCodec runtime.ParameterCodec

	// resync is the base frequency the informers are resynced
	// a 10 percent jitter will be added to the resync period between informers
	// so that all informers will not send list requests simultaneously.
	resync time.Duration

	// mu guards access to the map
	mu sync.RWMutex

	// started is true if the informers have been started
	started bool

	// startWait is a channel that is closed after the
	// informer has been started.
	startWait chan struct{}

	// waitGroup is the wait group that is used to wait for all informers to stop
	waitGroup sync.WaitGroup

	// stopped is true if the informers have been stopped
	stopped bool

	// ctx is the context to stop informers
	ctx context.Context

	// namespace is the namespace that all ListWatches are restricted to
	// default or empty string means all namespaces
	namespace string

	selector              Selector
	transform             cache.TransformFunc
	unsafeDisableDeepCopy bool

	// NewInformer allows overriding of the shared index informer constructor for testing.
	newInformer func(cache.ListerWatcher, runtime.Object, time.Duration, cache.Indexers) cache.SharedIndexInformer

	// WatchErrorHandler allows the shared index informer's
	// watchErrorHandler to be set by overriding the options
	// or to use the default watchErrorHandler
	watchErrorHandler cache.WatchErrorHandler
}

// Start calls Run on each of the informers and sets started to true. Blocks on the context.
// It doesn't return start because it can't return an error, and it's not a runnable directly.
func (ip *Informers) Start(ctx context.Context) error {
	func() {
		ip.mu.Lock()
		defer ip.mu.Unlock()

		// Set the context so it can be passed to informers that are added later
		ip.ctx = ctx

		// Start each informer
		for _, i := range ip.tracker.Structured {
			ip.startInformerLocked(i)
		}
		for _, i := range ip.tracker.Unstructured {
			ip.startInformerLocked(i)
		}
		for _, i := range ip.tracker.Metadata {
			ip.startInformerLocked(i)
		}

		// Set started to true so we immediately start any informers added later.
		ip.started = true
		close(ip.startWait)
	}()
	<-ctx.Done() // Block until the context is done
	ip.mu.Lock()
	ip.stopped = true // Set stopped to true so we don't start any new informers
	ip.mu.Unlock()
	ip.waitGroup.Wait() // Block until all informers have stopped
	return nil
}

func (ip *Informers) startInformerLocked(cacheEntry *Cache) {
	// Don't start the informer in case we are already waiting for the items in
	// the waitGroup to finish, since waitGroups don't support waiting and adding
	// at the same time.
	if ip.stopped {
		return
	}

	ip.waitGroup.Add(1)
	go func() {
		defer ip.waitGroup.Done()
		cacheEntry.Start(ip.ctx.Done())
	}()
}

func (ip *Informers) waitForStarted(ctx context.Context) bool {
	select {
	case <-ip.startWait:
		return true
	case <-ctx.Done():
		return false
	}
}

// getHasSyncedFuncs returns all the HasSynced functions for the informers in this map.
func (ip *Informers) getHasSyncedFuncs() []cache.InformerSynced {
	ip.mu.RLock()
	defer ip.mu.RUnlock()

	res := make([]cache.InformerSynced, 0,
		len(ip.tracker.Structured)+len(ip.tracker.Unstructured)+len(ip.tracker.Metadata),
	)
	for _, i := range ip.tracker.Structured {
		res = append(res, i.Informer.HasSynced)
	}
	for _, i := range ip.tracker.Unstructured {
		res = append(res, i.Informer.HasSynced)
	}
	for _, i := range ip.tracker.Metadata {
		res = append(res, i.Informer.HasSynced)
	}
	return res
}

// WaitForCacheSync waits until all the caches have been started and synced.
func (ip *Informers) WaitForCacheSync(ctx context.Context) bool {
	if !ip.waitForStarted(ctx) {
		return false
	}
	return cache.WaitForCacheSync(ctx.Done(), ip.getHasSyncedFuncs()...)
}

// Peek attempts to get the informer for the GVK, but does not start one if one does not exist.
func (ip *Informers) Peek(gvk schema.GroupVersionKind, obj runtime.Object) (res *Cache, started bool, ok bool) {
	ip.mu.RLock()
	defer ip.mu.RUnlock()
	i, ok := ip.informersByType(obj)[gvk]
	return i, ip.started, ok
}

// Get will create a new Informer and add it to the map of specificInformersMap if none exists. Returns
// the Informer from the map.
func (ip *Informers) Get(ctx context.Context, gvk schema.GroupVersionKind, obj runtime.Object, opts *GetOptions) (bool, *Cache, error) {
	// Return the informer if it is found
	i, started, ok := ip.Peek(gvk, obj)
	if !ok {
		var err error
		if i, started, err = ip.addInformerToMap(gvk, obj); err != nil {
			return started, nil, err
		}
	}

	shouldBlock := true
	if opts.BlockUntilSynced != nil {
		shouldBlock = *opts.BlockUntilSynced
	}

	if shouldBlock && started && !i.Informer.HasSynced() {
		// Wait for it to sync before returning the Informer so that folks don't read from a stale cache.
		if !cache.WaitForCacheSync(ctx.Done(), i.Informer.HasSynced) {
			return started, nil, apierrors.NewTimeoutError(fmt.Sprintf("failed waiting for %T Informer to sync", obj), 0)
		}
	}

	return started, i, nil
}

// Remove removes an informer entry and stops it if it was running.
func (ip *Informers) Remove(gvk schema.GroupVersionKind, obj runtime.Object) {
	ip.mu.Lock()
	defer ip.mu.Unlock()

	informerMap := ip.informersByType(obj)

	entry, ok := informerMap[gvk]
	if !ok {
		return
	}
	close(entry.stop)
	delete(informerMap, gvk)
}

func (ip *Informers) informersByType(obj runtime.Object) map[schema.GroupVersionKind]*Cache {
	switch obj.(type) {
	case runtime.Unstructured:
		return ip.tracker.Unstructured
	case *metav1.PartialObjectMetadata, *metav1.PartialObjectMetadataList:
		return ip.tracker.Metadata
	default:
		return ip.tracker.Structured
	}
}

// addInformerToMap either returns an existing informer or creates a new informer, adds it to the map and returns it.
func (ip *Informers) addInformerToMap(gvk schema.GroupVersionKind, obj runtime.Object) (*Cache, bool, error) {
	ip.mu.Lock()
	defer ip.mu.Unlock()

	// Check the cache to see if we already have an Informer. If we do, return the Informer.
	// This is for the case where 2 routines tried to get the informer when it wasn't in the map
	// so neither returned early, but the first one created it.
	if i, ok := ip.informersByType(obj)[gvk]; ok {
		return i, ip.started, nil
	}

	// Create a NewSharedIndexInformer and add it to the map.
	listWatcher, err := ip.makeListWatcher(gvk, obj)
	if err != nil {
		return nil, false, err
	}
	sharedIndexInformer := ip.newInformer(&cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			ip.selector.ApplyToList(&opts)
			return listWatcher.ListFunc(opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			ip.selector.ApplyToList(&opts)
			opts.Watch = true // Watch needs to be set to true separately
			return listWatcher.WatchFunc(opts)
		},
	}, obj, calculateResyncPeriod(ip.resync), cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	})

	// Set WatchErrorHandler on SharedIndexInformer if set
	if ip.watchErrorHandler != nil {
		if err := sharedIndexInformer.SetWatchErrorHandler(ip.watchErrorHandler); err != nil {
			return nil, false, err
		}
	}

	// Check to see if there is a transformer for this gvk
	if err := sharedIndexInformer.SetTransform(ip.transform); err != nil {
		return nil, false, err
	}

	mapping, err := ip.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, false, err
	}

	// Create the new entry and set it in the map.
	i := &Cache{
		Informer: sharedIndexInformer,
		Reader: CacheReader{
			indexer:          sharedIndexInformer.GetIndexer(),
			groupVersionKind: gvk,
			scopeName:        mapping.Scope.Name(),
			disableDeepCopy:  ip.unsafeDisableDeepCopy,
		},
		stop: make(chan struct{}),
	}
	ip.informersByType(obj)[gvk] = i

	// Start the informer in case the InformersMap has started, otherwise it will be
	// started when the InformersMap starts.
	if ip.started {
		ip.startInformerLocked(i)
	}
	return i, ip.started, nil
}

func (ip *Informers) makeListWatcher(gvk schema.GroupVersionKind, obj runtime.Object) (*cache.ListWatch, error) {
	// Kubernetes APIs work against Resources, not GroupVersionKinds.  Map the
	// groupVersionKind to the Resource API we will use.
	mapping, err := ip.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, err
	}

	// Figure out if the GVK we're dealing with is global, or namespace scoped.
	var namespace string
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		namespace = restrictNamespaceBySelector(ip.namespace, ip.selector)
	}

	switch obj.(type) {
	//
	// Unstructured
	//
	case runtime.Unstructured:
		// If the rest configuration has a negotiated serializer passed in,
		// we should remove it and use the one that the dynamic client sets for us.
		cfg := rest.CopyConfig(ip.config)
		cfg.NegotiatedSerializer = nil
		dynamicClient, err := dynamic.NewForConfigAndClient(cfg, ip.httpClient)
		if err != nil {
			return nil, err
		}
		resources := dynamicClient.Resource(mapping.Resource)
		return &cache.ListWatch{
			ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
				if namespace != "" {
					return resources.Namespace(namespace).List(ip.ctx, opts)
				}
				return resources.List(ip.ctx, opts)
			},
			// Setup the watch function
			WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
				if namespace != "" {
					return resources.Namespace(namespace).Watch(ip.ctx, opts)
				}
				return resources.Watch(ip.ctx, opts)
			},
		}, nil
	//
	// Metadata
	//
	case *metav1.PartialObjectMetadata, *metav1.PartialObjectMetadataList:
		// Always clear the negotiated serializer and use the one
		// set from the metadata client.
		cfg := rest.CopyConfig(ip.config)
		cfg.NegotiatedSerializer = nil

		// Grab the metadata metadataClient.
		metadataClient, err := metadata.NewForConfigAndClient(cfg, ip.httpClient)
		if err != nil {
			return nil, err
		}
		resources := metadataClient.Resource(mapping.Resource)

		return &cache.ListWatch{
			ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
				var (
					list *metav1.PartialObjectMetadataList
					err  error
				)
				if namespace != "" {
					list, err = resources.Namespace(namespace).List(ip.ctx, opts)
				} else {
					list, err = resources.List(ip.ctx, opts)
				}
				if list != nil {
					for i := range list.Items {
						list.Items[i].SetGroupVersionKind(gvk)
					}
				}
				return list, err
			},
			// Setup the watch function
			WatchFunc: func(opts metav1.ListOptions) (watcher watch.Interface, err error) {
				if namespace != "" {
					watcher, err = resources.Namespace(namespace).Watch(ip.ctx, opts)
				} else {
					watcher, err = resources.Watch(ip.ctx, opts)
				}
				if err != nil {
					return nil, err
				}
				return newGVKFixupWatcher(gvk, watcher), nil
			},
		}, nil
	//
	// Structured.
	//
	default:
		client, err := apiutil.RESTClientForGVK(gvk, false, ip.config, ip.codecs, ip.httpClient)
		if err != nil {
			return nil, err
		}
		listGVK := gvk.GroupVersion().WithKind(gvk.Kind + "List")
		listObj, err := ip.scheme.New(listGVK)
		if err != nil {
			return nil, err
		}
		return &cache.ListWatch{
			ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
				// Build the request.
				req := client.Get().Resource(mapping.Resource.Resource).VersionedParams(&opts, ip.paramCodec)
				if namespace != "" {
					req.Namespace(namespace)
				}

				// Create the resulting object, and execute the request.
				res := listObj.DeepCopyObject()
				if err := req.Do(ip.ctx).Into(res); err != nil {
					return nil, err
				}
				return res, nil
			},
			// Setup the watch function
			WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
				// Build the request.
				req := client.Get().Resource(mapping.Resource.Resource).VersionedParams(&opts, ip.paramCodec)
				if namespace != "" {
					req.Namespace(namespace)
				}
				// Call the watch.
				return req.Watch(ip.ctx)
			},
		}, nil
	}
}

// newGVKFixupWatcher adds a wrapper that preserves the GVK information when
// events come in.
//
// This works around a bug where GVK information is not passed into mapping
// functions when using the OnlyMetadata option in the builder.
// This issue is most likely caused by kubernetes/kubernetes#80609.
// See kubernetes-sigs/controller-runtime#1484.
//
// This was originally implemented as a cache.ResourceEventHandler wrapper but
// that contained a data race which was resolved by setting the GVK in a watch
// wrapper, before the objects are written to the cache.
// See kubernetes-sigs/controller-runtime#1650.
//
// The original watch wrapper was found to be incompatible with
// k8s.io/client-go/tools/cache.Reflector so it has been re-implemented as a
// watch.Filter which is compatible.
// See kubernetes-sigs/controller-runtime#1789.
func newGVKFixupWatcher(gvk schema.GroupVersionKind, watcher watch.Interface) watch.Interface {
	return watch.Filter(
		watcher,
		func(in watch.Event) (watch.Event, bool) {
			in.Object.GetObjectKind().SetGroupVersionKind(gvk)
			return in, true
		},
	)
}

// calculateResyncPeriod returns a duration based on the desired input
// this is so that multiple controllers don't get into lock-step and all
// hammer the apiserver with list requests simultaneously.
func calculateResyncPeriod(resync time.Duration) time.Duration {
	// the factor will fall into [0.9, 1.1)
	factor := rand.Float64()/5.0 + 0.9 //nolint:gosec
	return time.Duration(float64(resync.Nanoseconds()) * factor)
}

// restrictNamespaceBySelector returns either a global restriction for all ListWatches
// if not default/empty, or the namespace that a ListWatch for the specific resource
// is restricted to, based on a specified field selector for metadata.namespace field.
func restrictNamespaceBySelector(namespaceOpt string, s Selector) string {
	if namespaceOpt != "" {
		// namespace is already restricted
		return namespaceOpt
	}
	fieldSelector := s.Field
	if fieldSelector == nil || fieldSelector.Empty() {
		return ""
	}
	// check whether a selector includes the namespace field
	value, found := fieldSelector.RequiresExactMatch("metadata.namespace")
	if found {
		return value
	}
	return ""
}
