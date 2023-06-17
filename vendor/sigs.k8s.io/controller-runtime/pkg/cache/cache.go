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

package cache

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"

	"sigs.k8s.io/controller-runtime/pkg/cache/internal"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"
)

var (
	log               = logf.RuntimeLog.WithName("object-cache")
	defaultSyncPeriod = 10 * time.Hour
)

// Cache knows how to load Kubernetes objects, fetch informers to request
// to receive events for Kubernetes objects (at a low-level),
// and add indices to fields on the objects stored in the cache.
type Cache interface {
	// Cache acts as a client to objects stored in the cache.
	client.Reader

	// Cache loads informers and adds field indices.
	Informers
}

// Informers knows how to create or fetch informers for different
// group-version-kinds, and add indices to those informers.  It's safe to call
// GetInformer from multiple threads.
type Informers interface {
	// GetInformer fetches or constructs an informer for the given object that corresponds to a single
	// API kind and resource.
	GetInformer(ctx context.Context, obj client.Object) (Informer, error)

	// GetInformerForKind is similar to GetInformer, except that it takes a group-version-kind, instead
	// of the underlying object.
	GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind) (Informer, error)

	// Start runs all the informers known to this cache until the context is closed.
	// It blocks.
	Start(ctx context.Context) error

	// WaitForCacheSync waits for all the caches to sync.  Returns false if it could not sync a cache.
	WaitForCacheSync(ctx context.Context) bool

	// Informers knows how to add indices to the caches (informers) that it manages.
	client.FieldIndexer
}

// Informer - informer allows you interact with the underlying informer.
type Informer interface {
	// AddEventHandler adds an event handler to the shared informer using the shared informer's resync
	// period.  Events to a single handler are delivered sequentially, but there is no coordination
	// between different handlers.
	// It returns a registration handle for the handler that can be used to remove
	// the handler again.
	AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error)
	// AddEventHandlerWithResyncPeriod adds an event handler to the shared informer using the
	// specified resync period.  Events to a single handler are delivered sequentially, but there is
	// no coordination between different handlers.
	// It returns a registration handle for the handler that can be used to remove
	// the handler again and an error if the handler cannot be added.
	AddEventHandlerWithResyncPeriod(handler toolscache.ResourceEventHandler, resyncPeriod time.Duration) (toolscache.ResourceEventHandlerRegistration, error)
	// RemoveEventHandler removes a formerly added event handler given by
	// its registration handle.
	// This function is guaranteed to be idempotent, and thread-safe.
	RemoveEventHandler(handle toolscache.ResourceEventHandlerRegistration) error
	// AddIndexers adds more indexers to this store.  If you call this after you already have data
	// in the store, the results are undefined.
	AddIndexers(indexers toolscache.Indexers) error
	// HasSynced return true if the informers underlying store has synced.
	HasSynced() bool
}

// Options are the optional arguments for creating a new InformersMap object.
type Options struct {
	// HTTPClient is the http client to use for the REST client
	HTTPClient *http.Client

	// Scheme is the scheme to use for mapping objects to GroupVersionKinds
	Scheme *runtime.Scheme

	// Mapper is the RESTMapper to use for mapping GroupVersionKinds to Resources
	Mapper meta.RESTMapper

	// SyncPeriod determines the minimum frequency at which watched resources are
	// reconciled. A lower period will correct entropy more quickly, but reduce
	// responsiveness to change if there are many watched resources. Change this
	// value only if you know what you are doing. Defaults to 10 hours if unset.
	// there will a 10 percent jitter between the SyncPeriod of all controllers
	// so that all controllers will not send list requests simultaneously.
	//
	// This applies to all controllers.
	//
	// A period sync happens for two reasons:
	// 1. To insure against a bug in the controller that causes an object to not
	// be requeued, when it otherwise should be requeued.
	// 2. To insure against an unknown bug in controller-runtime, or its dependencies,
	// that causes an object to not be requeued, when it otherwise should be
	// requeued, or to be removed from the queue, when it otherwise should not
	// be removed.
	//
	// If you want
	// 1. to insure against missed watch events, or
	// 2. to poll services that cannot be watched,
	// then we recommend that, instead of changing the default period, the
	// controller requeue, with a constant duration `t`, whenever the controller
	// is "done" with an object, and would otherwise not requeue it, i.e., we
	// recommend the `Reconcile` function return `reconcile.Result{RequeueAfter: t}`,
	// instead of `reconcile.Result{}`.
	SyncPeriod *time.Duration

	// Namespaces restricts the cache's ListWatch to the desired namespaces
	// Default watches all namespaces
	Namespaces []string

	// DefaultLabelSelector will be used as a label selectors for all object types
	// unless they have a more specific selector set in ByObject.
	DefaultLabelSelector labels.Selector

	// DefaultFieldSelector will be used as a field selectors for all object types
	// unless they have a more specific selector set in ByObject.
	DefaultFieldSelector fields.Selector

	// DefaultTransform will be used as transform for all object types
	// unless they have a more specific transform set in ByObject.
	DefaultTransform toolscache.TransformFunc

	// ByObject restricts the cache's ListWatch to the desired fields per GVK at the specified object.
	ByObject map[client.Object]ByObject

	// UnsafeDisableDeepCopy indicates not to deep copy objects during get or
	// list objects for EVERY object.
	// Be very careful with this, when enabled you must DeepCopy any object before mutating it,
	// otherwise you will mutate the object in the cache.
	//
	// This is a global setting for all objects, and can be overridden by the ByObject setting.
	UnsafeDisableDeepCopy *bool
}

// ByObject offers more fine-grained control over the cache's ListWatch by object.
type ByObject struct {
	// Label represents a label selector for the object.
	Label labels.Selector

	// Field represents a field selector for the object.
	Field fields.Selector

	// Transform is a map from objects to transformer functions which
	// get applied when objects of the transformation are about to be committed
	// to cache.
	//
	// This function is called both for new objects to enter the cache,
	// and for updated objects.
	Transform toolscache.TransformFunc

	// UnsafeDisableDeepCopy indicates not to deep copy objects during get or
	// list objects per GVK at the specified object.
	// Be very careful with this, when enabled you must DeepCopy any object before mutating it,
	// otherwise you will mutate the object in the cache.
	UnsafeDisableDeepCopy *bool
}

// NewCacheFunc - Function for creating a new cache from the options and a rest config.
type NewCacheFunc func(config *rest.Config, opts Options) (Cache, error)

// New initializes and returns a new Cache.
func New(config *rest.Config, opts Options) (Cache, error) {
	if len(opts.Namespaces) == 0 {
		opts.Namespaces = []string{metav1.NamespaceAll}
	}
	if len(opts.Namespaces) > 1 {
		return newMultiNamespaceCache(config, opts)
	}

	opts, err := defaultOpts(config, opts)
	if err != nil {
		return nil, err
	}

	byGVK, err := convertToInformerOptsByGVK(opts.ByObject, opts.Scheme)
	if err != nil {
		return nil, err
	}
	// Set the default selector and transform.
	byGVK[schema.GroupVersionKind{}] = internal.InformersOptsByGVK{
		Selector: internal.Selector{
			Label: opts.DefaultLabelSelector,
			Field: opts.DefaultFieldSelector,
		},
		Transform:             opts.DefaultTransform,
		UnsafeDisableDeepCopy: opts.UnsafeDisableDeepCopy,
	}

	return &informerCache{
		scheme: opts.Scheme,
		Informers: internal.NewInformers(config, &internal.InformersOpts{
			HTTPClient:   opts.HTTPClient,
			Scheme:       opts.Scheme,
			Mapper:       opts.Mapper,
			ResyncPeriod: *opts.SyncPeriod,
			Namespace:    opts.Namespaces[0],
			ByGVK:        byGVK,
		}),
	}, nil
}

func defaultOpts(config *rest.Config, opts Options) (Options, error) {
	logger := log.WithName("setup")

	// Use the rest HTTP client for the provided config if unset
	if opts.HTTPClient == nil {
		var err error
		opts.HTTPClient, err = rest.HTTPClientFor(config)
		if err != nil {
			logger.Error(err, "Failed to get HTTP client")
			return opts, fmt.Errorf("could not create HTTP client from config: %w", err)
		}
	}

	// Use the default Kubernetes Scheme if unset
	if opts.Scheme == nil {
		opts.Scheme = scheme.Scheme
	}

	// Construct a new Mapper if unset
	if opts.Mapper == nil {
		var err error
		opts.Mapper, err = apiutil.NewDiscoveryRESTMapper(config, opts.HTTPClient)
		if err != nil {
			logger.Error(err, "Failed to get API Group-Resources")
			return opts, fmt.Errorf("could not create RESTMapper from config: %w", err)
		}
	}

	// Default the resync period to 10 hours if unset
	if opts.SyncPeriod == nil {
		opts.SyncPeriod = &defaultSyncPeriod
	}
	return opts, nil
}

func convertToInformerOptsByGVK(in map[client.Object]ByObject, scheme *runtime.Scheme) (map[schema.GroupVersionKind]internal.InformersOptsByGVK, error) {
	out := map[schema.GroupVersionKind]internal.InformersOptsByGVK{}
	for object, byObject := range in {
		gvk, err := apiutil.GVKForObject(object, scheme)
		if err != nil {
			return nil, err
		}
		if _, ok := out[gvk]; ok {
			return nil, fmt.Errorf("duplicate cache options for GVK %v, cache.Options.ByObject has multiple types with the same GroupVersionKind", gvk)
		}
		out[gvk] = internal.InformersOptsByGVK{
			Selector: internal.Selector{
				Field: byObject.Field,
				Label: byObject.Label,
			},
			Transform:             byObject.Transform,
			UnsafeDisableDeepCopy: byObject.UnsafeDisableDeepCopy,
		}
	}
	return out, nil
}
