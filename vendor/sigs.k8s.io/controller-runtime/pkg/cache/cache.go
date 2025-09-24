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
	"maps"
	"net/http"
	"slices"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/cache/internal"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var (
	defaultSyncPeriod = 10 * time.Hour
)

// InformerGetOptions defines the behavior of how informers are retrieved.
type InformerGetOptions internal.GetOptions

// InformerGetOption defines an option that alters the behavior of how informers are retrieved.
type InformerGetOption func(*InformerGetOptions)

// BlockUntilSynced determines whether a get request for an informer should block
// until the informer's cache has synced.
func BlockUntilSynced(shouldBlock bool) InformerGetOption {
	return func(opts *InformerGetOptions) {
		opts.BlockUntilSynced = &shouldBlock
	}
}

// Cache knows how to load Kubernetes objects, fetch informers to request
// to receive events for Kubernetes objects (at a low-level),
// and add indices to fields on the objects stored in the cache.
type Cache interface {
	// Reader acts as a client to objects stored in the cache.
	client.Reader

	// Informers loads informers and adds field indices.
	Informers
}

// Informers knows how to create or fetch informers for different
// group-version-kinds, and add indices to those informers.  It's safe to call
// GetInformer from multiple threads.
type Informers interface {
	// GetInformer fetches or constructs an informer for the given object that corresponds to a single
	// API kind and resource.
	GetInformer(ctx context.Context, obj client.Object, opts ...InformerGetOption) (Informer, error)

	// GetInformerForKind is similar to GetInformer, except that it takes a group-version-kind, instead
	// of the underlying object.
	GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...InformerGetOption) (Informer, error)

	// RemoveInformer removes an informer entry and stops it if it was running.
	RemoveInformer(ctx context.Context, obj client.Object) error

	// Start runs all the informers known to this cache until the context is closed.
	// It blocks.
	Start(ctx context.Context) error

	// WaitForCacheSync waits for all the caches to sync. Returns false if it could not sync a cache.
	WaitForCacheSync(ctx context.Context) bool

	// FieldIndexer adds indices to the managed informers.
	client.FieldIndexer
}

// Informer allows you to interact with the underlying informer.
type Informer interface {
	// AddEventHandler adds an event handler to the shared informer using the shared informer's resync
	// period. Events to a single handler are delivered sequentially, but there is no coordination
	// between different handlers.
	// It returns a registration handle for the handler that can be used to remove
	// the handler again and an error if the handler cannot be added.
	AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error)

	// AddEventHandlerWithResyncPeriod adds an event handler to the shared informer using the
	// specified resync period. Events to a single handler are delivered sequentially, but there is
	// no coordination between different handlers.
	// It returns a registration handle for the handler that can be used to remove
	// the handler again and an error if the handler cannot be added.
	AddEventHandlerWithResyncPeriod(handler toolscache.ResourceEventHandler, resyncPeriod time.Duration) (toolscache.ResourceEventHandlerRegistration, error)

	// AddEventHandlerWithOptions is a variant of AddEventHandlerWithResyncPeriod where
	// all optional parameters are passed in as a struct.
	AddEventHandlerWithOptions(handler toolscache.ResourceEventHandler, options toolscache.HandlerOptions) (toolscache.ResourceEventHandlerRegistration, error)

	// RemoveEventHandler removes a previously added event handler given by
	// its registration handle.
	// This function is guaranteed to be idempotent and thread-safe.
	RemoveEventHandler(handle toolscache.ResourceEventHandlerRegistration) error

	// AddIndexers adds indexers to this store. It is valid to add indexers
	// after an informer was started.
	AddIndexers(indexers toolscache.Indexers) error

	// HasSynced return true if the informers underlying store has synced.
	HasSynced() bool
	// IsStopped returns true if the informer has been stopped.
	IsStopped() bool
}

// AllNamespaces should be used as the map key to deliminate namespace settings
// that apply to all namespaces that themselves do not have explicit settings.
const AllNamespaces = metav1.NamespaceAll

// Options are the optional arguments for creating a new Cache object.
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
	//
	// SyncPeriod will locally trigger an artificial Update event with the same
	// object in both ObjectOld and ObjectNew for everything that is in the
	// cache.
	//
	// Predicates or Handlers that expect ObjectOld and ObjectNew to be different
	// (such as GenerationChangedPredicate) will filter out this event, preventing
	// it from triggering a reconciliation.
	// SyncPeriod does not sync between the local cache and the server.
	SyncPeriod *time.Duration

	// ReaderFailOnMissingInformer configures the cache to return a ErrResourceNotCached error when a user
	// requests, using Get() and List(), a resource the cache does not already have an informer for.
	//
	// This error is distinct from an errors.NotFound.
	//
	// Defaults to false, which means that the cache will start a new informer
	// for every new requested resource.
	ReaderFailOnMissingInformer bool

	// DefaultNamespaces maps namespace names to cache configs. If set, only
	// the namespaces in here will be watched and it will by used to default
	// ByObject.Namespaces for all objects if that is nil.
	//
	// It is possible to have specific Config for just some namespaces
	// but cache all namespaces by using the AllNamespaces const as the map key.
	// This will then include all namespaces that do not have a more specific
	// setting.
	//
	// The options in the Config that are nil will be defaulted from
	// the respective Default* settings.
	DefaultNamespaces map[string]Config

	// DefaultLabelSelector will be used as a label selector for all objects
	// unless there is already one set in ByObject or DefaultNamespaces.
	DefaultLabelSelector labels.Selector

	// DefaultFieldSelector will be used as a field selector for all object types
	// unless there is already one set in ByObject or DefaultNamespaces.
	DefaultFieldSelector fields.Selector

	// DefaultTransform will be used as transform for all object types
	// unless there is already one set in ByObject or DefaultNamespaces.
	//
	// A typical usecase for this is to use TransformStripManagedFields
	// to reduce the caches memory usage.
	DefaultTransform toolscache.TransformFunc

	// DefaultWatchErrorHandler will be used to set the WatchErrorHandler which is called
	// whenever ListAndWatch drops the connection with an error.
	//
	// After calling this handler, the informer will backoff and retry.
	DefaultWatchErrorHandler toolscache.WatchErrorHandlerWithContext

	// DefaultUnsafeDisableDeepCopy is the default for UnsafeDisableDeepCopy
	// for everything that doesn't specify this.
	//
	// Be very careful with this, when enabled you must DeepCopy any object before mutating it,
	// otherwise you will mutate the object in the cache.
	//
	// This will be used for all object types, unless it is set in ByObject or
	// DefaultNamespaces.
	DefaultUnsafeDisableDeepCopy *bool

	// DefaultEnableWatchBookmarks requests watch events with type "BOOKMARK".
	// Servers that do not implement bookmarks may ignore this flag and
	// bookmarks are sent at the server's discretion. Clients should not
	// assume bookmarks are returned at any specific interval, nor may they
	// assume the server will send any BOOKMARK event during a session.
	//
	// This will be used for all object types, unless it is set in ByObject or
	// DefaultNamespaces.
	//
	// Defaults to true.
	DefaultEnableWatchBookmarks *bool

	// ByObject restricts the cache's ListWatch to the desired fields per GVK at the specified object.
	// If unset, this will fall through to the Default* settings.
	ByObject map[client.Object]ByObject

	// NewInformer allows overriding of NewSharedIndexInformer, for example for testing
	// or if someone wants to write their own Informer.
	NewInformer func(toolscache.ListerWatcher, runtime.Object, time.Duration, toolscache.Indexers) toolscache.SharedIndexInformer
}

// ByObject offers more fine-grained control over the cache's ListWatch by object.
type ByObject struct {
	// Namespaces maps a namespace name to cache configs. If set, only the
	// namespaces in this map will be cached.
	//
	// Settings in the map value that are unset will be defaulted.
	// Use an empty value for the specific setting to prevent that.
	//
	// It is possible to have specific Config for just some namespaces
	// but cache all namespaces by using the AllNamespaces const as the map key.
	// This will then include all namespaces that do not have a more specific
	// setting.
	//
	// A nil map allows to default this to the cache's DefaultNamespaces setting.
	// An empty map prevents this and means that all namespaces will be cached.
	//
	// The defaulting follows the following precedence order:
	// 1. ByObject
	// 2. DefaultNamespaces[namespace]
	// 3. Default*
	//
	// This must be unset for cluster-scoped objects.
	Namespaces map[string]Config

	// Label represents a label selector for the object.
	Label labels.Selector

	// Field represents a field selector for the object.
	Field fields.Selector

	// Transform is a transformer function for the object which gets applied
	// when objects of the transformation are about to be committed to the cache.
	//
	// This function is called both for new objects to enter the cache,
	// and for updated objects.
	Transform toolscache.TransformFunc

	// UnsafeDisableDeepCopy indicates not to deep copy objects during get or
	// list objects per GVK at the specified object.
	// Be very careful with this, when enabled you must DeepCopy any object before mutating it,
	// otherwise you will mutate the object in the cache.
	UnsafeDisableDeepCopy *bool

	// EnableWatchBookmarks requests watch events with type "BOOKMARK".
	// Servers that do not implement bookmarks may ignore this flag and
	// bookmarks are sent at the server's discretion. Clients should not
	// assume bookmarks are returned at any specific interval, nor may they
	// assume the server will send any BOOKMARK event during a session.
	//
	// Defaults to true.
	EnableWatchBookmarks *bool
}

// Config describes all potential options for a given watch.
type Config struct {
	// LabelSelector specifies a label selector. A nil value allows to
	// default this.
	//
	// Set to labels.Everything() if you don't want this defaulted.
	LabelSelector labels.Selector

	// FieldSelector specifics a field selector. A nil value allows to
	// default this.
	//
	// Set to fields.Everything() if you don't want this defaulted.
	FieldSelector fields.Selector

	// Transform specifies a transform func. A nil value allows to default
	// this.
	//
	// Set to an empty func to prevent this:
	// func(in interface{}) (interface{}, error) { return in, nil }
	Transform toolscache.TransformFunc

	// UnsafeDisableDeepCopy specifies if List and Get requests against the
	// cache should not DeepCopy. A nil value allows to default this.
	UnsafeDisableDeepCopy *bool

	// EnableWatchBookmarks requests watch events with type "BOOKMARK".
	// Servers that do not implement bookmarks may ignore this flag and
	// bookmarks are sent at the server's discretion. Clients should not
	// assume bookmarks are returned at any specific interval, nor may they
	// assume the server will send any BOOKMARK event during a session.
	//
	// Defaults to true.
	EnableWatchBookmarks *bool
}

// NewCacheFunc - Function for creating a new cache from the options and a rest config.
type NewCacheFunc func(config *rest.Config, opts Options) (Cache, error)

// New initializes and returns a new Cache.
func New(cfg *rest.Config, opts Options) (Cache, error) {
	opts, err := defaultOpts(cfg, opts)
	if err != nil {
		return nil, err
	}

	newCacheFunc := newCache(cfg, opts)

	var defaultCache Cache
	if len(opts.DefaultNamespaces) > 0 {
		defaultConfig := optionDefaultsToConfig(&opts)
		defaultCache = newMultiNamespaceCache(newCacheFunc, opts.Scheme, opts.Mapper, opts.DefaultNamespaces, &defaultConfig)
	} else {
		defaultCache = newCacheFunc(optionDefaultsToConfig(&opts), corev1.NamespaceAll)
	}

	if len(opts.ByObject) == 0 {
		return defaultCache, nil
	}

	delegating := &delegatingByGVKCache{
		scheme:       opts.Scheme,
		caches:       make(map[schema.GroupVersionKind]Cache, len(opts.ByObject)),
		defaultCache: defaultCache,
	}

	for obj, config := range opts.ByObject {
		gvk, err := apiutil.GVKForObject(obj, opts.Scheme)
		if err != nil {
			return nil, fmt.Errorf("failed to get GVK for type %T: %w", obj, err)
		}
		var cache Cache
		if len(config.Namespaces) > 0 {
			cache = newMultiNamespaceCache(newCacheFunc, opts.Scheme, opts.Mapper, config.Namespaces, nil)
		} else {
			cache = newCacheFunc(byObjectToConfig(config), corev1.NamespaceAll)
		}
		delegating.caches[gvk] = cache
	}

	return delegating, nil
}

// TransformStripManagedFields strips the managed fields of an object before it is committed to the cache.
// If you are not explicitly accessing managedFields from your code, setting this as `DefaultTransform`
// on the cache can lead to a significant reduction in memory usage.
func TransformStripManagedFields() toolscache.TransformFunc {
	return func(in any) (any, error) {
		// Nilcheck managed fields to avoid hitting https://github.com/kubernetes/kubernetes/issues/124337
		if obj, err := meta.Accessor(in); err == nil && obj.GetManagedFields() != nil {
			obj.SetManagedFields(nil)
		}

		return in, nil
	}
}

func optionDefaultsToConfig(opts *Options) Config {
	return Config{
		LabelSelector:         opts.DefaultLabelSelector,
		FieldSelector:         opts.DefaultFieldSelector,
		Transform:             opts.DefaultTransform,
		UnsafeDisableDeepCopy: opts.DefaultUnsafeDisableDeepCopy,
		EnableWatchBookmarks:  opts.DefaultEnableWatchBookmarks,
	}
}

func byObjectToConfig(byObject ByObject) Config {
	return Config{
		LabelSelector:         byObject.Label,
		FieldSelector:         byObject.Field,
		Transform:             byObject.Transform,
		UnsafeDisableDeepCopy: byObject.UnsafeDisableDeepCopy,
		EnableWatchBookmarks:  byObject.EnableWatchBookmarks,
	}
}

type newCacheFunc func(config Config, namespace string) Cache

func newCache(restConfig *rest.Config, opts Options) newCacheFunc {
	return func(config Config, namespace string) Cache {
		return &informerCache{
			scheme: opts.Scheme,
			Informers: internal.NewInformers(restConfig, &internal.InformersOpts{
				HTTPClient:   opts.HTTPClient,
				Scheme:       opts.Scheme,
				Mapper:       opts.Mapper,
				ResyncPeriod: *opts.SyncPeriod,
				Namespace:    namespace,
				Selector: internal.Selector{
					Label: config.LabelSelector,
					Field: config.FieldSelector,
				},
				Transform:             config.Transform,
				WatchErrorHandler:     opts.DefaultWatchErrorHandler,
				UnsafeDisableDeepCopy: ptr.Deref(config.UnsafeDisableDeepCopy, false),
				EnableWatchBookmarks:  ptr.Deref(config.EnableWatchBookmarks, true),
				NewInformer:           opts.NewInformer,
			}),
			readerFailOnMissingInformer: opts.ReaderFailOnMissingInformer,
		}
	}
}

func defaultOpts(config *rest.Config, opts Options) (Options, error) {
	config = rest.CopyConfig(config)
	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	// Use the rest HTTP client for the provided config if unset
	if opts.HTTPClient == nil {
		var err error
		opts.HTTPClient, err = rest.HTTPClientFor(config)
		if err != nil {
			return Options{}, fmt.Errorf("could not create HTTP client from config: %w", err)
		}
	}

	// Use the default Kubernetes Scheme if unset
	if opts.Scheme == nil {
		opts.Scheme = scheme.Scheme
	}

	// Construct a new Mapper if unset
	if opts.Mapper == nil {
		var err error
		opts.Mapper, err = apiutil.NewDynamicRESTMapper(config, opts.HTTPClient)
		if err != nil {
			return Options{}, fmt.Errorf("could not create RESTMapper from config: %w", err)
		}
	}

	opts.ByObject = maps.Clone(opts.ByObject)
	opts.DefaultNamespaces = maps.Clone(opts.DefaultNamespaces)
	for obj, byObject := range opts.ByObject {
		isNamespaced, err := apiutil.IsObjectNamespaced(obj, opts.Scheme, opts.Mapper)
		if err != nil {
			return opts, fmt.Errorf("failed to determine if %T is namespaced: %w", obj, err)
		}
		if !isNamespaced && byObject.Namespaces != nil {
			return opts, fmt.Errorf("type %T is not namespaced, but its ByObject.Namespaces setting is not nil", obj)
		}

		if isNamespaced && byObject.Namespaces == nil {
			byObject.Namespaces = maps.Clone(opts.DefaultNamespaces)
		} else {
			byObject.Namespaces = maps.Clone(byObject.Namespaces)
		}

		// Default the namespace-level configs first, because they need to use the undefaulted type-level config
		// to be able to potentially fall through to settings from DefaultNamespaces.
		for namespace, config := range byObject.Namespaces {
			// 1. Default from the undefaulted type-level config
			config = defaultConfig(config, byObjectToConfig(byObject))
			// 2. Default from the namespace-level config. This was defaulted from the global default config earlier, but
			//    might not have an entry for the current namespace.
			if defaultNamespaceSettings, hasDefaultNamespace := opts.DefaultNamespaces[namespace]; hasDefaultNamespace {
				config = defaultConfig(config, defaultNamespaceSettings)
			}

			// 3. Default from the global defaults
			config = defaultConfig(config, optionDefaultsToConfig(&opts))

			if namespace == metav1.NamespaceAll {
				config.FieldSelector = fields.AndSelectors(
					appendIfNotNil(
						namespaceAllSelector(slices.Collect(maps.Keys(byObject.Namespaces))),
						config.FieldSelector,
					)...,
				)
			}

			byObject.Namespaces[namespace] = config
		}

		// Only default ByObject iself if it isn't namespaced or has no namespaces configured, as only
		// then any of this will be honored.
		if !isNamespaced || len(byObject.Namespaces) == 0 {
			defaultedConfig := defaultConfig(byObjectToConfig(byObject), optionDefaultsToConfig(&opts))
			byObject.Label = defaultedConfig.LabelSelector
			byObject.Field = defaultedConfig.FieldSelector
			byObject.Transform = defaultedConfig.Transform
			byObject.UnsafeDisableDeepCopy = defaultedConfig.UnsafeDisableDeepCopy
			byObject.EnableWatchBookmarks = defaultedConfig.EnableWatchBookmarks
		}

		opts.ByObject[obj] = byObject
	}

	// Default namespaces after byObject has been defaulted, otherwise a namespace without selectors
	// will get the `Default` selectors, then get copied to byObject and then not get defaulted from
	// byObject, as it already has selectors.
	for namespace, cfg := range opts.DefaultNamespaces {
		cfg = defaultConfig(cfg, optionDefaultsToConfig(&opts))
		if namespace == metav1.NamespaceAll {
			cfg.FieldSelector = fields.AndSelectors(
				appendIfNotNil(
					namespaceAllSelector(slices.Collect(maps.Keys(opts.DefaultNamespaces))),
					cfg.FieldSelector,
				)...,
			)
		}
		opts.DefaultNamespaces[namespace] = cfg
	}

	// Default the resync period to 10 hours if unset
	if opts.SyncPeriod == nil {
		opts.SyncPeriod = &defaultSyncPeriod
	}
	return opts, nil
}

func defaultConfig(toDefault, defaultFrom Config) Config {
	if toDefault.LabelSelector == nil {
		toDefault.LabelSelector = defaultFrom.LabelSelector
	}
	if toDefault.FieldSelector == nil {
		toDefault.FieldSelector = defaultFrom.FieldSelector
	}
	if toDefault.Transform == nil {
		toDefault.Transform = defaultFrom.Transform
	}
	if toDefault.UnsafeDisableDeepCopy == nil {
		toDefault.UnsafeDisableDeepCopy = defaultFrom.UnsafeDisableDeepCopy
	}
	if toDefault.EnableWatchBookmarks == nil {
		toDefault.EnableWatchBookmarks = defaultFrom.EnableWatchBookmarks
	}
	return toDefault
}

func namespaceAllSelector(namespaces []string) []fields.Selector {
	selectors := make([]fields.Selector, 0, len(namespaces)-1)
	sort.Strings(namespaces)
	for _, namespace := range namespaces {
		if namespace != metav1.NamespaceAll {
			selectors = append(selectors, fields.OneTermNotEqualSelector("metadata.namespace", namespace))
		}
	}

	return selectors
}

func appendIfNotNil[T comparable](a []T, b T) []T {
	if b != *new(T) {
		return append(a, b)
	}
	return a
}
