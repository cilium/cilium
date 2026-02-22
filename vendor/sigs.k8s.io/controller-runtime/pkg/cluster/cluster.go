/*
Copyright 2020 The Kubernetes Authors.

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

package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	eventsv1client "k8s.io/client-go/kubernetes/typed/events/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/tools/record"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"
	intrec "sigs.k8s.io/controller-runtime/pkg/internal/recorder"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
)

// Cluster provides various methods to interact with a cluster.
type Cluster interface {
	recorder.Provider

	// GetHTTPClient returns an HTTP client that can be used to talk to the apiserver
	GetHTTPClient() *http.Client

	// GetConfig returns an initialized Config
	GetConfig() *rest.Config

	// GetCache returns a cache.Cache
	GetCache() cache.Cache

	// GetScheme returns an initialized Scheme
	GetScheme() *runtime.Scheme

	// GetClient returns a client configured with the Config. This client may
	// not be a fully "direct" client -- it may read from a cache, for
	// instance.  See Options.NewClient for more information on how the default
	// implementation works.
	GetClient() client.Client

	// GetFieldIndexer returns a client.FieldIndexer configured with the client
	GetFieldIndexer() client.FieldIndexer

	// GetRESTMapper returns a RESTMapper
	GetRESTMapper() meta.RESTMapper

	// GetAPIReader returns a reader that will be configured to use the API server directly.
	// This should be used sparingly and only when the cached client does not fit your
	// use case.
	GetAPIReader() client.Reader

	// Start starts the cluster
	Start(ctx context.Context) error
}

// Options are the possible options that can be configured for a Cluster.
type Options struct {
	// Scheme is the scheme used to resolve runtime.Objects to GroupVersionKinds / Resources
	// Defaults to the kubernetes/client-go scheme.Scheme, but it's almost always better
	// idea to pass your own scheme in.  See the documentation in pkg/scheme for more information.
	Scheme *runtime.Scheme

	// MapperProvider provides the rest mapper used to map go types to Kubernetes APIs
	MapperProvider func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error)

	// Logger is the logger that should be used by this Cluster.
	// If none is set, it defaults to log.Log global logger.
	Logger logr.Logger

	// HTTPClient is the http client that will be used to create the default
	// Cache and Client. If not set the rest.HTTPClientFor function will be used
	// to create the http client.
	HTTPClient *http.Client

	// Cache is the cache.Options that will be used to create the default Cache.
	// By default, the cache will watch and list requested objects in all namespaces.
	Cache cache.Options

	// NewCache is the function that will create the cache to be used
	// by the manager. If not set this will use the default new cache function.
	//
	// When using a custom NewCache, the Cache options will be passed to the
	// NewCache function.
	//
	// NOTE: LOW LEVEL PRIMITIVE!
	// Only use a custom NewCache if you know what you are doing.
	NewCache cache.NewCacheFunc

	// Client is the client.Options that will be used to create the default Client.
	// By default, the client will use the cache for reads and direct calls for writes.
	Client client.Options

	// NewClient is the func that creates the client to be used by the manager.
	// If not set this will create a Client backed by a Cache for read operations
	// and a direct Client for write operations.
	//
	// When using a custom NewClient, the Client options will be passed to the
	// NewClient function.
	//
	// NOTE: LOW LEVEL PRIMITIVE!
	// Only use a custom NewClient if you know what you are doing.
	NewClient client.NewClientFunc

	// EventBroadcaster records Events emitted by the manager and sends them to the Kubernetes API
	// Use this to customize the event correlator and spam filter
	//
	// Deprecated: using this may cause goroutine leaks if the lifetime of your manager or controllers
	// is shorter than the lifetime of your process.
	EventBroadcaster record.EventBroadcaster

	// makeBroadcaster allows deferring the creation of the broadcaster to
	// avoid leaking goroutines if we never call Start on this manager.  It also
	// returns whether or not this is a "owned" broadcaster, and as such should be
	// stopped with the manager.
	makeBroadcaster intrec.EventBroadcasterProducer

	// Dependency injection for testing
	newRecorderProvider func(config *rest.Config, httpClient *http.Client, scheme *runtime.Scheme, logger logr.Logger, makeBroadcaster intrec.EventBroadcasterProducer) (*intrec.Provider, error)
}

// Option can be used to manipulate Options.
type Option func(*Options)

// New constructs a brand new cluster.
func New(config *rest.Config, opts ...Option) (Cluster, error) {
	if config == nil {
		return nil, errors.New("must specify Config")
	}

	originalConfig := config

	config = rest.CopyConfig(config)
	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	options := Options{}
	for _, opt := range opts {
		opt(&options)
	}
	options, err := setOptionsDefaults(options, config)
	if err != nil {
		return nil, fmt.Errorf("failed setting cluster default options: %w", err)
	}

	// Create the mapper provider
	mapper, err := options.MapperProvider(config, options.HTTPClient)
	if err != nil {
		options.Logger.Error(err, "Failed to get API Group-Resources")
		return nil, err
	}

	// Create the cache for the cached read client and registering informers
	cacheOpts := options.Cache
	{
		if cacheOpts.Scheme == nil {
			cacheOpts.Scheme = options.Scheme
		}
		if cacheOpts.Mapper == nil {
			cacheOpts.Mapper = mapper
		}
		if cacheOpts.HTTPClient == nil {
			cacheOpts.HTTPClient = options.HTTPClient
		}
	}
	cache, err := options.NewCache(config, cacheOpts)
	if err != nil {
		return nil, err
	}

	// Create the client, and default its options.
	clientOpts := options.Client
	{
		if clientOpts.Scheme == nil {
			clientOpts.Scheme = options.Scheme
		}
		if clientOpts.Mapper == nil {
			clientOpts.Mapper = mapper
		}
		if clientOpts.HTTPClient == nil {
			clientOpts.HTTPClient = options.HTTPClient
		}
		if clientOpts.Cache == nil {
			clientOpts.Cache = &client.CacheOptions{
				Unstructured: false,
			}
		}
		if clientOpts.Cache.Reader == nil {
			clientOpts.Cache.Reader = cache
		}
	}
	clientWriter, err := options.NewClient(config, clientOpts)
	if err != nil {
		return nil, err
	}

	// Create the API Reader, a client with no cache.
	clientReader, err := client.New(config, client.Options{
		HTTPClient: options.HTTPClient,
		Scheme:     options.Scheme,
		Mapper:     mapper,
	})
	if err != nil {
		return nil, err
	}

	// Create the recorder provider to inject event recorders for the components.
	// TODO(directxman12): the log for the event provider should have a context (name, tags, etc) specific
	// to the particular controller that it's being injected into, rather than a generic one like is here.
	recorderProvider, err := options.newRecorderProvider(config, options.HTTPClient, options.Scheme, options.Logger.WithName("events"), options.makeBroadcaster)
	if err != nil {
		return nil, err
	}

	return &cluster{
		config:           originalConfig,
		httpClient:       options.HTTPClient,
		scheme:           options.Scheme,
		cache:            cache,
		fieldIndexes:     cache,
		client:           clientWriter,
		apiReader:        clientReader,
		recorderProvider: recorderProvider,
		mapper:           mapper,
		logger:           options.Logger,
	}, nil
}

// setOptionsDefaults set default values for Options fields.
func setOptionsDefaults(options Options, config *rest.Config) (Options, error) {
	if options.HTTPClient == nil {
		var err error
		options.HTTPClient, err = rest.HTTPClientFor(config)
		if err != nil {
			return options, err
		}
	}

	// Use the Kubernetes client-go scheme if none is specified
	if options.Scheme == nil {
		options.Scheme = scheme.Scheme
	}

	if options.MapperProvider == nil {
		options.MapperProvider = apiutil.NewDynamicRESTMapper
	}

	// Allow users to define how to create a new client
	if options.NewClient == nil {
		options.NewClient = client.New
	}

	// Allow newCache to be mocked
	if options.NewCache == nil {
		options.NewCache = cache.New
	}

	// Allow newRecorderProvider to be mocked
	if options.newRecorderProvider == nil {
		options.newRecorderProvider = intrec.NewProvider
	}

	// This is duplicated with pkg/manager, we need it here to provide
	// the user with an EventBroadcaster and there for the Leader election
	evtCl, err := eventsv1client.NewForConfigAndClient(config, options.HTTPClient)
	if err != nil {
		return options, err
	}

	// This is duplicated with pkg/manager, we need it here to provide
	// the user with an EventBroadcaster and there for the Leader election
	if options.EventBroadcaster == nil {
		// defer initialization to avoid leaking by default
		options.makeBroadcaster = func() (record.EventBroadcaster, events.EventBroadcaster, bool) {
			return record.NewBroadcaster(), events.NewBroadcaster(&events.EventSinkImpl{Interface: evtCl}), true
		}
	} else {
		// keep supporting the options.EventBroadcaster in the old API, but do not introduce it for the new one.
		options.makeBroadcaster = func() (record.EventBroadcaster, events.EventBroadcaster, bool) {
			return options.EventBroadcaster, events.NewBroadcaster(&events.EventSinkImpl{Interface: evtCl}), false
		}
	}

	if options.Logger.GetSink() == nil {
		options.Logger = logf.RuntimeLog.WithName("cluster")
	}

	return options, nil
}
