/*
Copyright 2026 The Kubernetes Authors.

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

package cacheapi

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"
)

// InformerGetOptions defines the behavior of how informers are retrieved.
type InformerGetOptions struct {
	// BlockUntilSynced controls if the informer retrieval will block until the informer is synced. Defaults to `true`.
	BlockUntilSynced *bool
}

// InformerGetOption defines an option that alters the behavior of how informers are retrieved.
type InformerGetOption func(*InformerGetOptions)

// BlockUntilSynced determines whether a get request for an informer should block
// until the informer's cache has synced.
func BlockUntilSynced(shouldBlock bool) InformerGetOption {
	return func(opts *InformerGetOptions) {
		opts.BlockUntilSynced = &shouldBlock
	}
}

// Object is a Kubernetes object, allows functions to work indistinctly with
// any resource that implements both Object interfaces.
//
// Semantically, these are objects which are both serializable (runtime.Object)
// and identifiable (metav1.Object) -- think any object which you could write
// as YAML or JSON, and then `kubectl create`.
//
// Code-wise, this means that any object which embeds both ObjectMeta (which
// provides metav1.Object) and TypeMeta (which provides half of runtime.Object)
// and has a `DeepCopyObject` implementation (the other half of runtime.Object)
// will implement this by default.
//
// For example, nearly all the built-in types are Objects, as well as all
// KubeBuilder-generated CRDs (unless you do something real funky to them).
//
// By and large, most things that implement runtime.Object also implement
// Object -- it's very rare to have *just* a runtime.Object implementation (the
// cases tend to be funky built-in types like Webhook payloads that don't have
// a `metadata` field).
//
// Notice that XYZList types are distinct: they implement ObjectList instead.
type Object interface {
	metav1.Object
	runtime.Object
}

// IndexerFunc knows how to take an object and turn it into a series
// of non-namespaced keys. Namespaced objects are automatically given
// namespaced and non-spaced variants, so keys do not need to include namespace.
type IndexerFunc func(Object) []string

// FieldIndexer knows how to index over a particular "field" such that it
// can later be used by a field selector.
type FieldIndexer interface {
	// IndexField adds an index with the given field name on the given object type
	// by using the given function to extract the value for that field.  If you want
	// compatibility with the Kubernetes API server, only return one key, and only use
	// fields that the API server supports.  Otherwise, you can return multiple keys,
	// and "equality" in the field selector means that at least one key matches the value.
	// The FieldIndexer will automatically take care of indexing over namespace
	// and supporting efficient all-namespace queries.
	IndexField(ctx context.Context, obj Object, field string, extractValue IndexerFunc) error
}

// Informers knows how to create or fetch informers for different
// group-version-kinds, and add indices to those informers.  It's safe to call
// GetInformer from multiple threads.
type Informers interface {
	// GetInformer fetches or constructs an informer for the given object that corresponds to a single
	// API kind and resource.
	GetInformer(ctx context.Context, obj Object, opts ...InformerGetOption) (Informer, error)

	// GetInformerForKind is similar to GetInformer, except that it takes a group-version-kind, instead
	// of the underlying object.
	GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...InformerGetOption) (Informer, error)

	// RemoveInformer removes an informer entry and stops it if it was running.
	RemoveInformer(ctx context.Context, obj Object) error

	// Start runs all the informers known to this cache until the context is closed.
	// It blocks.
	Start(ctx context.Context) error

	// WaitForCacheSync waits for all the caches to sync. Returns false if it could not sync a cache.
	WaitForCacheSync(ctx context.Context) bool

	// FieldIndexer adds indices to the managed informers.
	FieldIndexer
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

	// HasSyncedChecker completes if the informers underlying store has synced.
	HasSyncedChecker() toolscache.DoneChecker

	// IsStopped returns true if the informer has been stopped.
	IsStopped() bool
}
