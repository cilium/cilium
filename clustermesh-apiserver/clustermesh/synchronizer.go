// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Options represents the options to synchronize a given resource type.
type Options[T runtime.Object] struct {
	Enabled   bool
	Resource  string
	Prefix    string
	StoreOpts []store.WSSOpt
	// Namespaced indicates whether namespace changes should trigger resynchronization
	// of all resources of this type. If true, a namespace watcher will be started to monitor
	// namespace changes and resynchronize resources accordingly. Only required for certain resource types.
	Namespaced bool
}

// Converter knows how to convert a given Kubernetes event into the corresponding
// set of kvstore upsert and delete operations.
type Converter[T runtime.Object] interface {
	Convert(event resource.Event[T]) (upserts iter.Seq[store.Key], deletes iter.Seq[store.NamedKey])
}

// Namespacer is an interface that defines methods to handle namespace-related operations
// for Kubernetes resources in the context of clustermesh synchronization.
type Namespacer[T runtime.Object] interface {
	// ExtractNamespace retrieves the namespace of a given event's object.
	ExtractNamespace(resource.Event[T]) (namespace string)
}

type syncParams[T runtime.Object] struct {
	cell.In

	Logger      *slog.Logger
	JobGroup    job.Group
	ClusterInfo cmtypes.ClusterInfo

	Client  kvstore.Client
	Factory store.Factory

	Resource  resource.Resource[T]
	Options   Options[T]
	Converter Converter[T]
	SyncState syncstate.SyncState

	NamespaceManager cmnamespace.Manager
	Namespaces       resource.Resource[*slim_corev1.Namespace]
	Namespacer       Namespacer[T] `optional:"true"`
}

// RegisterSynchronizer registers a new synchronizer for the given resource,
// which watches for Kubernetes events and propagates the corresponding
// representation to the kvstore.
func RegisterSynchronizer[T runtime.Object](in syncParams[T]) {
	logger := in.Logger.With(logfields.Resource, in.Options.Resource)
	if !in.Options.Enabled {
		logger.Info("Synchronization is disabled")
		return
	}
	logger.Info("Synchronization is enabled")

	store := in.Factory.NewSyncStore(
		in.ClusterInfo.Name, in.Client,
		in.Options.Prefix, in.Options.StoreOpts...)

	synced := in.SyncState.WaitForResource()

	in.JobGroup.Add(
		job.OneShot(
			fmt.Sprintf("%s-sync", strings.ToLower(in.Options.Resource)),
			func(ctx context.Context, _ cell.Health) error {
				resourceStore, err := in.Resource.Store(ctx)
				if err != nil {
					return err
				}
				logger.Info("Starting synchronization")

				loop := &syncLoop[T]{
					logger:           logger,
					namespaced:       in.Options.Namespaced,
					converter:        in.Converter,
					namespaceManager: in.NamespaceManager,
					namespacer:       in.Namespacer,
					store:            store,
					resourceStore:    resourceStore,
					synced:           synced,
					seen:             sets.New[resource.Key](),
				}

				// Get event channels
				resourceEvents := in.Resource.Events(ctx)
				var namespaceEvents <-chan resource.Event[*slim_corev1.Namespace]
				if in.Options.Namespaced {
					logger.Debug("Namespace watcher is enabled for resource type")
					namespaceEvents = in.Namespaces.Events(ctx)
				} else {
					logger.Debug("Namespace watcher is not enabled for resource type")
				}

				for resourceEvents != nil || namespaceEvents != nil {
					select {
					case event, ok := <-resourceEvents:
						if !ok {
							resourceEvents = nil
							continue
						}
						loop.handleResource(ctx, event)
					case event, ok := <-namespaceEvents:
						if !ok {
							namespaceEvents = nil
							continue
						}
						loop.handleNamespace(ctx, event)
					}
				}
				logger.Info("Stopping synchronization")
				return nil
			},
		),
		job.OneShot(
			fmt.Sprintf("run-%s-store", strings.ToLower(in.Options.Resource)),
			func(ctx context.Context, _ cell.Health) error {
				store.Run(ctx)
				return nil
			},
		),
	)
}

// syncLoop holds the state of the synchronization loop of a given resource,
// and processes the resource and namespace events. Its methods must only be
// invoked from a single goroutine.
type syncLoop[T runtime.Object] struct {
	logger           *slog.Logger
	namespaced       bool
	converter        Converter[T]
	namespaceManager cmnamespace.Manager
	namespacer       Namespacer[T]
	store            store.SyncStore
	resourceStore    resource.Store[T]
	synced           func(context.Context)

	// seen tracks the keys of the resources that have been emitted as upsert
	// events by the resource subscriber, and not yet emitted as delete events.
	// The subscriber guarantees that a delete event is eventually emitted only
	// for these resources, hence namespace events must not propagate any other
	// resource to the converter, as its deletion might otherwise never be
	// observed, permanently leaking the corresponding kvstore entries.
	// Only populated for namespaced resources, as namespace events are not
	// watched otherwise.
	seen sets.Set[resource.Key]
}

// handleResource processes a single event for the synchronized resource.
func (l *syncLoop[T]) handleResource(ctx context.Context, event resource.Event[T]) {
	if event.Kind == resource.Sync {
		event.Done(nil)
		l.logger.Info("Initial entries successfully received from Kubernetes")
		l.store.Synced(ctx, l.synced)
		return
	}

	// Track the resources emitted by the subscriber, before the event kind is
	// possibly mutated by the namespace filter below. Upsert events converted
	// into delete events refer to resources which still exist, and that need to
	// be resynchronized in case their namespace later becomes global.
	if l.namespaced {
		switch event.Kind {
		case resource.Upsert:
			l.seen.Insert(event.Key)
		case resource.Delete:
			l.seen.Delete(event.Key)
		}
	}

	// Filter the event based on namespace global status.
	// Only required for certain resource types.
	// Ignore delete events as they should always be processed.
	if event.Kind != resource.Delete && l.namespaced {
		ns := l.namespacer.ExtractNamespace(event)
		if ns == "" {
			l.logger.Error("Failed to determine namespace for resource event, skipping",
				logfields.Name, event.Key.Name,
			)
			// No way to process this event, just mark done and continue.
			event.Done(nil)
			return
		}
		isGlobal, err := l.namespaceManager.IsGlobalNamespaceByName(ns)
		if err != nil {
			l.logger.Warn("Failed to determine if namespace is global",
				logfields.Error, err,
				logfields.K8sNamespace, ns,
			)
			// Retry this as it might succeed later.
			event.Done(err)
			return
		}
		if !isGlobal {
			l.logger.Debug("Deleting resource event as it is not in a global namespace",
				logfields.Name, event.Key.Name,
				logfields.K8sNamespace, ns,
			)
			// Handle resources transitioning out of global namespaces.
			// If a resource was previously in a global namespace and is now
			// in a non-global namespace (e.g.,mutable fields like in CiliumEndpointSlice),
			// we need to delete it from kvstore. Convert the event to a delete to ensure cleanup.
			// event.Done will be called later during normal processing.
			event.Kind = resource.Delete
		}
	}

	// No possible errors past this point.
	event.Done(nil)
	l.convert(ctx, "resource-event", event)
}

// handleNamespace processes a single namespace event, resynchronizing all
// the resources associated with the given namespace.
func (l *syncLoop[T]) handleNamespace(ctx context.Context, event resource.Event[*slim_corev1.Namespace]) {
	event.Done(nil)
	for resEvent := range l.namespaceHandler(event) {
		l.convert(ctx, "namespace-event", resEvent)
	}
}

// convert converts the given event and propagates the corresponding
// operations to the kvstore.
func (l *syncLoop[T]) convert(ctx context.Context, invoker string, event resource.Event[T]) {
	upserts, deletes := l.converter.Convert(event)
	for upsert := range upserts {
		l.process(invoker, "upsert", upsert.GetKeyName(), func() error { return l.store.UpsertKey(ctx, upsert) })
	}
	for delete := range deletes {
		l.process(invoker, "delete", delete.GetKeyName(), func() error { return l.store.DeleteKey(ctx, delete) })
	}
}

// process is a helper function to log and execute store operations.
func (l *syncLoop[T]) process(invoker, op, key string, do func() error) {
	l.logger.Info("Updating resource in etcd",
		logfields.Reason, invoker,
		logfields.Operation, op,
		logfields.Key, key,
	)
	if err := do(); err != nil {
		l.logger.Warn("Failed updating resource in etcd",
			logfields.Error, err,
			logfields.Reason, invoker,
			logfields.Operation, op,
			logfields.Key, key,
		)
	}
}

// namespaceHandler handles namespace events to resynchronize resources
// associated with the namespace based on whether it is global or not.
// Return an iterator of events to be processed.
func (l *syncLoop[T]) namespaceHandler(event resource.Event[*slim_corev1.Namespace]) iter.Seq[resource.Event[T]] {
	return func(yield func(resource.Event[T]) bool) {
		if event.Kind == resource.Sync {
			return
		}
		isGlobal := l.namespaceManager.IsGlobalNamespaceByObject(event.Object)

		// Sync all entries in the Resource store to reflect the namespace change.
		objects, err := l.resourceStore.ByIndex(cache.NamespaceIndex, event.Key.Name)
		if err != nil {
			l.logger.Warn("Failed to list resources for namespace update",
				logfields.Error, err,
			)
			return
		}
		for _, obj := range objects {
			key := resource.NewKey(obj)
			if !l.seen.Has(key) {
				// The resource has not been emitted by the subscriber yet. It will
				// be processed when the corresponding upsert event is received,
				// if it still exists at that point.
				continue
			}

			resEvent := resource.Event[T]{
				Key:    key,
				Object: obj,
			}
			// Determine the event kind. If namespace is being deleted,
			// all associated resources should be deleted.
			// If namespace is upserted/updated and is global,
			// resources should be upserted. Otherwise, they should be deleted
			// (ex: annotated non-global from global).
			if event.Kind == resource.Upsert && isGlobal {
				resEvent.Kind = resource.Upsert
			} else {
				resEvent.Kind = resource.Delete
			}
			if !yield(resEvent) {
				return
			}
		}
	}
}
