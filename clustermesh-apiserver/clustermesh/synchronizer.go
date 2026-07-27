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

	// process is a helper function to log and execute store operations.
	process := func(invoker, op, key string, do func() error) {
		logger.Info("Updating resource in etcd",
			logfields.Reason, invoker,
			logfields.Operation, op,
			logfields.Key, key,
		)
		if err := do(); err != nil {
			logger.Warn("Failed updating resource in etcd",
				logfields.Error, err,
				logfields.Reason, invoker,
				logfields.Operation, op,
				logfields.Key, key,
			)
		}
	}

	in.JobGroup.Add(
		job.OneShot(
			fmt.Sprintf("%s-sync", strings.ToLower(in.Options.Resource)),
			func(ctx context.Context, _ cell.Health) error {
				resourceStore, err := in.Resource.Store(ctx)
				if err != nil {
					return err
				}
				logger.Info("Starting synchronization")

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

						if event.Kind == resource.Sync {
							event.Done(nil)
							logger.Info("Initial entries successfully received from Kubernetes")
							store.Synced(ctx, synced)
							continue
						}
						// Filter the event based on namespace global status.
						// Only required for certain resource types.
						// Ignore delete events as they should always be processed.
						if event.Kind != resource.Delete && in.Options.Namespaced {
							ns := in.Namespacer.ExtractNamespace(event)
							if ns == "" {
								logger.Error("Failed to determine namespace for resource event, skipping",
									logfields.Name, event.Key.Name,
								)
								// No way to process this event, just mark done and continue.
								event.Done(nil)
								continue
							}
							isGlobal, err := in.NamespaceManager.IsGlobalNamespaceByName(ns)
							if err != nil {
								logger.Warn("Failed to determine if namespace is global",
									logfields.Error, err,
									logfields.K8sNamespace, ns,
								)
								// Retry this as it might succeed later.
								event.Done(err)
								continue
							}
							if !isGlobal {
								logger.Debug("Deleting resource event as it is not in a global namespace",
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

						upserts, deletes := in.Converter.Convert(event)
						for upsert := range upserts {
							process("resource-event", "upsert", upsert.GetKeyName(), func() error { return store.UpsertKey(ctx, upsert) })
						}
						for delete := range deletes {
							process("resource-event", "delete", delete.GetKeyName(), func() error { return store.DeleteKey(ctx, delete) })
						}
					case event, ok := <-namespaceEvents:
						if !ok {
							namespaceEvents = nil
							continue
						}
						event.Done(nil)
						for resEvent := range namespaceHandler(in, resourceStore, event) {
							upserts, deletes := in.Converter.Convert(resEvent)
							for upsert := range upserts {
								process("namespace-event", "upsert", upsert.GetKeyName(), func() error { return store.UpsertKey(ctx, upsert) })
							}
							for delete := range deletes {
								process("namespace-event", "delete", delete.GetKeyName(), func() error { return store.DeleteKey(ctx, delete) })
							}
						}
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

// namespaceHandler handles namespace events to resynchronize resources
// associated with the namespace based on whether it is global or not.
// Return an iterator of events to be processed.
func namespaceHandler[T runtime.Object](
	in syncParams[T], rs resource.Store[T],
	event resource.Event[*slim_corev1.Namespace]) iter.Seq[resource.Event[T]] {
	return func(yield func(resource.Event[T]) bool) {
		if event.Kind == resource.Sync {
			return
		}
		isGlobal := in.NamespaceManager.IsGlobalNamespaceByObject(event.Object)

		// Sync all entries in the Resource store to reflect the namespace change.
		objects, err := rs.ByIndex(cache.NamespaceIndex, event.Key.Name)
		if err != nil {
			in.Logger.Warn("Failed to list resources for namespace update",
				logfields.Error, err,
			)
			return
		}
		for _, obj := range objects {
			resEvent := resource.Event[T]{
				Key:    resource.NewKey(obj),
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
