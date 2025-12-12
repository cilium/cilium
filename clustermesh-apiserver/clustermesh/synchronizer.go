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
	Namespacer       Namespacer[T]
}

// RegisterSynchronizer registers a new synchronizer for the given resource,
// which watches for Kubernetes events and propagates the corresponding
// representation to the kvstore.
func RegisterSynchronizer[T runtime.Object](in syncParams[T]) {
	if !in.Options.Enabled {
		in.Logger.Info("Synchronization is disabled")
		return
	}
	in.Logger.Info("Synchronization is enabled")

	store := in.Factory.NewSyncStore(
		in.ClusterInfo.Name, in.Client,
		in.Options.Prefix, in.Options.StoreOpts...)

	synced := in.SyncState.WaitForResource()

	// process is a helper function to log and execute store operations.
	process := func(invoker, op, key string, do func() error) {
		in.Logger.Info("Processing resource",
			logfields.LogSubsys, invoker,
			logfields.Operation, op,
			logfields.Key, key,
		)
		if err := do(); err != nil {
			in.Logger.Warn("Failed updating resource in etcd",
				logfields.Error, err,
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
				invoker := fmt.Sprintf("%s-sync", strings.ToLower(in.Options.Resource))
				in.Logger.Info("Starting event synchronizer")

				// Get event channels
				resourceEvents := in.Resource.Events(ctx)
				var namespaceEvents <-chan resource.Event[*slim_corev1.Namespace]
				if in.Options.Namespaced {
					in.Logger.Info("Namespace watcher is enabled for resource type")
					namespaceEvents = in.Namespaces.Events(ctx)
				} else {
					in.Logger.Info("Namespace watcher is not enabled for resource type")
				}

				for {
					select {
					case <-ctx.Done():
						in.Logger.Info("Context done, stopping event synchronizer")
						return nil
					case event, ok := <-resourceEvents:
						if !ok {
							in.Logger.Info("Resource event channel closed, stopping synchronizer")
							return nil
						}

						if event.Kind == resource.Sync {
							event.Done(nil)
							in.Logger.Info("Initial entries successfully received from Kubernetes")
							store.Synced(ctx, synced)
							continue
						}
						// Filter the event based on namespace global status.
						// Only required for certain resource types.
						// Ignore delete events as they should always be processed.
						if in.Options.Namespaced {
							ns, err := in.Namespacer.ExtractNamespace(event)
							if err != nil {
								in.Logger.Error("Failed to extract namespace from resource event",
									logfields.Error, err,
								)
								// This error won't succeed for this event, so just mark it done and continue.
								event.Done(nil)
								continue
							}
							// Check if the namespace is empty.
							if ns == "" {
								in.Logger.Error("Failed to determine namespace for resource event, skipping",
									logfields.Name, event.Key.Name,
								)
								// No way to process this event, just mark done and continue.
								event.Done(nil)
								continue
							}
							isGlobal, err := in.NamespaceManager.IsGlobalNamespaceByName(ns)
							if err != nil {
								in.Logger.Warn("Failed to determine if namespace is global",
									logfields.Error, err,
									logfields.K8sNamespace, ns,
								)
								// Retry this as it might succeed later because of dependency on namespace store.
								event.Done(err)
								continue
							}
							if !isGlobal {
								in.Logger.Debug("Skipping resource event as it is not in a global namespace",
									logfields.Name, event.Key.Name,
									logfields.K8sNamespace, ns,
								)
								event.Done(nil)
								continue
							}
						}

						// No possible errors past this point.
						event.Done(nil)

						// The convert uses global namespace config to determine whether to
						// upsert or delete the resource. The resource decides whether the namespace
						// needs to be considered for conversion based on the config.
						upserts, deletes := in.Converter.Convert(event)
						for upsert := range upserts {
							process(invoker, "upsert", upsert.GetKeyName(), func() error { return store.UpsertKey(ctx, upsert) })
						}
						for delete := range deletes {
							process(invoker, "delete", delete.GetKeyName(), func() error { return store.DeleteKey(ctx, delete) })
						}
					case event, ok := <-namespaceEvents:
						if !ok {
							in.Logger.Info("Namespace event channel closed, ignoring future namespace events")
							// Namespace watcher is optional, so we can just set to nil to ignore future events.
							namespaceEvents = nil
							continue
						}
						event.Done(nil)
						for resEvent := range namespaceHandler(in, resourceStore, event) {
							upserts, deletes := in.Converter.Convert(resEvent)
							for upsert := range upserts {
								process(invoker, "upsert", upsert.GetKeyName(), func() error { return store.UpsertKey(ctx, upsert) })
							}
							for delete := range deletes {
								process(invoker, "delete", delete.GetKeyName(), func() error { return store.DeleteKey(ctx, delete) })
							}
						}
					}
				}
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
		// Check if the object exists.
		if event.Object == nil {
			in.Logger.Info("Namespace object is nil, skipping event",
				logfields.Name, event.Key.Name,
			)
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
