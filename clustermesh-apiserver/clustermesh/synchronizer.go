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
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	podPrefixLbl = labels.LabelSourceK8s + ":" + k8sConst.PodNamespaceLabel
)

// Options represents the options to synchronize a given resource type.
type Options[T runtime.Object] struct {
	Enabled   bool
	Resource  string
	Prefix    string
	StoreOpts []store.WSSOpt
	// NamespaceSyncRequired indicates whether namespace changes should trigger resynchronization
	// of all resources of this type. If true, a namespace watcher will be started to monitor
	// namespace changes and resynchronize resources accordingly. Only required for certain resource types.
	NamespaceSyncRequired bool
}

// Converter knows how to convert a given Kubernetes event into the corresponding
// set of kvstore upsert and delete operations.
// The converter may decide to ignore certain events, e.g., if the resource
// is not in a global namespace.
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
}

// RegisterSynchronizer registers a new synchronizer for the given resource,
// which watches for Kubernetes events and propagates the corresponding
// representation to the kvstore.
func RegisterSynchronizer[T runtime.Object](in syncParams[T]) {
	scopedLogger := in.Logger.With(
		logfields.Resource, in.Options.Resource,
	)
	if !in.Options.Enabled {
		scopedLogger.Info("Synchronization is disabled")
		return
	}
	scopedLogger.Info("Synchronization is enabled")

	store := in.Factory.NewSyncStore(
		in.ClusterInfo.Name, in.Client,
		in.Options.Prefix, in.Options.StoreOpts...)

	synced := in.SyncState.WaitForResource()

	// process is a helper function to log and execute store operations.
	process := func(invoker, op, key string, do func() error) {
		scopedLogger.Info("Processing resource",
			logfields.LogSubsys, invoker,
			logfields.Operation, op,
			logfields.Key, key,
		)
		if err := do(); err != nil {
			scopedLogger.Warn("Failed updating resource in etcd",
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
					scopedLogger.WarnContext(ctx, "Unable to get resource store", logfields.Error, err)
					return err
				}
				invoker := fmt.Sprintf("%s-sync", strings.ToLower(in.Options.Resource))
				scopedLogger := scopedLogger.With(logfields.LogSubsys, invoker)

				scopedLogger.Info("Starting event synchronizer")

				// Get event channels
				resourceEvents := in.Resource.Events(ctx)
				var namespaceEvents <-chan resource.Event[*slim_corev1.Namespace]
				if in.Options.NamespaceSyncRequired {
					scopedLogger.Info("Namespace watcher is enabled for resource type")
					namespaceEvents = in.Namespaces.Events(ctx)
				} else {
					scopedLogger.Info("Namespace watcher is not enabled for resource type")
				}

				for resourceEvents != nil || namespaceEvents != nil {
					select {
					case <-ctx.Done():
						scopedLogger.Info("Context done, stopping event synchronizer")
						return nil
					case event, ok := <-resourceEvents:
						if !ok {
							scopedLogger.Info("Resource event channel closed, stopping synchronizer")
							return nil
						}

						if event.Kind == resource.Sync {
							event.Done(nil)
							scopedLogger.Info("Initial entries successfully received from Kubernetes")
							store.Synced(ctx, synced)
							continue
						}
						// Filter the event based on namespace global status.
						// Only required for certain resource types.
						if in.Options.NamespaceSyncRequired {
							ns, processEvent, err := resourceHandler(in, event)
							if err != nil {
								scopedLogger.Warn("Failed to handle resource event",
									logfields.Error, err,
								)
								event.Done(err)
								continue
							}
							if !processEvent {
								scopedLogger.Debug("Skipping resource event as it is not in a global namespace",
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

						// The convert uses global namespace config to determine whether to
						// upsert or delete the resource. The resource decides whether the namespace
						// needs to be considered for conversion based on the config.
						upserts, deletes := in.Converter.Convert(event)
						for upsert := range upserts {
							process("resource-event", "upsert", upsert.GetKeyName(), func() error { return store.UpsertKey(ctx, upsert) })
						}
						for delete := range deletes {
							process("resource-event", "delete", delete.GetKeyName(), func() error { return store.DeleteKey(ctx, delete) })
						}
					case event, ok := <-namespaceEvents:
						if !ok {
							scopedLogger.Info("Namespace event channel closed, ignoring future namespace events")
							// Namespace watcher is optional, so we can just set to nil to ignore future events.
							namespaceEvents = nil
							continue
						}
						event.Done(nil)
						for resEvent := range namespaceHandler[T](in, resourceStore, scopedLogger, event) {
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
				scopedLogger.Info("Stopping synchronization")
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
	scopedLogger *slog.Logger,
	event resource.Event[*slim_corev1.Namespace]) iter.Seq[resource.Event[T]] {
	return func(yield func(resource.Event[T]) bool) {
		if event.Kind == resource.Sync {
			return
		}
		// Check if the object exists.
		if event.Object == nil {
			scopedLogger.Info("Namespace object is nil, skipping event",
				logfields.Name, event.Key.Name,
			)
			return
		}
		isGlobal := in.NamespaceManager.IsGlobalNamespaceByObject(event.Object)

		// Sync all entries in the Resource store to reflect the namespace change.
		objects, err := rs.ByIndex(cache.NamespaceIndex, event.Key.Name)
		if err != nil {
			scopedLogger.Warn("Failed to list resources for namespace update",
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

// resourceHandler is a helper function that retrives the namepace of a given event's object
// and determines whether the event should be processed based on whether the namespace
// is global or not. This is required only for CiliumIdentity, CiliumEndpoint and
// CiliumEndpointSlice resources. Only handle Upsert and Delete events.
func resourceHandler[T runtime.Object](
	in syncParams[T],
	event resource.Event[T]) (namespace string, process bool, err error) {
	// For Delete events, always process (cleanup regardless of namespace state)
	if event.Kind == resource.Delete {
		return namespace, true, nil
	}

	// Type switch on the event object to determine the resource type
	switch obj := any(event.Object).(type) {
	case *cilium_api_v2.CiliumIdentity:
		if obj == nil { // Protect against nil pointer panic.
			return "", false, nil
		}
		// Get the CiliumIdentity namespace from labels.
		namespace = obj.SecurityLabels[podPrefixLbl]
	case *types.CiliumEndpoint:
		if obj == nil { // Protect against nil pointer panic.
			return "", false, nil
		}
		namespace = obj.Namespace
	case *cilium_api_v2a1.CiliumEndpointSlice:
		if obj == nil { // Protect against nil pointer panic.
			return "", false, nil
		}
		namespace = obj.Namespace
	default:
		// For other resource types, we don't need namespace-based filtering
		return "", false, nil
	}

	// If no namespace, it's a cluster-scoped resource, don't process
	if namespace == "" {
		return "", false, fmt.Errorf("could not determine namespace")
	}

	// Check if the namespace is global
	isGlobal, err := in.NamespaceManager.IsGlobalNamespaceByName(namespace)
	if err != nil {
		return namespace, false, fmt.Errorf("failed to determine if namespace %q is global: %w", namespace, err)
	}

	// For Upsert events, only process if namespace is global
	return namespace, isGlobal, err
}
