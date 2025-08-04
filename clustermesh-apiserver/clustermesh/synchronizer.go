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
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
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
	Tracker GlobalNamespaceTracker

	Resource  resource.Resource[T]
	Options   Options[T]
	Converter Converter[T]
	SyncState syncstate.SyncState
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

	// Register a processor for namespace changes to handle resource sync
	// Only register processors for resources that need namespace-based filtering
	if in.Tracker != nil && in.Resource != nil && needsNamespaceProcessor(in.Options.Resource) {
		processor := &resourceProcessor[T]{
			logger:    logger,
			resource:  in.Resource,
			converter: in.Converter,
			store:     store,
		}
		in.Tracker.RegisterProcessor(processor)
	}

	in.JobGroup.Add(
		job.OneShot(
			fmt.Sprintf("%s-sync", strings.ToLower(in.Options.Resource)),
			func(ctx context.Context, _ cell.Health) error {
				for event := range in.Resource.Events(ctx) {
					event.Done(nil)

					if event.Kind == resource.Sync {
						logger.Info("Initial entries successfully received from Kubernetes")
						store.Synced(ctx, synced)
						continue
					}

					process := func(op, key string, do func() error) {
						logger.Info("Updating resource in etcd",
							logfields.Operation, op,
							logfields.Key, key,
						)

						if err := do(); err != nil {
							logger.Warn("Failed updating resource in etcd",
								logfields.Error, err,
								logfields.Operation, op,
								logfields.Key, key,
							)
						}
					}

					upserts, deletes := in.Converter.Convert(event)
					for upsert := range upserts {
						process("upsert", upsert.GetKeyName(), func() error { return store.UpsertKey(ctx, upsert) })
					}
					for delete := range deletes {
						process("delete", delete.GetKeyName(), func() error { return store.DeleteKey(ctx, delete) })
					}
				}
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

// needsNamespaceProcessor returns true if the given resource type requires namespace-based filtering.
// Only CiliumIdentity, CiliumEndpoint, and CiliumEndpointSlice need namespace processors.
func needsNamespaceProcessor(resourceName string) bool {
	switch resourceName {
	case "CiliumIdentity", "CiliumEndpoint", "CiliumEndpointSlice":
		return true
	default:
		return false
	}
}

// resourceProcessor implements NamespaceProcessor for a specific resource type
type resourceProcessor[T runtime.Object] struct {
	logger    *slog.Logger
	resource  resource.Resource[T]
	converter Converter[T]
	store     store.SyncStore
}

func (rp *resourceProcessor[T]) ProcessNamespaceChange(namespace string, isGlobal bool) {
	ctx := context.Background()

	rp.logger.Info("Namespace global status changed, triggering resource sync",
		logfields.K8sNamespace, namespace,
		"isGlobal", isGlobal,
	)

	resourceStore, err := rp.resource.Store(ctx)
	if err != nil {
		rp.logger.Warn("Failed to get resource store for namespace sync",
			logfields.Error, err,
			logfields.K8sNamespace, namespace,
		)
		return
	}

	// Get all resources in the specific namespace using namespace index
	resources, err := resourceStore.ByIndex(cache.NamespaceIndex, namespace)
	if err != nil {
		rp.logger.Warn("Failed to query resources by namespace",
			logfields.Error, err,
			logfields.K8sNamespace, namespace,
		)
		return
	}

	rp.logger.Info("Processing resources for namespace status change",
		logfields.K8sNamespace, namespace,
		"resourceCount", len(resources),
		"isGlobal", isGlobal,
	)

	// Process each resource in the namespace
	for _, obj := range resources {
		// Create a synthetic event for the resource
		event := resource.Event[T]{
			Kind:   resource.Upsert,
			Object: obj,
			Key:    resource.NewKey(obj),
		}

		// Use the converter to determine what should be done
		upserts, deletes := rp.converter.Convert(event)

		process := func(op, key string, do func() error) {
			rp.logger.Info("Updating resource in etcd due to namespace change",
				logfields.Operation, op,
				logfields.Key, key,
				logfields.K8sNamespace, namespace,
				"isGlobal", isGlobal,
			)

			if err := do(); err != nil {
				rp.logger.Warn("Failed updating resource in etcd due to namespace change",
					logfields.Error, err,
					logfields.Operation, op,
					logfields.Key, key,
					logfields.K8sNamespace, namespace,
				)
			}
		}

		// Execute upserts and deletes as determined by the converter
		for upsert := range upserts {
			process("upsert", upsert.GetKeyName(), func() error { return rp.store.UpsertKey(ctx, upsert) })
		}
		for delete := range deletes {
			process("delete", delete.GetKeyName(), func() error { return rp.store.DeleteKey(ctx, delete) })
		}
	}
}
