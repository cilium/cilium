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
