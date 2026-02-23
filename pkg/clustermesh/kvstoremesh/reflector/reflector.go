// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
)

// Name represents the name of a reflector.
type Name string

const (
	Endpoints      Name = "endpoints"
	Identities     Name = "identities"
	Nodes          Name = "nodes"
	Services       Name = "services"
	ServiceExports Name = "service exports"
)

// Reflector knows how to watch a prefix from a given etcd instance, and
// propagate all changes into a different instance.
type Reflector interface {
	// Name returns the name of the reflector.
	Name() Name

	// Status returns the status of the reflector.
	Status() Status

	// Run starts the synchronization process. It blocks until the context is canceled.
	Run(ctx context.Context)

	// Register registers the reflector with the given [store.WatchStoreManager], to
	// watch the desired prefix. If reflection is not enabled (e.g., as not supported
	// according to the remote cluster capabilities), it drains possibly stale data.
	Register(mgr store.WatchStoreManager, remote kvstore.BackendOperations, cfg types.CiliumClusterConfig)

	// DeleteCache deletes all previously cached data from the local kvstore, possibly
	// at once. It shall be invoked only once the synchronization process has already been
	// aborted, and under the assumption that all Cilium agents have already stopped watching
	// the prefix.
	DeleteCache(ctx context.Context) error

	// RevokeCache revokes all previously cached data, if revocation is enabled.
	// It shall be invoked when synchronization is still in progress, and it is expected
	// that Cilium agents may be potentially watching the prefix.
	RevokeCache(ctx context.Context)
}

// Status summarizes the status of a reflector.
type Status struct {
	// Enabled represents whether the reflector is currently enabled.
	Enabled bool

	// Synced represents whether the reflector retrieved the initial list of entries from etcd.
	Synced bool

	// Entries is the number of entries synchronized by the given reflector.
	Entries uint64
}

type opt func(*reflector)

// ClusterNamePlaceHolder is the placeholder for the cluster name in prefix overrides.
const ClusterNamePlaceHolder = "<cluster-name>"

// WithStatePrefixOverride allows to override the state prefix, for non-standard paths.
// [ClusterNamePlaceHolder] gets automatically replaced with the actual cluster name.
func WithStatePrefixOverride(prefix string) opt {
	return func(r *reflector) {
		r.statePrefix = strings.ReplaceAll(prefix, ClusterNamePlaceHolder, r.cluster)
	}
}

// WithCachePrefixOverride allows to override the cache prefix, for non-standard paths.
// [ClusterNamePlaceHolder] gets automatically replaced with the actual cluster name.
func WithCachePrefixOverride(prefix string) opt {
	return func(r *reflector) {
		r.cachePrefix = strings.ReplaceAll(prefix, ClusterNamePlaceHolder, r.cluster)
	}
}

// WithEnabledOverride configures a function that determines whether reflection
// of a resource should be enabled, depending on the remote cluster configuration.
// Reflection is enabled by default if not configured otherwise.
func WithEnabledOverride(enabled func(types.CiliumClusterConfig) bool) opt {
	return func(r *reflector) {
		r.shouldRegister = enabled
	}
}

// WithRevocation enables the revocation of all previously cached data, in
// case connectivity to the source cluster is lost.
func WithRevocation() opt {
	return func(r *reflector) {
		r.shouldRevoke = true
	}
}

// Factory is the signature of the reflector factory.
type Factory func(local kvstore.Client, sf store.Factory, cluster string, onSync func()) Reflector

// NewFactory returns a new factory for the given reflector.
func NewFactory(name Name, prefix string, opts ...opt) Factory {
	return func(local kvstore.Client, sf store.Factory, cluster string, onSync func()) Reflector {
		var rfl = reflector{
			name:    name,
			cluster: cluster,

			basePrefix:  prefix,
			statePrefix: path.Join(prefix, cluster),
			cachePrefix: path.Join(kvstore.StateToCachePrefix(prefix), cluster),

			shouldRegister: func(types.CiliumClusterConfig) bool { return true },
			shouldRevoke:   false,

			local: local,
		}

		for _, opt := range opts {
			opt(&rfl)
		}

		rfl.syncer = syncer{
			SyncStore: sf.NewSyncStore(
				cluster, local, rfl.cachePrefix,
				store.WSSWithSyncedKeyOverride(kvstore.StateToCachePrefix(rfl.basePrefix)),
			),
			syncedDone: onSync,
		}

		rfl.watcher = sf.NewWatchStore(
			cluster, store.KVPairCreator, &rfl.syncer,
			store.RWSWithOnSyncCallback(rfl.syncer.OnSync),
		)

		return &rfl
	}
}

type reflector struct {
	name    Name
	cluster string

	statePrefix string
	cachePrefix string
	basePrefix  string

	shouldRegister func(types.CiliumClusterConfig) bool
	shouldRevoke   bool

	local   kvstore.Client
	watcher store.WatchStore
	syncer  syncer

	enabled atomic.Bool
}

func (rfl *reflector) Name() Name {
	return rfl.name
}

func (rfl *reflector) Run(ctx context.Context) {
	rfl.syncer.Run(ctx)
}

func (rfl *reflector) Register(mgr store.WatchStoreManager, backend kvstore.BackendOperations, cfg types.CiliumClusterConfig) {
	if rfl.shouldRegister(cfg) {
		var syncPrefix, watchPrefix = rfl.basePrefix, rfl.statePrefix
		if cfg.Capabilities.Cached {
			syncPrefix, watchPrefix = kvstore.StateToCachePrefix(syncPrefix), rfl.cachePrefix
		}

		rfl.enabled.Store(true)
		mgr.Register(syncPrefix, func(ctx context.Context) {
			rfl.watcher.Watch(ctx, backend, watchPrefix)
		})
	} else {
		rfl.enabled.Store(false)

		// Let's drain the watcher in case the given reflector is not enabled,
		// to remove possibly state data if previously enabled.
		rfl.watcher.Drain()
		// Additionally, pretend that synchronization completed, to ensure that
		// the synced key is written, and eventually invoke the onSync callback.
		rfl.syncer.OnSync(context.Background())
	}
}

func (rfl *reflector) DeleteCache(ctx context.Context) error {
	if err := rfl.local.DeletePrefix(ctx, rfl.cachePrefix+"/"); err != nil {
		return fmt.Errorf("deleting prefix %q: %w", rfl.cachePrefix+"/", err)
	}

	return nil
}

func (rfl *reflector) RevokeCache(context.Context) {
	if rfl.shouldRevoke {
		rfl.watcher.Drain()
	}
}

func (rfl *reflector) Status() Status {
	return Status{
		Enabled: rfl.enabled.Load(),
		Synced:  rfl.watcher.Synced(),
		Entries: rfl.watcher.NumEntries(),
	}
}

type syncer struct {
	store.SyncStore
	syncedDone lock.DoneFunc
}

func (o *syncer) OnUpdate(key store.Key) {
	o.UpsertKey(context.Background(), key)
}

func (o *syncer) OnDelete(key store.NamedKey) {
	o.DeleteKey(context.Background(), key)
}

func (o *syncer) OnSync(ctx context.Context) {
	o.Synced(ctx, func(context.Context) { o.syncedDone() })
}
