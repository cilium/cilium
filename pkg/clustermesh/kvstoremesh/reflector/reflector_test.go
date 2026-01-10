// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector_test

import (
	"context"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh/reflector"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/testutils"
)

type (
	Config       = types.CiliumClusterConfig
	Capabilities = types.CiliumClusterConfigCapabilities
)

const (
	tick    = 10 * time.Millisecond
	timeout = 3 * time.Second

	name    = reflector.Name("burro")
	cluster = "ape"
)

func TestMain(m *testing.M) {
	testutils.GoleakVerifyTestMain(m)
}

func TestReflector(t *testing.T) {
	tests := []struct {
		name    string
		factory reflector.Factory
		cfg     Config
		revoke  bool

		keys     []string
		synced   string
		expected []string
	}{
		{
			name:    "vanilla",
			factory: reflector.NewFactory(name, "cilium/state/foo/bar"),
			cfg:     Config{Capabilities: Capabilities{SyncedCanaries: true}},

			keys: []string{
				"cilium/synced/ape/cilium/state/foo/bar",
				"cilium/state/foo/bar/ape/impala",
				"cilium/state/foo/bar/ape/lacewing",
				"cilium/state/foo/bar/walrus/lacewing",
			},
			synced: "cilium/synced/ape/cilium/cache/foo/bar",
			expected: []string{
				"cilium/cache/foo/bar/ape/impala",
				"cilium/cache/foo/bar/ape/lacewing",
			},
		},
		{
			name:    "cached",
			factory: reflector.NewFactory(name, "cilium/state/foo/bar"),
			cfg:     Config{Capabilities: Capabilities{SyncedCanaries: true, Cached: true}},

			keys: []string{
				"cilium/synced/ape/cilium/cache/foo/bar",
				"cilium/cache/foo/bar/ape/impala",
				"cilium/cache/foo/bar/ape/lacewing",
				"cilium/cache/foo/bar/walrus/lacewing",
			},
			synced: "cilium/synced/ape/cilium/cache/foo/bar",
			expected: []string{
				"cilium/cache/foo/bar/ape/impala",
				"cilium/cache/foo/bar/ape/lacewing",
			},
		},
		{
			name: "with prefix overrides",
			factory: reflector.NewFactory(name, "cilium/state/foo/bar",
				reflector.WithStatePrefixOverride("cilium/state/foo/"+reflector.ClusterNamePlaceHolder+"/bar"),
				reflector.WithCachePrefixOverride("cilium/cache/foo/"+reflector.ClusterNamePlaceHolder+"/baz"),
			),
			cfg: Config{Capabilities: Capabilities{SyncedCanaries: true}},

			keys: []string{
				"cilium/synced/ape/cilium/state/foo/bar",
				"cilium/state/foo/ape/bar/impala",
				"cilium/state/foo/ape/bar/lacewing",
				"cilium/state/foo/walrus/baz/lacewing",
			},
			synced: "cilium/synced/ape/cilium/cache/foo/bar",
			expected: []string{
				"cilium/cache/foo/ape/baz/impala",
				"cilium/cache/foo/ape/baz/lacewing",
			},
		},
		{
			name:    "with revocation",
			factory: reflector.NewFactory(name, "cilium/state/foo/bar", reflector.WithRevocation()),
			cfg:     Config{Capabilities: Capabilities{SyncedCanaries: true}},
			revoke:  true,

			keys: []string{
				"cilium/synced/ape/cilium/state/foo/bar",
				"cilium/state/foo/bar/ape/impala",
				"cilium/state/foo/bar/ape/lacewing",
				"cilium/state/foo/bar/walrus/lacewing",
			},
			synced: "cilium/synced/ape/cilium/cache/foo/bar",
			expected: []string{
				"cilium/cache/foo/bar/ape/impala",
				"cilium/cache/foo/bar/ape/lacewing",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				synced atomic.Bool

				db     = statedb.New()
				local  = kvstore.NewInMemoryClient(db, "__local__")
				remote = kvstore.NewInMemoryClient(db, "__remote__")
				sf     = store.NewFactory(hivetest.Logger(t), store.MetricsProvider())
				mgr    = sf.NewWatchStoreManager(remote, cluster)
			)

			rfl := tt.factory(local, sf, cluster, func() { synced.Store(true) })

			require.Equal(t, name, rfl.Name())
			require.Equal(t, reflector.Status{}, rfl.Status())

			// Start the reflector.
			var rwg sync.WaitGroup
			rctx, rcancel := context.WithCancel(t.Context())
			defer func() { rcancel(); rwg.Wait() }()
			rwg.Go(func() { rfl.Run(rctx) })

			// Populate the content of the remote instance.
			for _, key := range tt.keys {
				require.NoError(t, remote.Update(t.Context(), key, []byte("value"), false), "remote.Update")
			}

			rfl.Register(mgr, remote, tt.cfg)
			require.Equal(t, reflector.Status{Enabled: true}, rfl.Status())

			// Start the WatchStoreManager
			var mwg sync.WaitGroup
			mctx, mcancel := context.WithCancel(t.Context())
			defer func() { mcancel(); mwg.Wait() }()
			mwg.Go(func() { mgr.Run(mctx) })

			// Wait for initial synchronization to complete.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.True(c, synced.Load())
			}, timeout, tick)

			// The expected keys should have been reflected.
			var all = append([]string{tt.synced}, tt.expected...)
			kvs, err := local.ListPrefix(t.Context(), "")
			require.NoError(t, err, "local.ListPrefix")
			require.ElementsMatch(t, all, slices.Collect(maps.Keys(kvs)))

			require.Equal(t, reflector.Status{
				Enabled: true,
				Synced:  true,
				Entries: uint64(len(tt.expected)),
			}, rfl.Status())

			// Stop the manager.
			mcancel()
			mwg.Wait()

			rfl.RevokeCache(t.Context())

			if tt.revoke {
				// All keys should be eventually removed, except the synced prefix.
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					kvs, err := local.ListPrefix(t.Context(), "")
					assert.NoError(c, err, "local.ListPrefix")
					assert.ElementsMatch(c, []string{tt.synced}, slices.Collect(maps.Keys(kvs)))
				}, timeout, tick)

				require.Equal(t, reflector.Status{Enabled: true}, rfl.Status())
			} else {
				// No key should have been removed.
				time.Sleep(tick)

				kvs, err := local.ListPrefix(t.Context(), "")
				require.NoError(t, err, "local.ListPrefix")
				require.ElementsMatch(t, all, slices.Collect(maps.Keys(kvs)))

				require.Equal(t, reflector.Status{
					Enabled: true,
					Entries: uint64(len(tt.expected)),
				}, rfl.Status())
			}

			// Stop the reflector.
			rcancel()
			rwg.Wait()

			require.NoError(t, rfl.DeleteCache(t.Context()), "rfl.DeleteCache")

			// All keys should be removed, except the synced prefix.
			kvs, err = local.ListPrefix(t.Context(), "")
			assert.NoError(t, err, "local.ListPrefix")
			assert.ElementsMatch(t, []string{tt.synced}, slices.Collect(maps.Keys(kvs)))
		})
	}
}

func TestReflectorEnabled(t *testing.T) {
	var (
		synced atomic.Bool

		db     = statedb.New()
		log    = hivetest.Logger(t)
		local  = kvstore.NewInMemoryClient(db, "__local__")
		remote = kvstore.NewInMemoryClient(db, "__remote__")
		sf     = store.NewFactory(log, store.MetricsProvider())
	)

	rfl := reflector.NewFactory(name, "cilium/state/foo",
		reflector.WithEnabledOverride(func(cfg Config) bool {
			return cfg.Capabilities.MaxConnectedClusters == 22
		}),
	)(local, sf, cluster, func() { synced.Store(true) })

	// Start the reflector.
	var rwg sync.WaitGroup
	rctx, rcancel := context.WithCancel(t.Context())
	defer func() { rcancel(); rwg.Wait() }()
	rwg.Go(func() { rfl.Run(rctx) })

	// Populate the content of the remote instance.
	for _, key := range []string{"cilium/state/foo/ape/bar", "cilium/state/foo/ape/baz"} {
		require.NoError(t, remote.Update(t.Context(), key, []byte("value"), false), "remote.Update")
	}

	tests := []struct {
		capabilities Capabilities
		expected     int
	}{
		{capabilities: Capabilities{MaxConnectedClusters: 11}, expected: 0},
		{capabilities: Capabilities{MaxConnectedClusters: 22}, expected: 2},
		{capabilities: Capabilities{MaxConnectedClusters: 11}, expected: 0},
	}

	for _, tt := range tests {
		func() {
			var (
				mwg sync.WaitGroup
				mgr = store.NewWatchStoreManagerImmediate(log)
			)

			mctx, mcancel := context.WithCancel(t.Context())
			defer func() { mcancel(); mwg.Wait() }()

			rfl.Register(mgr, remote, Config{Capabilities: tt.capabilities})
			require.Equal(t, tt.expected != 0, rfl.Status().Enabled)

			mwg.Go(func() { mgr.Run(mctx) })

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				// The onSync callback should have been invoked regardless.
				assert.True(c, synced.Load())

				// The synced canary should have been created regardless.
				kvs, err := local.ListPrefix(t.Context(), "cilium/synced")
				assert.NoError(c, err, "local.ListPrefix")
				assert.Len(c, kvs, 1)

				// The actual keys should be synchronized only when enabled.
				kvs, err = local.ListPrefix(t.Context(), "cilium/cache")
				assert.NoError(c, err, "local.ListPrefix")
				assert.Len(c, kvs, tt.expected)

				assert.Equal(c, reflector.Status{
					Enabled: tt.expected != 0,
					Synced:  tt.expected != 0,
					Entries: uint64(tt.expected),
				}, rfl.Status())
			}, timeout, tick)
		}()
	}
}
