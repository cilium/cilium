// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 5 * time.Second
)

type remoteEtcdClientWrapper struct {
	kvstore.BackendOperations
	name   string
	cached bool

	kvs map[string]string
	mu  lock.Mutex

	syncedCanariesWatched bool
}

// Override the ListAndWatch method so that we can propagate whatever event we want without key conflicts with
// those eventually created by kvstoremesh. Additionally, this also allows to track which prefixes have been watched.
func (w *remoteEtcdClientWrapper) ListAndWatch(ctx context.Context, prefix string, chanSize int) *kvstore.Watcher {
	events := make(kvstore.EventChan, 10)

	w.mu.Lock()
	defer w.mu.Unlock()

	if prefix == fmt.Sprintf("cilium/synced/%s/", w.name) {
		state := "state"
		if w.cached {
			state = "cache"
		}

		w.syncedCanariesWatched = true
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/nodes/v1", w.name, state)}
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/services/v1", w.name, state)}
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/identities/v1", w.name, state)}
		events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: fmt.Sprintf("cilium/synced/%s/cilium/%s/ip/v1", w.name, state)}
	} else {
		for key, value := range w.kvs {
			var found bool
			if strings.HasPrefix(key, prefix) {
				events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: key, Value: []byte(value)}
				found = true
				delete(w.kvs, key)
			}

			if found {
				events <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeListDone}
			}
		}
	}

	go func() {
		<-ctx.Done()
		close(events)
	}()

	return &kvstore.Watcher{Events: events}
}

func TestRemoteClusterRun(t *testing.T) {
	testutils.IntegrationTest(t)

	kvstore.SetupDummyWithConfigOpts(t, "etcd",
		// Explicitly set higher QPS than the default to speedup the test
		map[string]string{kvstore.EtcdRateLimitOption: "100"},
	)

	tests := []struct {
		name   string
		srccfg *types.CiliumClusterConfig
		dstcfg *types.CiliumClusterConfig
		kvs    map[string]string
	}{
		{
			name:   "remote cluster has no cluster config",
			srccfg: nil,
			dstcfg: &types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries: true,
					Cached:         true,
				},
			},
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":    "qux1",
				"cilium/state/services/v1/foo/bar": "qux2",
				"cilium/state/identities/v1/bar":   "qux3",
				"cilium/state/ip/v1/default/bar":   "qux4",
			},
		},
		{
			name: "remote cluster supports the synced canaries",
			srccfg: &types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries: true,
				},
			},
			dstcfg: &types.CiliumClusterConfig{
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries: true,
					Cached:         true,
				},
			},
			kvs: map[string]string{
				"cilium/state/nodes/v1/foo/bar":    "qux1",
				"cilium/state/services/v1/foo/bar": "qux2",
				"cilium/state/identities/v1/bar":   "qux3",
				"cilium/state/ip/v1/default/bar":   "qux4",
			},
		},
		{
			name: "remote cluster supports the cached prefixes",
			srccfg: &types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					Cached: true,
				},
			},
			dstcfg: &types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries: true,
					Cached:         true,
				},
			},
			kvs: map[string]string{
				"cilium/cache/nodes/v1/foo/bar":      "qux1",
				"cilium/cache/services/v1/foo/bar":   "qux2",
				"cilium/cache/identities/v1/foo/bar": "qux3",
				"cilium/cache/ip/v1/foo/bar":         "qux4",
			},
		},
		{
			name: "remote cluster supports both synced canaries and cached prefixes",
			srccfg: &types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries: true,
					Cached:         true,
				},
			},
			dstcfg: &types.CiliumClusterConfig{
				ID: 10,
				Capabilities: types.CiliumClusterConfigCapabilities{
					SyncedCanaries: true,
					Cached:         true,
				},
			},
			kvs: map[string]string{
				"cilium/cache/nodes/v1/foo/bar":      "qux1",
				"cilium/cache/services/v1/foo/bar":   "qux2",
				"cilium/cache/identities/v1/foo/bar": "qux3",
				"cilium/cache/ip/v1/foo/bar":         "qux4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())

			t.Cleanup(func() {
				cancel()
				wg.Wait()

				require.NoError(t, kvstore.Client().DeletePrefix(context.Background(), kvstore.BaseKeyPrefix))
			})

			remoteClient := &remoteEtcdClientWrapper{
				BackendOperations: kvstore.Client(),
				name:              "foo",
				cached:            tt.srccfg != nil && tt.srccfg.Capabilities.Cached,
				kvs:               tt.kvs,
			}
			st := store.NewFactory(store.MetricsProvider())
			km := KVStoreMesh{backend: kvstore.Client(), storeFactory: st}
			rc := km.newRemoteCluster("foo", nil)
			ready := make(chan error)

			wg.Add(1)
			go func() {
				rc.Run(ctx, remoteClient, tt.srccfg, ready)
				rc.Stop()
				wg.Done()
			}()

			require.NoError(t, <-ready, "rc.Run() failed")

			// Assert that the cluster config got properly propagated
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				cfg, err := utils.GetClusterConfig(ctx, "foo", kvstore.Client())
				assert.NoError(c, err)
				assert.Equal(c, tt.dstcfg, cfg)
			}, timeout, tick, "Failed to retrieve the cluster config")

			// Assert that the keys have been properly reflected
			for key, value := range map[string]string{
				"cilium/cache/nodes/v1/foo/bar":      "qux1",
				"cilium/cache/services/v1/foo/bar":   "qux2",
				"cilium/cache/identities/v1/foo/bar": "qux3",
				"cilium/cache/ip/v1/foo/bar":         "qux4",
			} {
				require.EventuallyWithTf(t, func(c *assert.CollectT) {
					v, err := kvstore.Client().Get(ctx, key)
					assert.NoError(c, err)
					assert.Equal(c, value, string(v))
				}, timeout, tick, "Expected key %q does not seem to have the correct value %q", key, value)
			}

			// Assert that the sync canaries have been properly set
			for _, key := range []string{
				"cilium/synced/foo/cilium/cache/nodes/v1",
				"cilium/synced/foo/cilium/cache/services/v1",
				"cilium/synced/foo/cilium/cache/identities/v1",
				"cilium/synced/foo/cilium/cache/ip/v1",
			} {
				require.EventuallyWithTf(t, func(c *assert.CollectT) {
					v, err := kvstore.Client().Get(ctx, key)
					assert.NoError(c, err)
					assert.NotEmpty(c, string(v))
				}, timeout, tick, "Expected sync canary %q is not correctly present", key)
			}

			// Assert that synced canaries have been watched if expected
			require.Equal(t, tt.srccfg != nil && tt.srccfg.Capabilities.SyncedCanaries, remoteClient.syncedCanariesWatched)
		})
	}
}
