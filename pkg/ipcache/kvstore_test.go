// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	storepkg "github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/source"
)

type event struct{ ev, ip string }
type fakeIPCache struct{ events chan event }
type fakeBackend struct{ prefix string }

func NewEvent(ev, ip string) event { return event{ev: ev, ip: ip} }
func NewFakeIPCache() *fakeIPCache { return &fakeIPCache{events: make(chan event)} }
func NewFakeBackend() *fakeBackend { return &fakeBackend{} }

func (m *fakeIPCache) Upsert(ip string, _ net.IP, _ uint8, _ *K8sMetadata, _ Identity) (bool, error) {
	m.events <- NewEvent("upsert", ip)
	return true, nil
}

func (m *fakeIPCache) Delete(ip string, source source.Source) (namedPortsChanged bool) {
	m.events <- NewEvent("delete", ip)
	return true
}

func (m *fakeIPCache) ForEachListener(f func(listener IPIdentityMappingListener)) { f(m) }

func (m *fakeIPCache) OnIPIdentityCacheGC() { m.events <- NewEvent("sync", "") }
func (m *fakeIPCache) OnIPIdentityCacheChange(modType CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
	oldID *Identity, newID Identity, encryptKey uint8, k8sMeta *K8sMetadata) {
}

func (fb *fakeBackend) ListAndWatch(ctx context.Context, _, prefix string, _ int) *kvstore.Watcher {
	var pair identity.IPIdentityPair
	ch := make(kvstore.EventChan, 10)

	marshal := func(pair identity.IPIdentityPair) []byte {
		out, _ := pair.Marshal()
		return out
	}

	fb.prefix = prefix

	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.0.1")}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: pair.GetKeyName(), Value: marshal(pair)}
	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.1.0"), Mask: net.CIDRMask(24, 32)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: pair.GetKeyName(), Value: marshal(pair)}
	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.1.0"), Mask: net.CIDRMask(24, 32)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeListDone}

	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.1.0"), Mask: net.CIDRMask(24, 32)}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeDelete, Key: pair.GetKeyName()}
	pair = identity.IPIdentityPair{IP: net.ParseIP("10.0.0.1")}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeDelete, Key: pair.GetKeyName()}

	pair = identity.IPIdentityPair{IP: net.ParseIP("f00d::a00:0:0:c164")}
	ch <- kvstore.KeyValueEvent{Typ: kvstore.EventTypeCreate, Key: pair.GetKeyName(), Value: marshal(pair)}

	close(ch)
	return &kvstore.Watcher{Events: ch}
}

func eventually(in <-chan event) event {
	select {
	case kv := <-in:
		return kv
	// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
	case <-time.After(5 * time.Second):
		return NewEvent("error", "timed out waiting for KV")
	}
}

func TestIPIdentityWatcher(t *testing.T) {
	var synced bool
	st := storepkg.NewFactory(storepkg.MetricsProvider())
	runnable := func(body func(ipcache *fakeIPCache), prefix string, opts ...IWOpt) func(t *testing.T) {
		return func(t *testing.T) {
			synced = false
			ipcache := NewFakeIPCache()
			backend := NewFakeBackend()
			watcher := NewIPIdentityWatcher("foo", ipcache, st,
				storepkg.RWSWithOnSyncCallback(func(ctx context.Context) { synced = true }))

			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				// Read possible leftover events, to fail fast.
				for event := range ipcache.events {
					assert.Failf(t, "unexpected event not yet read", "event: %v", event)
				}
				wg.Wait()
			}()

			wg.Add(1)
			go func() {
				watcher.Watch(ctx, backend, opts...)
				close(ipcache.events)
				wg.Done()
			}()

			body(ipcache)

			// Assert that the watched prefix is correct.
			require.Equal(t, prefix, backend.prefix)
		}
	}

	t.Run("without cluster ID", runnable(func(ipcache *fakeIPCache) {
		require.Equal(t, NewEvent("upsert", "10.0.0.1"), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.1.0/24"), eventually(ipcache.events))
		require.Equal(t, NewEvent("sync", ""), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.1.0/24"), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.0.1"), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "f00d::a00:0:0:c164"), eventually(ipcache.events))
		require.True(t, synced, "The on-sync callback should have been executed")
	}, "cilium/state/ip/v1/default/"))

	t.Run("with cluster ID", runnable(func(ipcache *fakeIPCache) {
		require.Equal(t, NewEvent("upsert", "10.0.0.1@10"), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.1.0/24@10"), eventually(ipcache.events))
		require.Equal(t, NewEvent("sync", ""), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.1.0/24@10"), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.0.1@10"), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "f00d::a00:0:0:c164@10"), eventually(ipcache.events))
		require.True(t, synced, "The on-sync callback should have been executed")
	}, "cilium/state/ip/v1/default/", WithClusterID(10)))

	t.Run("with cached prefix", runnable(func(ipcache *fakeIPCache) {
		require.Equal(t, NewEvent("upsert", "10.0.0.1"), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "10.0.1.0/24"), eventually(ipcache.events))
		require.Equal(t, NewEvent("sync", ""), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.1.0/24"), eventually(ipcache.events))
		require.Equal(t, NewEvent("delete", "10.0.0.1"), eventually(ipcache.events))
		require.Equal(t, NewEvent("upsert", "f00d::a00:0:0:c164"), eventually(ipcache.events))
		require.True(t, synced, "The on-sync callback should have been executed")
	}, "cilium/cache/ip/v1/foo/", WithCachedPrefix(true)))
}
