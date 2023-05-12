// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"path"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// WSMFunc if a function which can be registered in the WatchStoreManager.
type WSMFunc func(context.Context)

// WatchStoreManager enables to register a set of functions to be asynchronously
// executed when the corresponding kvstore prefixes are synchronized (based on
// the implementation).
type WatchStoreManager interface {
	// Register registers a function associated with a given kvstore prefix.
	// It cannot be called once Run() has started.
	Register(prefix string, function WSMFunc)
	// Run starts the manager, blocking until the context is closed and all
	// started functions terminated.
	Run(ctx context.Context)
}

// wsmCommon implements the common logic shared by WatchStoreManager implementations.
type wsmCommon struct {
	wg        sync.WaitGroup
	functions map[string]WSMFunc

	running atomic.Bool
	log     *logrus.Entry
}

func newWSMCommon(clusterName string) wsmCommon {
	return wsmCommon{
		functions: make(map[string]WSMFunc),
		log:       log.WithField(logfields.ClusterName, clusterName),
	}
}

// Register registers a function associated with a given kvstore prefix.
// It cannot be called once Run() has started.
func (mgr *wsmCommon) Register(prefix string, function WSMFunc) {
	if mgr.running.Load() {
		mgr.log.Panic("Cannot call Register while the watch store manager is running")
	}

	mgr.functions[prefix] = function
}

func (mgr *wsmCommon) ready(ctx context.Context, prefix string) {
	if fn := mgr.functions[prefix]; fn != nil {
		mgr.log.WithField(logfields.Prefix, prefix).Debug("Starting function for kvstore prefix")
		delete(mgr.functions, prefix)

		mgr.wg.Add(1)
		go func() {
			defer mgr.wg.Done()
			fn(ctx)
			mgr.log.WithField(logfields.Prefix, prefix).Debug("Function terminated for kvstore prefix")
		}()
	} else {
		mgr.log.WithField(logfields.Prefix, prefix).Debug("Received sync event for unregistered prefix")
	}
}

func (mgr *wsmCommon) run() {
	mgr.log.Info("Starting watch store manager")
	if mgr.running.Swap(true) {
		mgr.log.Panic("Cannot start the watch store manager twice")
	}
}

func (mgr *wsmCommon) wait() {
	mgr.wg.Wait()
	mgr.log.Info("Stopped watch store manager")
}

type wsmSync struct {
	wsmCommon

	clusterName string
	backend     WatchStoreBackend
	store       WatchStore
	onUpdate    func(prefix string)
}

// NewWatchStoreManagerSync implements the WatchStoreManager interface, starting the
// registered functions only once the corresponding prefix sync canary has been received.
// This ensures that the synchronization of the keys hosted under the given prefix
// have been successfully synchronized from the external source, even in case an
// ephemeral kvstore is used.
func NewWatchStoreManagerSync(backend WatchStoreBackend, clusterName string) WatchStoreManager {
	mgr := wsmSync{
		wsmCommon:   newWSMCommon(clusterName),
		clusterName: clusterName,
		backend:     backend,
	}

	mgr.store = NewRestartableWatchStore(clusterName, KVPairCreator, &mgr)
	return &mgr
}

// Run starts the manager, blocking until the context is closed and all
// started functions terminated.
func (mgr *wsmSync) Run(ctx context.Context) {
	mgr.run()
	mgr.onUpdate = func(prefix string) { mgr.ready(ctx, prefix) }
	mgr.store.Watch(ctx, mgr.backend, path.Join(kvstore.SyncedPrefix, mgr.clusterName))
	mgr.wait()
}

func (mgr *wsmSync) OnUpdate(k Key)      { mgr.onUpdate(k.GetKeyName()) }
func (mgr *wsmSync) OnDelete(k NamedKey) {}

type wsmImmediate struct {
	wsmCommon
}

// NewWatchStoreManagerImmediate implements the WatchStoreManager interface,
// immediately starting the registered functions once Run() is executed.
func NewWatchStoreManagerImmediate(clusterName string) WatchStoreManager {
	return &wsmImmediate{
		wsmCommon: newWSMCommon(clusterName),
	}
}

// Run starts the manager, blocking until the context is closed and all
// started functions terminated.
func (mgr *wsmImmediate) Run(ctx context.Context) {
	mgr.run()
	for prefix := range mgr.functions {
		mgr.ready(ctx, prefix)
	}
	mgr.wait()
}
