// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// watcherHandle is an identifier for watchers.
type watcherHandle uint64

// callbackManager is a helper structure for Client focused on [un]registering callbacks on resource changes.
type callbackManager struct {
	log *slog.Logger

	src xds.ResourceSource

	// mux protects all fields below.
	mux lock.Mutex
	// watchers maps ID to an instance of a watcher.
	watchers map[watcherHandle]*watcher
	lastID   watcherHandle
}

func newCallbackManager(log *slog.Logger, src xds.ResourceSource) *callbackManager {
	return &callbackManager{
		log:      log,
		src:      src,
		watchers: make(map[watcherHandle]*watcher),
	}
}

// WatcherCallback will be called when a new version of a resource it was
// registered on appears. res will contain all resources of this type.
type WatcherCallback func(res *xds.VersionedResources)

// Add registers a callback for a specified typeUrl.
// Returned ID can be used to later unregister the callback.
func (c *callbackManager) Add(typeUrl string, cb WatcherCallback) watcherHandle {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.lastID++

	lastSeenVersion, changed := c.src.VersionState()
	l := &watcher{
		typeUrl:         typeUrl,
		cb:              cb,
		log:             c.log.With(logfields.ListenerID, c.lastID),
		resources:       c.src,
		stop:            make(chan struct{}),
		lastSeenVersion: lastSeenVersion,
		changed:         changed,
	}
	go l.process()
	c.watchers[c.lastID] = l

	return watcherHandle(c.lastID)
}

// Remove unregisters a callback with given ID. It does nothing if ID is not found.
func (c *callbackManager) Remove(id watcherHandle) {
	c.mux.Lock()
	defer c.mux.Unlock()

	l, ok := c.watchers[id]
	if !ok {
		// Not found or already deleted.
		return
	}
	delete(c.watchers, id)
	close(l.stop)
}

// watcher is a helper structure for callbackManager focused on handling
// a single, registered callback.
type watcher struct {
	typeUrl string
	cb      WatcherCallback
	stop    chan struct{}

	log             *slog.Logger
	resources       xds.ResourceSource
	lastSeenVersion uint64
	changed         <-chan struct{}
}

// process waits for a new source version and invokes the callback function.
func (w *watcher) process() {
	for {
		select {
		case <-w.stop:
			return
		case <-w.changed:
		}

		version, changed := w.resources.VersionState()
		w.changed = changed
		if version <= w.lastSeenVersion {
			continue
		}

		w.lastSeenVersion = version
		resVer := w.resources.GetResources(w.typeUrl, 0, nil)
		w.log.Debug("Invoke callback")
		w.cb(resVer)
	}
}
