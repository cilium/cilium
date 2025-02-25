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

	src xds.ObservableResourceSource

	// mux protects all fields below.
	mux lock.Mutex
	// watchers maps ID to an instance of a watcher.
	watchers map[watcherHandle]*watcher
	lastID   watcherHandle
}

func newCallbackManager(log *slog.Logger, src xds.ObservableResourceSource) *callbackManager {
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

	l := &watcher{
		typeUrl:   typeUrl,
		cb:        cb,
		log:       c.log.With(logfields.ListenerID, c.lastID),
		resources: c.src,
		trigger:   make(chan struct{}, 1),
	}
	go l.process()
	c.src.AddResourceVersionObserver(l)
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
	c.src.RemoveResourceVersionObserver(l)
	delete(c.watchers, id)
	close(l.trigger)
}

// watcher is a helper structure for callbackManager focused on handling
// a single, registered callback.
type watcher struct {
	typeUrl string
	cb      WatcherCallback
	trigger chan struct{}

	log       *slog.Logger
	resources xds.ResourceSource
}

// watcher implements xds.ResourceVersionObserver.
var _ xds.ResourceVersionObserver = (*watcher)(nil)

// HandleNewResourceVersion implements xds.ResourceVersionObserver.
// It triggers the callback process.
func (w *watcher) HandleNewResourceVersion(typeUrl string, _ uint64) {
	if typeUrl != w.typeUrl {
		w.log.Error("Called with wrong type URL",
			logfields.Got, typeUrl,
			logfields.Want, w.typeUrl)
		return
	}
	select {
	case w.trigger <- struct{}{}:
	default:
		// As l.trigger is a buffered channel, it means that:
		//   - process is currently executing a callback
		//   - trigger is queued, so callback will be invoked right after the
		//     current execution returns
		//
		// There is no need to queue another trigger as the current one will
		// fetch the latest version of the resources. The result is the same as
		// if we maneged to queue up another trigger.
	}
}

// process waits for the trigger (new resource version) and invokes the callback
// function. It needs to be done asynchronously from HandleNewResourceVersion,
// because the cache invoking the function holds a lock on the resources.
func (l *watcher) process() {
	for range l.trigger {
		resVer, err := l.resources.GetResources(l.typeUrl, 0, "", nil)
		if err != nil {
			l.log.Error("Failed to fetch resource", logfields.Error, err)
			continue
		}

		l.log.Debug("Invoke callback")
		l.cb(resVer)
	}
}
