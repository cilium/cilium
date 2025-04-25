// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ResourceWatcher watches and retrieves new versions of resources from a
// resource set.
// ResourceWatcher implements ResourceVersionObserver to get notified when new
// resource versions are available in the set.
type ResourceWatcher struct {
	logger *slog.Logger
	// typeURL is the URL that uniquely identifies the resource type.
	typeURL string

	// resourceSet is the set of resources to watch.
	resourceSet ResourceSource

	// version is the current version of the resources. Updated in calls to
	// NotifyNewVersion.
	// Versioning starts at 1.
	version uint64

	// versionLocker is used to lock all accesses to version.
	versionLocker lock.Mutex

	// versionCond is a condition that is broadcast whenever the source's
	// current version is increased.
	// versionCond is associated with versionLocker.
	versionCond *sync.Cond
}

// NewResourceWatcher creates a new ResourceWatcher backed by the given
// resource set.
func NewResourceWatcher(logger *slog.Logger, typeURL string, resourceSet ResourceSource) *ResourceWatcher {
	w := &ResourceWatcher{
		logger:      logger,
		version:     1,
		typeURL:     typeURL,
		resourceSet: resourceSet,
	}
	w.versionCond = sync.NewCond(&w.versionLocker)
	return w
}

func (w *ResourceWatcher) HandleNewResourceVersion(typeURL string, version uint64) {
	w.versionLocker.Lock()
	defer w.versionLocker.Unlock()

	if typeURL != w.typeURL {
		return
	}

	if version < w.version {
		logging.Fatal(w.logger,
			"decreasing version number found for resources: xdsCachedVersion < resourceWatcherVersion",
			logfields.XDSCachedVersion, version,
			logfields.ResourceWatcherVersion, w.version,
			logfields.XDSTypeURL, typeURL,
		)
	}
	w.version = version

	w.versionCond.Broadcast()
}

// WatchResources watches for new versions of specific resources and sends them
// into the given out channel.
//
// A call to this method blocks until a version greater than lastVersion is
// available. Therefore, every call must be done in a separate goroutine.
// A watch can be canceled by canceling the given context.
//
// lastVersion is the last version successfully applied by the
// client; nil if this is the first request for resources.
// This method call must always close the out channel.
func (w *ResourceWatcher) WatchResources(ctx context.Context, typeURL string, lastVersion, previouslyAckedVersion uint64, nodeIP string,
	resourceNames []string, out chan<- *VersionedResources) {
	defer close(out)

	scopedLog := w.logger.With(
		logfields.XDSAckedVersion, lastVersion,
		logfields.XDSClientNode, nodeIP,
		logfields.XDSTypeURL, typeURL,
	)

	var res *VersionedResources

	var waitVersion uint64
	var waitForVersion bool
	if lastVersion != 0 {
		waitForVersion = true
		waitVersion = lastVersion
	}

	for ctx.Err() == nil && res == nil {
		w.versionLocker.Lock()
		// lastVersion == 0 indicates that this is a new stream and
		// previouslyAckedVersion comes from previous instance of xDS server.
		// In this case, we artificially increase the version of the resource set.
		if w.version <= previouslyAckedVersion && lastVersion == 0 {
			w.versionLocker.Unlock()
			// Calling EnsureVersion will increase the version of the resource
			// set, which in turn will callback w.HandleNewResourceVersion with
			// that new version number. In order for that callback to not
			// deadlock, temporarily unlock w.versionLocker.
			// The w.HandleNewResourceVersion callback will update w.version to
			// the new resource set version.
			w.resourceSet.EnsureVersion(typeURL, previouslyAckedVersion+1)
			w.versionLocker.Lock()
		}

		// Re-check w.version, since it may have been modified by calling
		// EnsureVersion above.
		for ctx.Err() == nil && waitForVersion && w.version <= waitVersion {
			scopedLog.Debug("waiting for current version to increase up to waitVersion",
				logfields.WaitVersion, waitVersion,
				logfields.CurrentVersion, w.version,
			)
			w.versionCond.Wait()
		}
		// In case we need to loop again, wait for any version more recent than
		// the current one.
		waitForVersion = true
		waitVersion = w.version
		w.versionLocker.Unlock()

		if ctx.Err() != nil {
			break
		}

		scopedLog.Debug("getting resources from set",
			logfields.Resources, len(resourceNames),
		)
		var err error
		res, err = w.resourceSet.GetResources(typeURL, lastVersion, nodeIP, resourceNames)
		if err != nil {
			scopedLog.Error("failed to query resources; terminating resource watch",
				logfields.Error, err,
				logfields.Resources, resourceNames,
			)
			return
		}
	}

	if res != nil {
		// Resources have changed since the last version returned to the
		// client. Send out the new version.
		select {
		case <-ctx.Done():
		case out <- res:
			return
		}
	}

	err := ctx.Err()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			scopedLog.Debug("context canceled, terminating resource watch")
		} else {
			scopedLog.Error("context error, terminating resource watch", logfields.Error, err)
		}
	}
}
