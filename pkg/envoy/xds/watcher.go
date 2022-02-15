// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ResourceWatcher watches and retrieves new versions of resources from a
// resource set.
// ResourceWatcher implements ResourceVersionObserver to get notified when new
// resource versions are available in the set.
type ResourceWatcher struct {
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

	// resourceAccessTimeout is the timeout to use for any access to the
	// resource set.
	resourceAccessTimeout time.Duration
}

// NewResourceWatcher creates a new ResourceWatcher backed by the given
// resource set.
func NewResourceWatcher(typeURL string, resourceSet ResourceSource, resourceAccessTimeout time.Duration) *ResourceWatcher {
	w := &ResourceWatcher{
		version:               1,
		typeURL:               typeURL,
		resourceSet:           resourceSet,
		resourceAccessTimeout: resourceAccessTimeout,
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
		log.WithFields(logrus.Fields{
			logfields.XDSCachedVersion: version,
			logfields.XDSTypeURL:       typeURL,
		}).Panicf(fmt.Sprintf("decreasing version number found for resources of type %s: %d < %d",
			typeURL, version, w.version))
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
func (w *ResourceWatcher) WatchResources(ctx context.Context, typeURL string, lastVersion uint64, nodeIP string,
	resourceNames []string, out chan<- *VersionedResources) {
	defer close(out)

	watchLog := log.WithFields(logrus.Fields{
		logfields.XDSAckedVersion: lastVersion,
		logfields.XDSClientNode:   nodeIP,
		logfields.XDSTypeURL:      typeURL,
	})

	var res *VersionedResources

	var waitVersion uint64
	var waitForVersion bool
	if lastVersion != 0 {
		waitForVersion = true
		waitVersion = lastVersion
	}

	for ctx.Err() == nil && res == nil {
		w.versionLocker.Lock()
		// If the client ACKed a version that we have never sent back, this
		// indicates that this server restarted but the client survived and had
		// received a higher version number from the previous server instance.
		// Bump the resource set's version number to match the client's and
		// send a response immediately.
		if waitForVersion && w.version < waitVersion {
			w.versionLocker.Unlock()
			// Calling EnsureVersion will increase the version of the resource
			// set, which in turn will callback w.HandleNewResourceVersion with
			// that new version number. In order for that callback to not
			// deadlock, temporarily unlock w.versionLocker.
			// The w.HandleNewResourceVersion callback will update w.version to
			// the new resource set version.
			w.resourceSet.EnsureVersion(typeURL, waitVersion+1)
			w.versionLocker.Lock()
		}

		// Re-check w.version, since it may have been modified by calling
		// EnsureVersion above.
		for ctx.Err() == nil && waitForVersion && w.version <= waitVersion {
			watchLog.Debugf("current resource version is %d, waiting for it to become > %d", w.version, waitVersion)
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

		subCtx, cancel := context.WithTimeout(ctx, w.resourceAccessTimeout)
		var err error
		watchLog.Debugf("getting %d resources from set", len(resourceNames))
		res, err = w.resourceSet.GetResources(subCtx, typeURL, lastVersion, nodeIP, resourceNames)
		cancel()

		if err != nil {
			watchLog.WithError(err).Errorf("failed to query resources named: %v; terminating resource watch", resourceNames)
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
		switch err {
		case context.Canceled:
			watchLog.Debug("context canceled, terminating resource watch")
		default:
			watchLog.WithError(err).Error("context error, terminating resource watch")
		}
	}
}
