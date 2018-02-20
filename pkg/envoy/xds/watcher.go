// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds

import (
	"context"
	"fmt"
	"sync"
	"time"

	envoy_api_v2_core "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/sirupsen/logrus"
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
			logfields.XDSVersionInfo: version,
			logfields.XDSTypeURL:     typeURL,
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
func (w *ResourceWatcher) WatchResources(ctx context.Context, typeURL string, lastVersion *uint64, node *envoy_api_v2_core.Node,
	resourceNames []string, out chan<- *VersionedResources) {
	defer close(out)

	watchLog := log.WithFields(logrus.Fields{
		logfields.XDSVersionInfo: lastVersion,
		logfields.XDSClientNode:  node,
		logfields.XDSTypeURL:     typeURL,
	})

	var res *VersionedResources

	var waitVersion uint64
	var waitForVersion bool
	if lastVersion != nil {
		waitForVersion = true
		waitVersion = *lastVersion
	}

	for ctx.Err() == nil && res == nil {
		w.versionLocker.Lock()
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
		res, err = w.resourceSet.GetResources(subCtx, typeURL, lastVersion, node, resourceNames)
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
