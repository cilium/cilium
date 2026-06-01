// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"log/slog"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type sotwWatchRequest struct {
	logger              *slog.Logger
	source              ResourceSource
	typeURL             string
	lastReceivedVersion uint64
	lastAckedVersion    uint64
	resourceNames       []string
	interestExpanded    bool
}

type deltaWatchRequest struct {
	logger              *slog.Logger
	source              ResourceSource
	typeURL             string
	lastReceivedVersion uint64
	lastAckedVersion    uint64
	subscriptions       set.Set[string]
	ackedResourceNames  set.Set[string]
	forceResponseNames  set.Set[string]
	immediate           bool
	forceEmptyResponse  bool
}

func waitForVersion(ctx context.Context, logger *slog.Logger, source ResourceSource, waitVersion uint64) error {
	for {
		currentVersion, changed := source.VersionState()
		if currentVersion > waitVersion {
			return nil
		}

		logger.Debug("waiting for current version to increase up to waitVersion",
			logfields.WaitVersion, waitVersion,
			logfields.CurrentVersion, currentVersion,
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// WatchResources watches for new versions of specific resources and sends them into the
// given out channel.
//
// A call to this method blocks until a version greater than lastReceivedVersion is
// available. Therefore, every call must be done in a separate goroutine.
// A watch can be canceled by canceling the given context.
//
// lastAckedVersion is the last version successfully applied by the
// client; zero if this is the first request for resources.
// interestExpanded indicates that the tracked request expanded and therefore needs
// one immediate snapshot before waiting for a newer cache version.
// This method call must always close the out channel.
func (r sotwWatchRequest) WatchResources(ctx context.Context, out chan<- *VersionedResources) {
	defer close(out)

	scopedLog := r.logger.With(
		logfields.XDSAckedVersion, r.lastReceivedVersion,
	)

	var res *VersionedResources

	waitVersion := r.lastReceivedVersion
	waitForNextVersion := !r.interestExpanded && r.lastReceivedVersion != 0

	queryVersion := uint64(0)
	if waitForNextVersion {
		queryVersion = r.lastReceivedVersion
	}

	for ctx.Err() == nil && res == nil {
		currentVersion, _ := r.source.VersionState()

		// lastReceivedVersion == 0 indicates that this is a new stream and
		// lastAckedVersion comes from previous instance of xDS client.
		// In this case, we artificially increase the version of the resource set
		// to trigger sending a new version to the client.
		if currentVersion <= r.lastAckedVersion && r.lastReceivedVersion == 0 {
			r.source.EnsureVersion(r.typeURL, r.lastAckedVersion+1)
			continue
		}
		if r.interestExpanded && currentVersion <= r.lastReceivedVersion {
			// When the requested resource set expands without any underlying cache
			// update, bump the resource-set version once so the immediate response
			// carries a fresh nonce/version for its different resource contents.
			r.source.EnsureVersion(r.typeURL, r.lastReceivedVersion+1)
			continue
		}

		if waitForNextVersion {
			if err := waitForVersion(ctx, scopedLog, r.source, waitVersion); err != nil {
				break
			}
		}
		waitForNextVersion = true

		currentVersion, _ = r.source.VersionState()
		waitVersion = currentVersion

		scopedLog.Debug("getting resources from set",
			logfields.Resources, len(r.resourceNames),
		)

		res = r.source.GetResources(r.typeURL, queryVersion, r.resourceNames)
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

// WatchResources watches for delta xDS changes for the tracked subscriptions and sends
// them into the given out channel.
//
// immediate indicates whether the current request changed the tracked set and
// therefore needs an immediate diff before waiting for a newer cache version.
// When 'r.forceEmptyResponse' is 'true' a response is sent even if the set of
// resources is empty. This is needed for initial sync with Envoy.
// This method call must always close the out channel.
func (r deltaWatchRequest) WatchResources(ctx context.Context, out chan<- *VersionedResources) {
	defer close(out)

	scopedLog := r.logger.With(
		logfields.XDSAckedVersion, r.lastReceivedVersion,
	)

	var res *VersionedResources
	waitForNextVersion := !r.immediate && r.lastReceivedVersion != 0
	waitVersion := r.lastReceivedVersion
	forceResponseNames := r.forceResponseNames

	for ctx.Err() == nil && res == nil {
		if waitForNextVersion {
			if err := waitForVersion(ctx, scopedLog, r.source, waitVersion); err != nil {
				break
			}
		}
		waitForNextVersion = true

		currentVersion, _ := r.source.VersionState()
		waitVersion = currentVersion

		scopedLog.Debug("getting delta resources from set",
			logfields.Resources, r.subscriptions.Len(),
		)
		res = r.source.GetDeltaResources(r.typeURL, r.lastAckedVersion, r.subscriptions, r.ackedResourceNames, forceResponseNames, r.forceEmptyResponse)
		// No point forcing response names if the first round gets nothing.
		// forceResponseNames is a local shallow copy of the read-only r.forceResponseNames,
		// this does not mutate the watch request.
		forceResponseNames.Clear()
	}

	if res != nil {
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
