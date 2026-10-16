// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"log/slog"

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
		logfields.XDSTypeURL, r.typeURL,
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
