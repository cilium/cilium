// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package wait

import (
	"context"
	"errors"
)

var (
	// ErrRemoteClusterDisconnected is the error returned by wait for sync
	// operations if the remote cluster is disconnected while still waiting.
	ErrRemoteClusterDisconnected = errors.New("remote cluster disconnected")
)

// SyncedCommon contains common fields and methods used for tracking the
// synchronization status of a remote cluster.
type SyncedCommon struct {
	stopped chan struct{}
}

// NewSyncedCommon returns a new SyncedCommon instance.
func NewSyncedCommon() SyncedCommon {
	return SyncedCommon{
		stopped: make(chan struct{}),
	}
}

// Wait returns after all of the given channels have been closed, the remote
// cluster has been disconnected, or the given context has been cancelled.
func (sc *SyncedCommon) Wait(ctx context.Context, chs ...<-chan struct{}) error {
	for _, ch := range chs {
		select {
		case <-ch:
			continue
		case <-sc.stopped:
			return ErrRemoteClusterDisconnected
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (sc *SyncedCommon) Stop() {
	close(sc.stopped)
}

// Fn is the type of a function to wait for the initial synchronization
// of a given resource type from all remote clusters.
type Fn func(ctx context.Context) error

// ForAll returns after the all of the provided waiters have been executed.
func ForAll(ctx context.Context, waiters []Fn) error {
	for _, wait := range waiters {
		err := wait(ctx)

		// Ignore the error in case the given cluster was disconnected in
		// the meanwhile, as we do not longer care about it.
		if err != nil && !errors.Is(err, ErrRemoteClusterDisconnected) {
			return err
		}
	}
	return nil
}
