// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"github.com/fluxcd/cli-utils/pkg/object"
)

// BlindStatusWatcher sees nothing.
// BlindStatusWatcher sends no update or error events.
// BlindStatusWatcher waits patiently to be cancelled.
// BlindStatusWatcher implements the StatusWatcher interface.
type BlindStatusWatcher struct{}

var _ StatusWatcher = BlindStatusWatcher{}

// Watch nothing. See no changes.
func (w BlindStatusWatcher) Watch(ctx context.Context, _ object.ObjMetadataSet, _ Options) <-chan event.Event {
	doneCh := ctx.Done()
	eventCh := make(chan event.Event)
	go func() {
		// Send SyncEvent immediately.
		eventCh <- event.Event{Type: event.SyncEvent}
		// Block until the context is cancelled.
		<-doneCh
		// Signal to the caller there will be no more events.
		close(eventCh)
	}()
	return eventCh
}
