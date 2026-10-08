package delta

import (
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
)

// watches for all delta xDS resource types
type watches struct {
	deltaWatches map[string]watch

	// Opaque resources share a muxed channel
	deltaMuxedResponses chan cache.DeltaResponse
}

// newWatches creates and initializes watches.
func newWatches() watches {
	// deltaMuxedResponses needs a buffer to release go-routines populating it
	//
	// because deltaMuxedResponses can be populated by an update from the cache
	// and a request from the client, we need to create the channel with a buffer
	// size of 2x the number of types to avoid deadlocks.
	return watches{
		deltaWatches:        make(map[string]watch, int(types.UnknownType)),
		deltaMuxedResponses: make(chan cache.DeltaResponse, int(types.UnknownType)*2),
	}
}

// Cancel all watches
func (w *watches) Cancel() {
	for _, watch := range w.deltaWatches {
		watch.Cancel()
	}

	close(w.deltaMuxedResponses)
}

// watch contains the necessary modifiables for receiving resource responses
type watch struct {
	cancel func()
	nonce  string

	subscription stream.Subscription
}

// Cancel calls terminate and cancel
func (w *watch) Cancel() {
	if w.cancel != nil {
		w.cancel()
	}
}
