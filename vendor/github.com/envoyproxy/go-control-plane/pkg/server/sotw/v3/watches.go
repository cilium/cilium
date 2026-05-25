package sotw

import (
	"context"
	"reflect"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
)

// watches for all xDS resource types
type watches struct {
	responders map[string]*watch

	// cases is a dynamic select case for the watched channels.
	cases []reflect.SelectCase
}

// newWatches creates and initializes watches.
func newWatches() watches {
	return watches{
		responders: make(map[string]*watch, int(types.UnknownType)),
		cases:      make([]reflect.SelectCase, 0),
	}
}

// addWatch creates a new watch entry in the watches map.
// Watches are sorted by typeURL.
func (w *watches) addWatch(typeURL string, watch *watch) {
	w.responders[typeURL] = watch
}

// close all open watches
func (w *watches) close() {
	for _, watch := range w.responders {
		watch.close()
	}
}

// recomputeWatches rebuilds the known list of dynamic channels if needed
func (w *watches) recompute(ctx context.Context, req <-chan *discovery.DiscoveryRequest) {
	w.cases = w.cases[:0] // Clear the existing cases while retaining capacity.

	w.cases = append(w.cases,
		reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ctx.Done()),
		}, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(req),
		},
	)

	for _, watch := range w.responders {
		w.cases = append(w.cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(watch.response),
		})
	}
}

// watch contains the necessary modifiable data for receiving resource responses
type watch struct {
	cancel   func()
	response chan cache.Response

	sub stream.Subscription
	// Nonce of the latest response sent for this type
	nonce string
}

// close cancels an open watch
func (w *watch) close() {
	if w.cancel != nil {
		w.cancel()
	}
}
