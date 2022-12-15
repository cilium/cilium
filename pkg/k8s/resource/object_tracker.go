package resource

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
)

// ObjectTracker provides a lightweight mechanism for tracking the object changes
// of a dynamically changing set.
//
// This is a useful building block when merging information
// from multiple objects. For example a CiliumLocalRedirectPolicy can target
// a specific service, so in order to produce a load-balancing frontend for
// a redirect policy it needs to be merged with a service.
type ObjectTracker[Obj runtime.Object] interface {
	// Events returns the event channel for this tracker.
	// Sync event is not included.
	// Closed when the context used to create the ObjectTracker
	// is cancelled.
	Events() <-chan Event[Obj]

	// Track adds a key to the set of objects to be tracked. If
	// an object with the given key exists, an upsert event is
	// immediately emitted.
	Track(Key)

	// Untrack removes a key from the set of objects to be tracked.
	Untrack(Key)

	// TODO
	TrackBy(func(Obj) bool) (untrack func())
}

type objectTracker[Obj runtime.Object] struct {
	events   chan Event[Obj]
	resource Resource[Obj]
	track    chan Key
	untrack  chan Key
}

type trackRequest struct {
}

func newObjectTracker[Obj runtime.Object](ctx context.Context, res Resource[Obj]) ObjectTracker[Obj] {
	ot := &objectTracker[Obj]{
		events:   make(chan Event[Obj]),
		resource: res,
		track:    make(chan Key),
		untrack:  make(chan Key),
	}
	go ot.processLoop(ctx)
	return ot
}

func (ot *objectTracker[Obj]) Track(key Key) {
	ot.track <- key
}

func (ot *objectTracker[Obj]) Untrack(key Key) {
	ot.untrack <- key
}

func (ot *objectTracker[Obj]) TrackBy(match func(Obj) bool) (untrack func()) {
	// TODO idea was to use this for tracking endpoint slices that match specific
	// services in pkg/k8s/service_dialer.go.
	// TODO and use this in redirect policy handler to match on pods that are selected by the
	// policy config.
	panic("TBD")
}

func (ot *objectTracker[Obj]) Events() <-chan Event[Obj] {
	return ot.events
}

func (ot *objectTracker[Obj]) processLoop(ctx context.Context) {
	var (
		trackedKeys sync.Map
		requeues    = make(chan Key)
	)

	defer close(ot.events)
	defer close(requeues)

	// Subscribe to events that are part of the tracked set.
	allEvents := ot.resource.Events(
		ctx,

		// Only process events for a specific key.
		WithFilter(func(obj Obj) bool {
			_, ok := trackedKeys.Load(NewKey(obj))
			return ok
		}),
		WithRequeues(requeues),
	)

	startTracking := func(key Key) {
		// Add the key to the tracked set and
		// tell resource to queue up the handling for the key.
		trackedKeys.Store(key, true)
		requeues <- key
	}
	stopTracking := func(key Key) {
		trackedKeys.Delete(key)
	}

	sendEvent := func(ev Event[Obj]) {
		for {
			select {
			case key := <-ot.track:
				startTracking(key)

			case key := <-ot.untrack:
				stopTracking(key)

			case ot.events <- ev:
				return
			}
		}
	}

	for {
		select {
		case key := <-ot.track:
			startTracking(key)

		case key := <-ot.untrack:
			stopTracking(key)

		case ev, ok := <-allEvents:
			if !ok {
				return
			}
			if ev.Kind != Sync {
				sendEvent(ev)
			} else {
				ev.Done(nil)
			}
		}
	}
}
