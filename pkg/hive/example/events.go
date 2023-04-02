// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/cilium/workerpool"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/stream"
)

// eventsCell provides the ExampleEvents API for subscribing
// to a stream of example events.
var eventsCell = cell.Module(
	"example-events",
	"Provides a stream of example events",

	cell.Provide(newExampleEvents),
)

type ExampleEvent struct {
	Message string
}

type ExampleEvents interface {
	stream.Observable[ExampleEvent]
}

type exampleEventSource struct {
	stream.Observable[ExampleEvent]

	wp *workerpool.WorkerPool // Worker pool for background workers

	emit     func(ExampleEvent) // Emits an item to 'src'
	complete func(error)        // Completes 'src'
}

func (es *exampleEventSource) Start(hive.HookContext) error {
	es.wp = workerpool.New(1)
	// Start the emitter
	return es.wp.Submit("emitter", es.emitter)
}

func (es *exampleEventSource) Stop(hive.HookContext) error {
	defer es.complete(nil)

	// Cancel all background workers and wait for them to stop
	return es.wp.Close()
}

func (es *exampleEventSource) emitter(ctx context.Context) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			es.emit(makeEvent())
		}
	}
}

// makeEvent generates a random event
func makeEvent() ExampleEvent {
	var prefixes = []string{
		"Thrusters set to",
		"Main engine damage at",
		"Laser power set to",
		"Remaining hypercannon fuel:",
		"Reserve of peanut butter sandwiches:",
		"Crew morale at",
		"Elevator music volume now set to",
		"Mission completion: ",
	}

	prefixIdx := rand.Intn(len(prefixes))
	percentage := rand.Intn(100)

	return ExampleEvent{
		Message: fmt.Sprintf("%s %d%%", prefixes[prefixIdx], percentage),
	}
}

func newExampleEvents(lc hive.Lifecycle) ExampleEvents {
	es := &exampleEventSource{}
	// Multicast() constructs a one-to-many observable to which items can be emitted.
	es.Observable, es.emit, es.complete = stream.Multicast[ExampleEvent]()
	lc.Append(es)
	return es
}
