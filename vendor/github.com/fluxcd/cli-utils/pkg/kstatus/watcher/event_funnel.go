// Copyright 2022 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"

	"github.com/fluxcd/cli-utils/pkg/kstatus/polling/event"
	"k8s.io/klog/v2"
)

// eventFunnel wraps a list of event channels and multiplexes them down to a
// single event channel. New input channels can be added at runtime, and the
// output channel will remain open until all input channels are closed.
type eventFunnel struct {
	// ctx closure triggers shutdown
	ctx context.Context
	// outCh is the funnel that consumes all events from input channels
	outCh chan event.Event
	// doneCh is closed after outCh is closed.
	// This allows blocking until done without consuming events.
	doneCh chan struct{}
	// counterCh is used to track the number of open input channels.
	counterCh chan int
}

func newEventFunnel(ctx context.Context) *eventFunnel {
	funnel := &eventFunnel{
		ctx:       ctx,
		outCh:     make(chan event.Event),
		doneCh:    make(chan struct{}),
		counterCh: make(chan int),
	}
	// Wait until the context is done and all input channels are closed.
	// Then close out and done channels to signal completion.
	go func() {
		defer func() {
			// Don't close counterCh, otherwise AddInputChannel may panic.
			klog.V(5).Info("Closing funnel")
			close(funnel.outCh)
			close(funnel.doneCh)
		}()
		ctxDoneCh := ctx.Done()

		// Count input channels that have been added and not closed.
		inputs := 0
		for {
			select {
			case delta := <-funnel.counterCh:
				inputs += delta
				klog.V(5).Infof("Funnel input channels (%+d): %d", delta, inputs)
			case <-ctxDoneCh:
				// Stop waiting for context closure.
				// Nil channel avoids busy waiting.
				ctxDoneCh = nil
			}
			if ctxDoneCh == nil && inputs <= 0 {
				// Context is closed and all input channels are closed.
				break
			}
		}
	}()
	return funnel
}

// Add a new input channel to the multiplexer.
func (m *eventFunnel) AddInputChannel(inCh <-chan event.Event) error {
	select {
	case <-m.ctx.Done(): // skip, if context is closed
		return &EventFunnelClosedError{ContextError: m.ctx.Err()}
	case m.counterCh <- 1: // increment counter
	}

	// Create a multiplexer for each new event channel.
	go m.drain(inCh, m.outCh)
	return nil
}

// OutputChannel channel receives all events sent to input channels.
// This channel is closed after all input channels are closed.
func (m *eventFunnel) OutputChannel() <-chan event.Event {
	return m.outCh
}

// Done channel is closed after the Output channel is closed.
// This allows blocking until done without consuming events.
// If no input channels have been added yet, the done channel will be nil.
func (m *eventFunnel) Done() <-chan struct{} {
	return m.doneCh
}

// drain a single input channel to a single output channel.
func (m *eventFunnel) drain(inCh <-chan event.Event, outCh chan<- event.Event) {
	defer func() {
		m.counterCh <- -1 // decrement counter
	}()
	for event := range inCh {
		outCh <- event
	}
}

type EventFunnelClosedError struct {
	ContextError error
}

func (e *EventFunnelClosedError) Error() string {
	return fmt.Sprintf("event funnel closed: %v", e.ContextError)
}

func (e *EventFunnelClosedError) Is(err error) bool {
	fcErr, ok := err.(*EventFunnelClosedError)
	if !ok {
		return false
	}
	return e.ContextError == fcErr.ContextError
}

func (e *EventFunnelClosedError) Unwrap() error {
	return e.ContextError
}
