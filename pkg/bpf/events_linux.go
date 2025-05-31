// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

func (m *Map) initEventsBuffer(maxSize int, eventsTTL time.Duration) {
	b := &eventsBuffer{
		logger:   m.Logger,
		buffer:   container.NewRingBuffer(maxSize),
		eventTTL: eventsTTL,
	}
	if b.eventTTL > 0 {
		m.Logger.Debug("starting bpf map event buffer GC controller")
		mapControllers.UpdateController(
			fmt.Sprintf("bpf-event-buffer-gc-%s", m.name),
			controller.ControllerParams{
				Group: bpfEventBufferGCControllerGroup,
				DoFunc: func(_ context.Context) error {
					m.Logger.Debug(
						"clearing bpf map events older than TTL",
						logfields.TTL, b.eventTTL,
					)
					b.buffer.Compact(func(e any) bool {
						event, ok := e.(*Event)
						if !ok {
							m.Logger.Error("Failed to compact the event buffer", logfields.Error, wrongObjTypeErr(e))
							return false
						}
						return time.Since(event.Timestamp) < b.eventTTL
					})
					return nil
				},
				RunInterval: b.eventTTL,
			},
		)
	}
	m.events = b
}

// DumpAndSubscribe dumps existing buffer, if callback is not nil. Followed by creating a
// subscription to the maps events buffer and returning the handle.
// These actions are done together so as to prevent possible missed events between the handoff
// of the callback and sub handle creation.
func (m *Map) DumpAndSubscribe(callback EventCallbackFunc, follow bool) (*Handle, error) {
	// note: we have to hold rlock for the duration of this to prevent missed events between dump and sub.
	// dumpAndSubscribe maintains its own write-lock for updating subscribers.
	m.lock.RLock()
	defer m.lock.RUnlock()
	if !m.eventsBufferEnabled {
		return nil, fmt.Errorf("map events not enabled for map %q", m.name)
	}
	return m.events.dumpAndSubscribe(callback, follow)
}

func (m *Map) IsEventsEnabled() bool {
	return m.eventsBufferEnabled
}
