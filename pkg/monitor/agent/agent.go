// Copyright 2017-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	oldBPF "github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const eventsMapName = "cilium_events"

// isCtxDone is a utility function that returns true when the context's Done()
// channel is closed. It is intended to simplify goroutines that need to check
// this multiple times in their loop.
func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// Agent structure for centralizing the responsibilities of the main events
// reader.
// There is some racey-ness around perfReaderCancel since it replaces on every
// perf reader start. In the event that a MonitorListener from a previous
// generation calls its cleanup after the start of the new perf reader, we
// might call the new, and incorrect, cancel function. We guard for this by
// checking the number of listeners during the cleanup call. The perf reader
// must have at least one MonitorListener (since it started) so no cancel is called.
// If it doesn't, the cancel is the correct behavior (the older generation
// cancel must have been called for us to get this far anyway).
type Agent struct {
	lock.Mutex
	models.MonitorStatus

	ctx              context.Context
	perfReaderCancel context.CancelFunc

	// listeners are external cilium monitor clients which receive raw
	// gob-encoded payloads
	listeners map[listener.MonitorListener]struct{}
	// consumers are internal clients which receive decoded messages
	consumers map[consumer.MonitorConsumer]struct{}

	events        *ebpf.Map
	monitorEvents *perf.Reader
}

// NewAgent starts a new monitor agent instance which distributes monitor events
// to registered listeners. Once the datapath is set up, AttachToEventsMap needs
// to be called to receive events from the perf ring buffer. Otherwise, only
// user space events received via SendEvent are distributed registered listeners.
// Internally, the agent spawns a singleton goroutine reading events from
// the BPF perf ring buffer and provides an interface to pass in non-BPF events.
// The instance can be stopped by cancelling ctx, which will stop the perf reader
// go routine and close all registered listeners.
// Note that the perf buffer reader is started only when listeners are
// connected.
func NewAgent(ctx context.Context) *Agent {
	return &Agent{
		ctx:              ctx,
		listeners:        make(map[listener.MonitorListener]struct{}),
		consumers:        make(map[consumer.MonitorConsumer]struct{}),
		perfReaderCancel: func() {}, // no-op to avoid doing null checks everywhere
	}
}

// AttachToEventsMap opens the events perf ring buffer and makes it ready for
// consumption, such that any subscribed consumers may receive events
// from it. This function is to be called once the events map has been set up.
func (a *Agent) AttachToEventsMap(nPages int) error {
	a.Lock()
	defer a.Unlock()

	if a.events != nil {
		return errors.New("events map already attached")
	}

	// assert that we can actually connect the monitor
	path := oldBPF.MapPath(eventsMapName)
	eventsMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}

	a.events = eventsMap
	a.MonitorStatus = models.MonitorStatus{
		Cpus:     int64(eventsMap.MaxEntries()),
		Npages:   int64(nPages),
		Pagesize: int64(os.Getpagesize()),
	}

	// start the perf reader if we already have subscribers
	if a.hasSubscribersLocked() {
		a.startPerfReaderLocked()
	}

	return nil
}

// SendEvent distributes an event to all monitor listeners
func (a *Agent) SendEvent(typ int, event interface{}) error {
	if a == nil {
		return fmt.Errorf("monitor agent is not set up")
	}

	a.notifyAgentEvent(typ, event)

	// marshal notifications into JSON format for legacy listeners
	if typ == api.MessageTypeAgent {
		msg, ok := event.(api.AgentNotifyMessage)
		if !ok {
			return errors.New("unexpected event type for MessageTypeAgent")
		}
		var err error
		event, err = msg.ToJSON()
		if err != nil {
			return fmt.Errorf("unable to JSON encode agent notification: %w", err)
		}
	}

	var buf bytes.Buffer
	if err := buf.WriteByte(byte(typ)); err != nil {
		return fmt.Errorf("unable to initialize buffer: %w", err)
	}
	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		return fmt.Errorf("unable to gob encode: %w", err)
	}

	p := payload.Payload{Data: buf.Bytes(), CPU: 0, Lost: 0, Type: payload.EventSample}
	a.sendToListeners(&p)

	return nil
}

// Context returns the underlying context of this monitor instance. It can be
// used to derive other contexts which should be stopped when the monitor is
// stopped.
func (a *Agent) Context() context.Context {
	return a.ctx
}

// hasSubscribersLocked returns true if there are listeners subscribed to the
// agent right now.
func (a *Agent) hasSubscribersLocked() bool {
	return len(a.listeners)+len(a.consumers) != 0
}

// startPerfReaderLocked starts the perf reader. This should only be
// called if there are no other readers already running.
// The goroutine is spawned with a context derived from m.Context() and the
// cancelFunc is assigned to perfReaderCancel. Note that cancelling m.Context()
// (e.g. on program shutdown) will also cancel the derived context.
// Note: it is critical to hold the lock for this operation.
func (a *Agent) startPerfReaderLocked() {
	if a.events == nil {
		return // not attached to events map yet
	}

	a.perfReaderCancel() // don't leak any old readers, just in case.
	perfEventReaderCtx, cancel := context.WithCancel(a.ctx)
	a.perfReaderCancel = cancel
	go a.handleEvents(perfEventReaderCtx)
}

// RegisterNewListener adds the new MonitorListener to the global list.
// It also spawns a singleton goroutine to read and distribute the events.
func (a *Agent) RegisterNewListener(newListener listener.MonitorListener) {
	if a == nil {
		return
	}

	a.Lock()
	defer a.Unlock()

	if isCtxDone(a.ctx) {
		log.Debug("RegisterNewListener called on stopped monitor")
		newListener.Close()
		return
	}

	// If this is the first listener, start the perf reader
	if !a.hasSubscribersLocked() {
		a.startPerfReaderLocked()
	}

	version := newListener.Version()
	switch newListener.Version() {
	case listener.Version1_2:
		a.listeners[newListener] = struct{}{}

	default:
		newListener.Close()
		log.WithField("version", version).Error("Closing listener from unsupported monitor client version")
	}

	log.WithFields(logrus.Fields{
		"count.listener": len(a.listeners),
		"version":        version,
	}).Debug("New listener connected")
}

// RemoveListener deletes the MonitorListener from the list, closes its queue,
// and stops perfReader if this is the last subscriber
func (a *Agent) RemoveListener(ml listener.MonitorListener) {
	if a == nil {
		return
	}

	a.Lock()
	defer a.Unlock()

	// Remove the listener and close it.
	delete(a.listeners, ml)
	log.WithFields(logrus.Fields{
		"count.listener": len(a.listeners),
		"version":        ml.Version(),
	}).Debug("Removed listener")
	ml.Close()

	// If this was the final listener, shutdown the perf reader and unmap our
	// ring buffer readers. This tells the kernel to not emit this data.
	// Note: it is critical to hold the lock and check the number of listeners.
	// This guards against an older generation listener calling the
	// current generation perfReaderCancel
	if !a.hasSubscribersLocked() {
		a.perfReaderCancel()
	}
}

// RegisterNewConsumer adds the new MonitorConsumer to the global list.
// It also spawns a singleton goroutine to read and distribute the events.
func (a *Agent) RegisterNewConsumer(newConsumer consumer.MonitorConsumer) {
	if a == nil {
		return
	}

	if isCtxDone(a.ctx) {
		log.Debug("RegisterNewConsumer called on stopped monitor")
		return
	}

	a.Lock()
	defer a.Unlock()

	if !a.hasSubscribersLocked() {
		a.startPerfReaderLocked()
	}
	a.consumers[newConsumer] = struct{}{}
}

// RemoveConsumer deletes the MonitorConsumer from the list, closes its queue,
// and stops perfReader if this is the last subscriber
func (a *Agent) RemoveConsumer(mc consumer.MonitorConsumer) {
	if a == nil {
		return
	}

	a.Lock()
	defer a.Unlock()

	delete(a.consumers, mc)
	if !a.hasSubscribersLocked() {
		a.perfReaderCancel()
	}
}

// handleEvents reads events from the perf buffer and processes them. It
// will exit when stopCtx is done. Note, however, that it will block in the
// Poll call but assumes enough events are generated that these blocks are
// short.
func (a *Agent) handleEvents(stopCtx context.Context) {
	scopedLog := log.WithField(logfields.StartTime, time.Now())
	scopedLog.Info("Beginning to read perf buffer")
	defer scopedLog.Info("Stopped reading perf buffer")

	bufferSize := int(a.Pagesize * a.Npages)
	monitorEvents, err := perf.NewReader(a.events, bufferSize)
	if err != nil {
		scopedLog.WithError(err).Fatal("Cannot initialise BPF perf ring buffer sockets")
	}
	defer func() {
		monitorEvents.Close()
		a.Lock()
		a.monitorEvents = nil
		a.Unlock()
	}()

	a.Lock()
	a.monitorEvents = monitorEvents
	a.Unlock()

	for !isCtxDone(stopCtx) {
		record, err := monitorEvents.Read()
		switch {
		case isCtxDone(stopCtx):
			return
		case err != nil:
			if perf.IsUnknownEvent(err) {
				a.Lock()
				a.MonitorStatus.Unknown++
				a.Unlock()
			} else {
				scopedLog.WithError(err).Warn("Error received while reading from perf buffer")
				if errors.Is(err, unix.EBADFD) {
					return
				}
			}
			continue
		}

		a.processPerfRecord(scopedLog, record)
	}
}

// processPerfRecord processes a record from the datapath and sends it to any
// registered subscribers
func (a *Agent) processPerfRecord(scopedLog *logrus.Entry, record perf.Record) {
	a.Lock()
	defer a.Unlock()

	if record.LostSamples > 0 {
		a.MonitorStatus.Lost += int64(record.LostSamples)
		a.notifyPerfEventLostLocked(record.LostSamples, record.CPU)
		a.sendToListenersLocked(&payload.Payload{
			CPU:  record.CPU,
			Lost: record.LostSamples,
			Type: payload.RecordLost,
		})

	} else {
		a.notifyPerfEventLocked(record.RawSample, record.CPU)
		a.sendToListenersLocked(&payload.Payload{
			Data: record.RawSample,
			CPU:  record.CPU,
			Type: payload.EventSample,
		})
	}
}

// State returns the current status of the monitor
func (a *Agent) State() *models.MonitorStatus {
	if a == nil {
		return nil
	}

	a.Lock()
	defer a.Unlock()

	if a.monitorEvents == nil {
		return nil
	}

	// Shallow-copy the structure, then return the newly allocated copy.
	status := a.MonitorStatus
	return &status
}

// notifyPerfEventLocked notifies all consumers about an agent event.
func (a *Agent) notifyAgentEvent(typ int, message interface{}) {
	a.Lock()
	defer a.Unlock()
	for mc := range a.consumers {
		mc.NotifyAgentEvent(typ, message)
	}
}

// notifyPerfEventLocked notifies all consumers about a perf event.
// The caller must hold the monitor lock.
func (a *Agent) notifyPerfEventLocked(data []byte, cpu int) {
	for mc := range a.consumers {
		mc.NotifyPerfEvent(data, cpu)
	}
}

// notifyEventToConsumersLocked notifies all consumers about lost events.
// The caller must hold the monitor lock.
func (a *Agent) notifyPerfEventLostLocked(numLostEvents uint64, cpu int) {
	for mc := range a.consumers {
		mc.NotifyPerfEventLost(numLostEvents, cpu)
	}
}

// sendToListeners enqueues the payload to all listeners.
func (a *Agent) sendToListeners(pl *payload.Payload) {
	a.Lock()
	defer a.Unlock()
	a.sendToListenersLocked(pl)
}

// sendToListenersLocked enqueues the payload to all listeners while holding the monitor lock.
func (a *Agent) sendToListenersLocked(pl *payload.Payload) {
	for ml := range a.listeners {
		ml.Enqueue(pl)
	}
}
