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
	"context"
	"net"
	"os"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	oldBPF "github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	pollTimeout = 5000
)

var (
	eventsMapName = "cilium_events"
)

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

// Monitor structure for centralizing the responsibilities of the main events
// reader.
// There is some racey-ness around perfReaderCancel since it replaces on every
// perf reader start. In the event that a MonitorListener from a previous
// generation calls its cleanup after the start of the new perf reader, we
// might call the new, and incorrect, cancel function. We guard for this by
// checking the number of listeners during the cleanup call. The perf reader
// must have at least one MonitorListener (since it started) so no cancel is called.
// If it doesn't, the cancel is the correct behavior (the older generation
// cancel must have been called for us to get this far anyway).
type Monitor struct {
	lock.Mutex
	models.MonitorStatus

	ctx              context.Context
	perfReaderCancel context.CancelFunc
	listeners        map[listener.MonitorListener]struct{}

	events        *ebpf.Map
	monitorEvents *perf.Reader
}

// NewMonitor creates a Monitor, and starts client connection handling and agent event
// handling.
// Note that the perf buffer reader is started only when listeners are
// connected.
func NewMonitor(ctx context.Context, nPages int, server1_2 net.Listener) (m *Monitor, err error) {
	// assert that we can actually connect the monitor
	path := oldBPF.MapPath(eventsMapName)
	eventsMap, err := ebpf.LoadPinnedMap(path)
	if err != nil {
		return nil, err
	}

	m = &Monitor{
		ctx:              ctx,
		listeners:        make(map[listener.MonitorListener]struct{}),
		perfReaderCancel: func() {}, // no-op to avoid doing null checks everywhere
		events:           eventsMap,
		MonitorStatus: models.MonitorStatus{
			Cpus:     int64(eventsMap.ABI().MaxEntries),
			Npages:   int64(nPages),
			Pagesize: int64(os.Getpagesize()),
		},
	}

	// start new MonitorListener handler
	go m.connectionHandler1_2(ctx, server1_2)

	return m, nil
}

// registerNewListener adds the new MonitorListener to the global list. It also spawns
// a singleton goroutine to read and distribute the events. It passes a
// cancelable context to this goroutine and the cancelFunc is assigned to
// perfReaderCancel. Note that cancelling parentCtx (e.g. on program shutdown)
// will also cancel the derived context.
func (m *Monitor) registerNewListener(parentCtx context.Context, newListener listener.MonitorListener) {
	m.Lock()
	defer m.Unlock()

	// If this is the first listener, start the perf reader
	if len(m.listeners) == 0 {
		m.perfReaderCancel() // don't leak any old readers, just in case.
		perfEventReaderCtx, cancel := context.WithCancel(parentCtx)
		m.perfReaderCancel = cancel
		go m.handleEvents(perfEventReaderCtx)
	}
	version := newListener.Version()
	switch newListener.Version() {
	case listener.Version1_2:
		m.listeners[newListener] = struct{}{}

	default:
		newListener.Close()
		log.WithField("version", version).Error("Closing listener from unsupported monitor client version")
	}

	log.WithFields(logrus.Fields{
		"count.listener": len(m.listeners),
		"version":        version,
	}).Debug("New listener connected")
}

// removeListener deletes the MonitorListener from the list, closes its queue, and
// stops perfReader if this is the last MonitorListener
func (m *Monitor) removeListener(ml listener.MonitorListener) {
	m.Lock()
	defer m.Unlock()

	delete(m.listeners, ml)
	log.WithFields(logrus.Fields{
		"count.listener": len(m.listeners),
		"version":        ml.Version(),
	}).Debug("Removed listener")

	// If this was the final listener, shutdown the perf reader and unmap our
	// ring buffer readers. This tells the kernel to not emit this data.
	// Note: it is critical to hold the lock and check the number of listeners.
	// This guards against an older generation listener calling the
	// current generation perfReaderCancel
	if len(m.listeners) == 0 {
		m.perfReaderCancel()
	}
}

// handleEvents reads events from the perf buffer and processes them. It
// will exit when stopCtx is done. Note, however, that it will block in the
// Poll call but assumes enough events are generated that these blocks are
// short.
func (m *Monitor) handleEvents(stopCtx context.Context) {
	scopedLog := log.WithField(logfields.StartTime, time.Now())
	scopedLog.Info("Beginning to read perf buffer")
	defer scopedLog.Info("Stopped reading perf buffer")

	bufferSize := int(m.Pagesize * m.Npages)
	monitorEvents, err := perf.NewReader(m.events, bufferSize)
	if err != nil {
		scopedLog.WithError(err).Fatal("Cannot initialise BPF perf ring buffer sockets")
	}
	defer func() {
		monitorEvents.Close()
		m.Lock()
		m.monitorEvents = nil
		m.Unlock()
	}()

	m.Lock()
	m.monitorEvents = monitorEvents
	m.Unlock()

	for !isCtxDone(stopCtx) {
		record, err := monitorEvents.Read()
		switch {
		case isCtxDone(stopCtx):
			return
		case err != nil:
			if perf.IsUnknownEvent(err) {
				m.Lock()
				m.MonitorStatus.Unknown++
				m.Unlock()
			} else {
				scopedLog.WithError(err).Warn("Error received while reading from perf buffer")
				if errors.Cause(err) == unix.EBADFD {
					return
				}
			}
			continue
		}

		m.Lock()
		plType := payload.EventSample
		if record.LostSamples > 0 {
			plType = payload.RecordLost
			m.MonitorStatus.Lost += int64(record.LostSamples)
		}
		pl := payload.Payload{
			Data: record.RawSample,
			CPU:  record.CPU,
			Lost: record.LostSamples,
			Type: plType,
		}
		m.sendLocked(&pl)
		m.Unlock()
	}
}

// Status returns the current status of the monitor
func (m *Monitor) Status() *models.MonitorStatus {
	m.Lock()
	defer m.Unlock()

	if m.monitorEvents == nil {
		return nil
	}

	// Shallow-copy the structure, then return the newly allocated copy.
	status := m.MonitorStatus
	return &status
}

// connectionHandler1_2 handles all the incoming connections and sets up the
// listener objects. It will block on Accept, but expects the caller to close
// server, inducing a return.
func (m *Monitor) connectionHandler1_2(parentCtx context.Context, server net.Listener) {
	for !isCtxDone(parentCtx) {
		conn, err := server.Accept()
		switch {
		case isCtxDone(parentCtx) && conn != nil:
			conn.Close()
			fallthrough

		case isCtxDone(parentCtx) && conn == nil:
			return

		case err != nil:
			log.WithError(err).Warn("Error accepting connection")
			continue
		}

		newListener := newListenerv1_2(conn, option.Config.MonitorQueueSize, m.removeListener)
		m.registerNewListener(parentCtx, newListener)
	}
}

// send enqueues the payload to all listeners.
func (m *Monitor) send(pl *payload.Payload) {
	m.Lock()
	defer m.Unlock()
	m.sendLocked(pl)
}

// sendLocked enqueues the payload to all listeners while holding the monitor lock.
func (m *Monitor) sendLocked(pl *payload.Payload) {
	for ml := range m.listeners {
		ml.Enqueue(pl)
	}
}
