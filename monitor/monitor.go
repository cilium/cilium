// Copyright 2017 Authors of Cilium
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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path"
	"syscall"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/monitor/listener"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/sirupsen/logrus"
)

const (
	pollTimeout = 5000

	// queueSize is the size of the message queue
	queueSize = 65536
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

	ctx              context.Context
	perfReaderCancel context.CancelFunc
	listeners        map[listener.MonitorListener]struct{}
	nPages           int
	monitorEvents    *bpf.PerCpuEvents
}

// agentPipeReader reads agent events from the agentPipe and distributes to all listeners
func (m *Monitor) agentPipeReader(ctx context.Context, agentPipe io.Reader) {
	log.Info("Beginning to read cilium agent events")
	defer log.Info("Stopped reading cilium agent events")

	for !isCtxDone(ctx) {
		meta, p := payload.Meta{}, payload.Payload{}
		err := payload.ReadMetaPayload(agentPipe, &meta, &p)
		switch {
		// this captures the case where we are shutting down and main closes the
		// pipe socket
		case isCtxDone(ctx):
			return

		case err == io.EOF || err == io.ErrUnexpectedEOF:
			log.Fatal("Agent pipe unexpectedly closed, shutting down")

		case err != nil:
			log.WithError(err).Fatal("Unable to read cilium agent events from pipe")
		}

		m.send(&p)
	}
}

// NewMonitor creates a Monitor, and starts client connection handling and agent event
// handling.
// Note that the perf buffer reader is started only when listeners are
// connected.
func NewMonitor(ctx context.Context, nPages int, agentPipe io.Reader, server1_0, server1_2 net.Listener) (m *Monitor, err error) {
	m = &Monitor{
		ctx:              ctx,
		listeners:        make(map[listener.MonitorListener]struct{}),
		nPages:           nPages,
		perfReaderCancel: func() {}, // no-op to avoid doing null checks everywhere
	}

	// start new MonitorListener handler
	go m.connectionHandler1_0(ctx, server1_0)
	go m.connectionHandler1_2(ctx, server1_2)

	// start agent event pipe reader
	go m.agentPipeReader(ctx, agentPipe)

	return m, nil
}

// registerNewListener adds the new MonitorListener to the global list. It also spawns
// a singleton goroutine to read and distribute the events. It passes a
// cancelable context to this goroutine and the cancelFunc is assigned to
// perfReaderCancel. Note that cancelling parentCtx (e.g. on program shutdown)
// will also cancel the derived context.
func (m *Monitor) registerNewListener(parentCtx context.Context, conn net.Conn, version listener.Version) {
	m.Lock()
	defer m.Unlock()

	// If this is the first listener, start the perf reader
	if len(m.listeners) == 0 {
		m.perfReaderCancel() // don't leak any old readers, just in case.
		perfEventReaderCtx, cancel := context.WithCancel(parentCtx)
		m.perfReaderCancel = cancel
		go m.perfEventReader(perfEventReaderCtx, m.nPages)
	}

	switch version {
	case listener.Version1_0:
		newListener := newListenerv1_0(conn, queueSize, m.removeListener)
		m.listeners[newListener] = struct{}{}

	case listener.Version1_2:
		newListener := newListenerv1_2(conn, queueSize, m.removeListener)
		m.listeners[newListener] = struct{}{}

	default:
		conn.Close()
		log.WithField("version", version).Error("Closing new connection from unsupported monitor client version")
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

// perfEventReader is a goroutine that reads events from the perf buffer. It
// will exit when stopCtx is done. Note, however, that it will block in the
// Poll call but assumes enough events are generated that these blocks are
// short.
func (m *Monitor) perfEventReader(stopCtx context.Context, nPages int) {
	scopedLog := log.WithField(logfields.StartTime, time.Now())
	scopedLog.Info("Beginning to read perf buffer")
	defer scopedLog.Info("Stopped reading perf buffer")

	// configure BPF perf buffer reader
	c := bpf.DefaultPerfEventConfig()
	c.NumPages = nPages

	monitorEvents, err := bpf.NewPerCpuEvents(c)
	if err != nil {
		scopedLog.WithError(err).Fatal("Cannot initialise BPF perf ring buffer sockets")
	}
	defer monitorEvents.CloseAll()

	// update the class's monitorEvents This is only accessed by .DumpStats()
	// also grab the callbacks we need to avoid locking again. These methods never change.
	m.Lock()
	m.monitorEvents = monitorEvents
	receiveEvent := m.receiveEvent
	lostEvent := m.lostEvent
	errorEvent := m.errorEvent
	m.Unlock()

	last := time.Now()
	for !isCtxDone(stopCtx) {
		todo, err := monitorEvents.Poll(pollTimeout)
		switch {
		case isCtxDone(stopCtx):
			return

		case err == syscall.EBADF:
			return

		case err != nil:
			scopedLog.WithError(err).Error("Error in Poll")
			continue
		}

		if todo > 0 {
			if err := monitorEvents.ReadAll(receiveEvent, lostEvent, errorEvent); err != nil {
				scopedLog.WithError(err).Warn("Error received while reading from perf buffer")
			}
		}

		if time.Since(last) > 5*time.Second {
			last = time.Now()
			m.dumpStat()
		}
	}
}

// dumpStat prints out the monitor status in JSON.
func (m *Monitor) dumpStat() {
	m.Lock()
	defer m.Unlock()

	c := int64(m.monitorEvents.Cpus)
	n := int64(m.monitorEvents.Npages)
	p := int64(m.monitorEvents.Pagesize)
	l, _, u := m.monitorEvents.Stats()
	ms := models.MonitorStatus{Cpus: c, Npages: n, Pagesize: p, Lost: int64(l), Unknown: int64(u)}

	mp, err := json.Marshal(ms)
	if err != nil {
		log.WithError(err).Error("Error marshalling JSON")
		return
	}
	fmt.Println(string(mp))
}

// connectionHandler1_0 handles all the incoming connections and sets up the
// listener objects. It will block on Accept, but expects the caller to close
// server, inducing a return.
func (m *Monitor) connectionHandler1_0(parentCtx context.Context, server net.Listener) {
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

		m.registerNewListener(parentCtx, conn, listener.Version1_0)
	}
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

		m.registerNewListener(parentCtx, conn, listener.Version1_2)
	}
}

// send enqueues the payload to all listeners.
func (m *Monitor) send(pl *payload.Payload) {
	m.Lock()
	defer m.Unlock()
	for ml := range m.listeners {
		ml.Enqueue(pl)
	}
}

func (m *Monitor) receiveEvent(es *bpf.PerfEventSample, c int) {
	pl := payload.Payload{Data: es.DataCopy(), CPU: c, Lost: 0, Type: payload.EventSample}
	m.send(&pl)
}

func (m *Monitor) lostEvent(el *bpf.PerfEventLost, c int) {
	pl := payload.Payload{Data: []byte{}, CPU: c, Lost: el.Lost, Type: payload.RecordLost}
	m.send(&pl)
}

func (m *Monitor) errorEvent(el *bpf.PerfEvent) {
	log.Errorf("BUG: Timeout while reading perf ring buffer: %s", el.Debug())
	dumpFile := path.Join(defaults.RuntimePath, defaults.StateDir, "ring-buffer-crash.dump")
	if err := ioutil.WriteFile(dumpFile, []byte(el.DebugDump()), 0644); err != nil {
		log.WithError(err).Errorf("Unable to dump ring buffer state to %s", dumpFile)
	}
}
