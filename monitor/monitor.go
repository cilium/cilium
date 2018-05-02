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
	"net"
	"os"
	"syscall"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/monitor/payload"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
// must have at least one listener (since it started) so no cancel is called.
// If it doesn't, the cancel is the correct behavior (the older generation
// cancel must have been called for us to get this far anyway).
type Monitor struct {
	lock.Mutex

	ctx              context.Context
	perfReaderCancel context.CancelFunc
	listeners        map[*monitorListener]struct{}
	nPages           int
	monitorEvents    *bpf.PerCpuEvents
}

type monitorListener struct {
	conn      net.Conn
	queue     chan []byte
	cleanupFn func(*monitorListener)
}

func newMonitorListener(c net.Conn, cleanupFn func(*monitorListener)) *monitorListener {
	ml := &monitorListener{
		conn:      c,
		queue:     make(chan []byte, queueSize),
		cleanupFn: cleanupFn,
	}

	go ml.drainQueue()

	return ml
}

// agentPipeReader reads agent events from the agentPipe and distributes to all listeners
func (m *Monitor) agentPipeReader(ctx context.Context, agentPipe io.Reader) {
	log.Info("Beginning to read cilium agent events")
	defer log.Info("Stopped reading cilium agent events")

	meta, p := payload.Meta{}, payload.Payload{}
	for !isCtxDone(ctx) {
		err := payload.ReadMetaPayload(agentPipe, &meta, &p)
		switch {
		// this captures the case where we are shutting down and main closes the
		// pipe socket
		case isCtxDone(ctx):
			return

		case err == io.EOF || err == io.ErrUnexpectedEOF:
			log.Panic("Agent pipe unexpectedly closed, shutting down")

		case err != nil:
			log.WithError(err).Panic("Unable to read cilium agent events from pipe")
		}

		m.send(&p)
	}
}

// NewMonitor creates a Monitor, and starts client connection handling and agent event
// handling.
// Note that the perf buffer reader is started only when listeners are
// connected.
func NewMonitor(ctx context.Context, nPages int, agentPipe io.Reader, server net.Listener) (m *Monitor, err error) {
	m = &Monitor{
		ctx:              ctx,
		listeners:        make(map[*monitorListener]struct{}),
		nPages:           nPages,
		perfReaderCancel: func() {}, // no-op to avoid doing null checks everywhere
	}

	// start new listener handler
	go m.connectionHandler(ctx, server)

	// start agent event pipe reader
	go m.agentPipeReader(ctx, agentPipe)

	return m, nil
}

// registerNewListener adds the new listener to the global list. It also spawns
// a singleton goroutine to read and distribute the events. It passes a
// cancelable context to this goroutine and the cancelFunc is assigned to
// perfReaderCancel. Note that cancelling parentCtx (e.g. on program shutdown)
// will also cancel the derived context.
func (m *Monitor) registerNewListener(parentCtx context.Context, conn net.Conn) {
	m.Lock()
	defer m.Unlock()

	// If this is the first listener, start the perf reader
	if len(m.listeners) == 0 {
		m.perfReaderCancel() // don't leak any old readers, just in case.
		perfEventReaderCtx, cancel := context.WithCancel(parentCtx)
		m.perfReaderCancel = cancel
		go m.perfEventReader(perfEventReaderCtx, m.nPages)
	}

	newListener := newMonitorListener(conn, m.removeListener)
	m.listeners[newListener] = struct{}{}

	log.WithField("count.listener", len(m.listeners)).Info("New listener connected.")
}

// removeListener deletes the listener from the list, closes its queue, and
// stops perfReader if this is the last listener
func (m *Monitor) removeListener(ml *monitorListener) {
	m.Lock()
	defer m.Unlock()

	delete(m.listeners, ml)
	log.WithField("count.listener", len(m.listeners)).Info("Removed listener")

	// If this was the final listener, shutdown the perf reader and unmap our
	// ring buffer readers. This tells the kernel to not emit this data.
	// Note: it is critical to hold the lock and check the number of listeners.
	// This guards against an older generation MonitorListener calling the
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
		scopedLog.WithError(err).Panic("Cannot initialise BPF perf ring buffer sockets")
	}
	defer monitorEvents.CloseAll()

	// update the class's monitorEvents This is only accessed by .DumpStats()
	// also grab the callbacks we need to avoid locking again. These methods never change.
	m.Lock()
	m.monitorEvents = monitorEvents
	receiveEvent := m.receiveEvent
	lostEvent := m.lostEvent
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
			if err := monitorEvents.ReadAll(receiveEvent, lostEvent); err != nil {
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
	l, u := m.monitorEvents.Stats()
	ms := models.MonitorStatus{Cpus: c, Npages: n, Pagesize: p, Lost: int64(l), Unknown: int64(u)}

	mp, err := json.Marshal(ms)
	if err != nil {
		log.WithError(err).Error("error marshalling JSON")
		return
	}
	fmt.Println(string(mp))
}

// connectionHandler handles all the incoming connections and sets up the
// listener objects. It will block on Accept, but expects the caller to close
// server, inducing a return.
func (m *Monitor) connectionHandler(parentCtx context.Context, server net.Listener) {
	for !isCtxDone(parentCtx) {
		conn, err := server.Accept()
		switch {
		case isCtxDone(parentCtx) && conn != nil:
			conn.Close()
			fallthrough

		case isCtxDone(parentCtx) && conn == nil:
			return

		case err != nil:
			log.WithError(err).Warn("error accepting connection")
			continue
		}

		m.registerNewListener(parentCtx, conn)
	}
}

// send writes the payload.Meta and the actual payload to the active
// connections.
func (m *Monitor) send(pl *payload.Payload) {
	buf, err := pl.BuildMessage()
	if err != nil {
		log.WithError(err).Error("Unable to send notification to listeners")
	}

	m.Lock()
	defer m.Unlock()
	for ml := range m.listeners {
		ml.enqueue(buf)
	}
}

func (ml *monitorListener) enqueue(msg []byte) {
	select {
	case ml.queue <- msg:
	default:
		log.Debugf("Per listener queue is full, dropping message")
	}
}

func (ml *monitorListener) drainQueue() {
	defer func() {
		ml.conn.Close()
		ml.cleanupFn(ml)
	}()

	for msgBuf := range ml.queue {
		if _, err := ml.conn.Write(msgBuf); err != nil {
			if op, ok := err.(*net.OpError); ok {
				if syscerr, ok := op.Err.(*os.SyscallError); ok {
					if errn, ok := syscerr.Err.(syscall.Errno); ok {
						if errn == syscall.EPIPE {
							log.Info("Listener disconnected")
							return
						}
					}
				}
			}
			log.WithError(err).Warn("Removing listener due to write failure")
			return
		}
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
