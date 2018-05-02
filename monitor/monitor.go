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
)

const (
	pollTimeout = 5000

	// queueSize is the size of the message queue
	queueSize = 65536
)

var (
	mutex            lock.Mutex
	listeners        = make(map[*monitorListener]struct{})
	monitorEvents    *bpf.PerCpuEvents
	perfReaderCancel context.CancelFunc
	nPages           int
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

type monitorListener struct {
	conn  net.Conn
	queue chan []byte
}

func newMonitorListener(c net.Conn) *monitorListener {
	ml := &monitorListener{
		conn:  c,
		queue: make(chan []byte, queueSize),
	}

	go ml.drainQueue()

	return ml
}

// Monitor structure for centralizing the responsibilities of the main events reader.
type Monitor struct {
}

// agentPipeReader reads agent events from the agentPipe and distributes to all listeners
func (m *Monitor) agentPipeReader(ctx context.Context, agentPipe io.Reader) {
	meta, p := payload.Meta{}, payload.Payload{}

	for !isCtxDone(ctx) {
		err := payload.ReadMetaPayload(agentPipe, &meta, &p)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			log.Panic("Agent pipe closed, shutting down")
		} else if err != nil {
			log.WithError(err).Panic("Unable to read from agent pipe")
		}

		m.send(&p)
	}
}

// Init configures client connection handling and agent event handling.
// Note that the perf buffer reader is started only when listeners are connected.
func (m *Monitor) Init(ctx context.Context, npages int, agentPipe io.Reader, server net.Listener) (err error) {
	// start new listener handler
	go m.connectionHandler(ctx, server)

	// start agent event pipe reader
	go m.agentPipeReader(ctx, agentPipe)

	mutex.Lock()
	defer mutex.Unlock()
	nPages = npages

	return nil
}

// startPerfEventReader spawns a singleton goroutine to read and distribute the
// events. It passes a cancelable context to this goroutine and the cancelFunc
// is assigned to perfReaderCancel. Note that cancelling parentCtx (e.g. on
// program shutdown) will also cancel the derived context.
func (m *Monitor) startPerfEventReader(parentCtx context.Context) {
	mutex.Lock()
	defer mutex.Unlock()

	perfReaderCancel() // don't leak any old readers, just in case.
	perfEventReaderCtx, cancelFn := context.WithCancel(parentCtx)
	perfReaderCancel = cancelFn

	go m.perfEventReader(perfEventReaderCtx)
}

func (m *Monitor) perfEventReader(stopCtx context.Context) {
	log.Info("Beginning to read perf buffer")
	defer log.Info("Stopped reading perf buffer")

	// configure BPF perf buffer reader
	c := bpf.DefaultPerfEventConfig()
	c.NumPages = nPages

	monEvents, err := bpf.NewPerCpuEvents(c)
	if err != nil {
		log.WithError(err).Fatal("Cannot initialize BPF perf buffer reader")
		return
	}

	defer monEvents.CloseAll()

	// this is only used by .DumpStats()
	mutex.Lock()
	monitorEvents = monEvents
	mutex.Unlock()

	last := time.Now()

	for !isCtxDone(stopCtx) {
		todo, err := monEvents.Poll(pollTimeout)
		if err != nil {
			log.WithError(err).Error("Error in Poll")
			if err == syscall.EBADF {
				break
			}
		}
		if todo > 0 {
			if err := monEvents.ReadAll(m.receiveEvent, m.lostEvent); err != nil {
				log.WithError(err).Warn("Error received while reading from perf buffer")
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
	mutex.Lock()
	defer mutex.Unlock()

	c := int64(monitorEvents.Cpus)
	n := int64(monitorEvents.Npages)
	p := int64(monitorEvents.Pagesize)
	l, u := monitorEvents.Stats()
	ms := models.MonitorStatus{Cpus: c, Npages: n, Pagesize: p, Lost: int64(l), Unknown: int64(u)}

	mp, err := json.Marshal(ms)
	if err != nil {
		log.WithError(err).Error("error marshalling JSON")
		return
	}
	fmt.Println(string(mp))
}

// connectionHandler handles all the incoming connections.
func (m *Monitor) connectionHandler(parentCtx context.Context, server net.Listener) {
	for {
		conn, err := server.Accept()
		if err != nil {
			log.WithError(err).Warn("error accepting connection")
			continue
		}

		var (
			listenerCount int
			newListener   = newMonitorListener(conn)
		)
		mutex.Lock()
		listeners[newListener] = struct{}{}
		listenerCount = len(listeners)
		mutex.Unlock()
		log.WithField("count.listener", listenerCount).Info("New monitor connected.")

		// If this is the first listener, start reading the perf buffer
		if listenerCount == 1 {
			m.startPerfEventReader(parentCtx)
		}
	}
}

// send writes the payload.Meta and the actual payload to the active
// connections.
func (m *Monitor) send(pl *payload.Payload) {
	buf, err := pl.BuildMessage()
	if err != nil {
		log.WithError(err).Error("Unable to send notification to listeners")
	}

	mutex.Lock()
	defer mutex.Unlock()
	for ml := range listeners {
		ml.enqueue(buf)
	}
}

func (ml *monitorListener) remove() {
	mutex.Lock()
	defer mutex.Unlock()

	delete(listeners, ml)

	// If this was the final listener, shutdown the perf reader
	if len(listeners) == 0 {
		perfReaderCancel()
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
	for msgBuf := range ml.queue {
		if _, err := ml.conn.Write(msgBuf); err != nil {
			ml.conn.Close()
			ml.remove()

			if op, ok := err.(*net.OpError); ok {
				if syscerr, ok := op.Err.(*os.SyscallError); ok {
					if errn, ok := syscerr.Err.(syscall.Errno); ok {
						if errn == syscall.EPIPE {
							log.Info("Monitor client disconnected")
							return
						}
					}
				}
			}
			log.WithError(err).Warn("Monitor removed due to write failure")
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
