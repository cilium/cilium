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
	mutex         lock.Mutex
	listeners     = make(map[*monitorListener]struct{})
	monitorEvents *bpf.PerCpuEvents
)

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
func (m *Monitor) agentPipeReader(agentPipe io.Reader, stop chan struct{}) {
	meta, p := payload.Meta{}, payload.Payload{}

	for {
		select {
		default:
			err := payload.ReadMetaPayload(agentPipe, &meta, &p)
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				log.Panic("Agent pipe closed, shutting down")
			} else if err != nil {
				log.WithError(err).Panic("Unable to read from agent pipe")
			}

			m.send(&p)

		case <-stop:
			return
		}
	}
}

// Run starts monitoring.
func (m *Monitor) Run(npages int, agentPipe io.Reader) {
	stopAgentPipeReader := make(chan struct{})
	go m.agentPipeReader(agentPipe, stopAgentPipeReader)
	defer close(stopAgentPipeReader)

	c := bpf.DefaultPerfEventConfig()
	c.NumPages = npages

	me, err := bpf.NewPerCpuEvents(c)
	if err != nil {
		log.WithError(err).Error("Error while starting monitor")
		return
	}
	monitorEvents = me

	last := time.Now()
	// Main event loop
	for {
		todo, err := monitorEvents.Poll(pollTimeout)
		if err != nil {
			log.WithError(err).Error("Error in Poll")
			if err == syscall.EBADF {
				break
			}
		}
		if todo > 0 {
			if err := monitorEvents.ReadAll(m.receiveEvent, m.lostEvent); err != nil {
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

// handleConnection handles all the incoming connections.
func (m *Monitor) handleConnection(server net.Listener) {
	for {
		conn, err := server.Accept()
		if err != nil {
			log.WithError(err).Warn("error accepting connection")
			continue
		}

		mutex.Lock()
		listeners[newMonitorListener(conn)] = struct{}{}
		log.WithField("count.listener", len(listeners)).Info("New monitor connected.")
		mutex.Unlock()
	}
}

// send writes the payload.Meta and the actual payload to the active
// connections.
func (m *Monitor) send(pl *payload.Payload) {
	mutex.Lock()
	defer mutex.Unlock()
	if len(listeners) == 0 {
		return
	}

	buf, err := pl.BuildMessage()
	if err != nil {
		log.WithError(err).Error("Unable to send notification to listeners")
	}

	for ml := range listeners {
		ml.enqueue(buf)
	}
}

func (ml *monitorListener) remove() {
	mutex.Lock()
	delete(listeners, ml)
	mutex.Unlock()
}

func (ml *monitorListener) enqueue(msg []byte) {
	select {
	case ml.queue <- msg:
	default:
		log.Debugf("Per listener queue is full, dropping message")
	}
}

func (ml *monitorListener) drainQueue() {
	for {
		msgBuf := <-ml.queue
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
