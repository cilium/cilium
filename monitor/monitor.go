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
	"container/list"
	"encoding/json"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/monitor/payload"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
)

const pollTimeout = 5000

var (
	mutex         lock.Mutex
	listeners     = list.New()
	monitorEvents *bpf.PerCpuEvents
)

// Monitor structure for centralizing the responsibilities of the main events reader.
type Monitor struct {
}

// Run starts monitoring.
func (m *Monitor) Run(npages int) {
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
		listeners.PushBack(conn)
		log.WithField("count.listener", listeners.Len()).Info("New monitor connected.")
		mutex.Unlock()
	}
}

// send writes the payload.Meta and the actual payload to the active
// connections.
func (m *Monitor) send(pl payload.Payload) {
	mutex.Lock()
	defer mutex.Unlock()
	if listeners.Len() == 0 {
		return
	}

	writeError := func(prefix string, err error) {
		log.WithError(err).Warnf("Monitor removed due to write failure (%s)", prefix)
	}

	payloadBuf, err := pl.Encode()
	if err != nil {
		log.WithError(err).Fatal("payload encode")
	}
	meta := &payload.Meta{Size: uint32(len(payloadBuf))}
	metaBuf, err := meta.MarshalBinary()
	if err != nil {
		log.WithError(err).Fatal("meta encode")
	}
	var next *list.Element
	for e := listeners.Front(); e != nil; e = next {
		client := e.Value.(net.Conn)
		next = e.Next()

		if _, err := client.Write(metaBuf); err != nil {
			client.Close()
			listeners.Remove(e)
			writeError("metadata", err)
			continue
		}

		if _, err := client.Write(payloadBuf); err != nil {
			client.Close()
			listeners.Remove(e)
			writeError("payload", err)
			continue
		}
	}
}

func (m *Monitor) receiveEvent(es *bpf.PerfEventSample, c int) {
	pl := payload.Payload{Data: es.DataCopy(), CPU: c, Lost: 0, Type: payload.EventSample}
	m.send(pl)
}

func (m *Monitor) lostEvent(el *bpf.PerfEventLost, c int) {
	pl := payload.Payload{Data: []byte{}, CPU: c, Lost: el.Lost, Type: payload.RecordLost}
	m.send(pl)
}
