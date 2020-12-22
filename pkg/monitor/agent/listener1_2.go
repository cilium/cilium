// Copyright 2018-2019 Authors of Cilium
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
	"encoding/gob"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/payload"
)

// listenerv1_2 implements the cilium-node-monitor API protocol compatible with
// cilium 1.2
// cleanupFn is called on exit
type listenerv1_2 struct {
	conn      net.Conn
	queue     chan *payload.Payload
	cleanupFn func(listener.MonitorListener)
	// Used to prevent queue from getting closed multiple times.
	once sync.Once
}

func newListenerv1_2(c net.Conn, queueSize int, cleanupFn func(listener.MonitorListener)) *listenerv1_2 {
	ml := &listenerv1_2{
		conn:      c,
		queue:     make(chan *payload.Payload, queueSize),
		cleanupFn: cleanupFn,
	}

	go ml.drainQueue()

	return ml
}

func (ml *listenerv1_2) Enqueue(pl *payload.Payload) {
	select {
	case ml.queue <- pl:
	default:
		log.Debug("Per listener queue is full, dropping message")
	}
}

// drainQueue encodes and sends monitor payloads to the listener. It is
// intended to be a goroutine.
func (ml *listenerv1_2) drainQueue() {
	defer func() {
		ml.cleanupFn(ml)
	}()

	enc := gob.NewEncoder(ml.conn)
	for pl := range ml.queue {
		if err := pl.EncodeBinary(enc); err != nil {
			switch {
			case listener.IsDisconnected(err):
				log.Debug("Listener disconnected")
				return

			default:
				log.WithError(err).Warn("Removing listener due to write failure")
				return
			}
		}
	}
}

func (ml *listenerv1_2) Version() listener.Version {
	return listener.Version1_2
}

// Close closes the underlying socket and payload queue.
func (ml *listenerv1_2) Close() {
	ml.once.Do(func() {
		ml.conn.Close()
		close(ml.queue)
	})
}
