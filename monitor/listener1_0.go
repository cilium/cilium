// Copyright 2017-2018 Authors of Cilium
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
	"net"

	"github.com/cilium/cilium/monitor/listener"
)

type listenerv1_0 struct {
	conn      net.Conn
	queue     chan []byte
	cleanupFn func(*listenerv1_0)
}

func newListenerv1_0(c net.Conn, queueSize int, cleanupFn func(*listenerv1_0)) *listenerv1_0 {
	ml := &listenerv1_0{
		conn:      c,
		queue:     make(chan []byte, queueSize),
		cleanupFn: cleanupFn,
	}

	go ml.drainQueue()

	return ml
}

func (ml *listenerv1_0) enqueue(msg []byte) {
	select {
	case ml.queue <- msg:
	default:
		log.Debugf("Per listener queue is full, dropping message")
	}
}

func (ml *listenerv1_0) drainQueue() {
	defer func() {
		ml.conn.Close()
		ml.cleanupFn(ml)
	}()

	for msgBuf := range ml.queue {
		if _, err := ml.conn.Write(msgBuf); err != nil {
			if listener.IsDisconnected(err) {
				log.Info("Listener disconnected")
				return
			}
			log.WithError(err).Warn("Removing listener due to write failure")
			return
		}
	}
}

func (ml *listenerv1_0) Version() listener.Version {
	return listener.Version1_0
}
