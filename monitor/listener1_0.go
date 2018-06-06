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
	"github.com/cilium/cilium/monitor/payload"
)

type listenerv1_0 struct {
	conn      net.Conn
	queue     chan *payload.Payload
	cleanupFn func(*listenerv1_0)
}

func newListenerv1_0(c net.Conn, queueSize int, cleanupFn func(*listenerv1_0)) *listenerv1_0 {
	ml := &listenerv1_0{
		conn:      c,
		queue:     make(chan *payload.Payload, queueSize),
		cleanupFn: cleanupFn,
	}

	go ml.drainQueue()

	return ml
}

func (ml *listenerv1_0) enqueue(pl *payload.Payload) {
	select {
	case ml.queue <- pl:
	default:
		log.Debugf("Per listener queue is full, dropping message")
	}
}

func (ml *listenerv1_0) drainQueue() {
	defer func() {
		ml.conn.Close()
		ml.cleanupFn(ml)
	}()

	for pl := range ml.queue {
		buf, err := pl.BuildMessage()
		if err != nil {
			log.WithError(err).Error("Unable to send notification to listeners")
			continue
		}

		if _, err := ml.conn.Write(buf); err != nil {
			switch {
			case listener.IsDisconnected(err):
				log.Info("Listener disconnected")
				return

			default:
				log.WithError(err).Warn("Removing listener due to write failure")
				return
			}
		}
	}
}

func (ml *listenerv1_0) Version() listener.Version {
	return listener.Version1_0
}
