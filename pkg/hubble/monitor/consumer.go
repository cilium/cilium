// Copyright 2020 Authors of Cilium
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

package monitor

import (
	"time"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	monitorConsumer "github.com/cilium/cilium/pkg/monitor/agent/consumer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/sirupsen/logrus"
)

// Observer is the receiver of MonitorEvents
type Observer interface {
	GetEventsChannel() chan *observerTypes.MonitorEvent
	GetLogger() logrus.FieldLogger
}

// consumer implements monitorConsumer.MonitorConsumer
type consumer struct {
	observer      Observer
	numEventsLost uint64
}

// NewConsumer returns an initialized pointer to consumer.
func NewConsumer(observer Observer) monitorConsumer.MonitorConsumer {
	mc := &consumer{
		observer:      observer,
		numEventsLost: 0,
	}
	return mc
}

// sendEventQueueLostEvents tries to send the current value of the lost events
// counter to the observer. If it succeeds to enqueue a notification, it
// resets the counter.
func (c *consumer) sendNumLostEvents() {
	numEventsLostNotification := &observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourceEventsQueue,
			NumLostEvents: c.numEventsLost,
		},
	}
	select {
	case c.observer.GetEventsChannel() <- numEventsLostNotification:
		// We now now safely reset the counter, as at this point have
		// successfully notified the observer about the amount of events
		// that were lost since the previous LostEvent message
		c.numEventsLost = 0
	default:
		// We do not need to bump the numEventsLost counter here, as we will
		// try to send a new LostEvent notification again during the next
		// invocation of sendEvent
	}
}

// sendEvent enqueues an event in the observer. If this is not possible, it
// keeps a counter of lost events, which it will regularly try to send to the
// observer as well
func (c *consumer) sendEvent(event *observerTypes.MonitorEvent) {
	if c.numEventsLost > 0 {
		c.sendNumLostEvents()
	}

	select {
	case c.observer.GetEventsChannel() <- event:
	default:
		c.observer.GetLogger().Debug("hubble events queue is full, dropping message")
		c.numEventsLost++
	}
}

// NotifyAgentEvent implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyAgentEvent(typ int, message interface{}) {
	c.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.AgentEvent{
			Type:    typ,
			Message: message,
		},
	})
}

// NotifyPerfEvent implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyPerfEvent(data []byte, cpu int) {
	c.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.PerfEvent{
			Data: data,
			CPU:  cpu,
		},
	})
}

// NotifyPerfEventLost implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	c.sendEvent(&observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: numLostEvents,
			CPU:           cpu,
		},
	})
}
