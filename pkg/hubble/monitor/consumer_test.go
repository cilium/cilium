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

// +build !privileged_tests

package monitor

import (
	"testing"
	"time"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/monitor/api"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeObserver struct {
	events chan *observerTypes.MonitorEvent
	logger *logrus.Entry
}

func (f fakeObserver) GetEventsChannel() chan *observerTypes.MonitorEvent {
	return f.events
}

func (f fakeObserver) GetLogger() logrus.FieldLogger {
	return f.logger
}

func TestHubbleConsumer(t *testing.T) {
	observer := fakeObserver{
		// For testing, we an events queue with a buffer size of 1
		events: make(chan *observerTypes.MonitorEvent, 1),
		logger: logrus.NewEntry(logrus.New()),
	}
	consumer := NewConsumer(observer)
	data := []byte{0, 1, 2, 3, 4}
	cpu := 5

	consumer.NotifyPerfEvent(data, cpu)
	expected := &observerTypes.MonitorEvent{
		NodeName: nodeTypes.GetName(),
		Payload: &observerTypes.PerfEvent{
			Data: data,
			CPU:  cpu,
		},
	}
	received := <-observer.GetEventsChannel()
	assert.Equal(t, expected.NodeName, received.NodeName)
	assert.Equal(t, expected.Payload, received.Payload)

	numLostEvents := uint64(7)
	consumer.NotifyPerfEventLost(numLostEvents, cpu)
	expected = &observerTypes.MonitorEvent{
		NodeName: nodeTypes.GetName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: numLostEvents,
			CPU:           cpu,
		},
	}
	received = <-observer.GetEventsChannel()
	assert.Equal(t, expected.NodeName, received.NodeName)
	assert.Equal(t, expected.Payload, received.Payload)

	typ := api.MessageTypeAccessLog
	message := &accesslog.LogRecord{Timestamp: time.RFC3339}
	consumer.NotifyAgentEvent(typ, message)
	expected = &observerTypes.MonitorEvent{
		NodeName: nodeTypes.GetName(),
		Payload: &observerTypes.AgentEvent{
			Type:    typ,
			Message: message,
		},
	}
	received = <-observer.GetEventsChannel()
	assert.Equal(t, expected.NodeName, received.NodeName)
	assert.Equal(t, expected.Payload, received.Payload)

	// The first notification will get through, the other two will be dropped
	consumer.NotifyAgentEvent(1, nil)
	consumer.NotifyPerfEventLost(0, 0) // dropped
	consumer.NotifyPerfEvent(nil, 0)   // dropped
	expected = &observerTypes.MonitorEvent{
		NodeName: nodeTypes.GetName(),
		Payload: &observerTypes.AgentEvent{
			Type: 1,
		},
	}
	received = <-observer.GetEventsChannel()
	assert.Equal(t, expected.NodeName, received.NodeName)
	assert.Equal(t, expected.Payload, received.Payload)

	// Now that the channel has one slot again, send another message
	// (which will be dropped) to get a lost event notifications
	consumer.NotifyAgentEvent(0, nil) // dropped

	expected = &observerTypes.MonitorEvent{
		NodeName: nodeTypes.GetName(),
		Payload: &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourceEventsQueue,
			NumLostEvents: 2,
		},
	}
	received = <-observer.GetEventsChannel()
	assert.Equal(t, expected.NodeName, received.NodeName)
	assert.Equal(t, expected.Payload, received.Payload)

	// Verify that the events channel is empty now.
	select {
	case ev := <-observer.GetEventsChannel():
		assert.Fail(t, "Unexpected event", ev)
	default:
	}
}
