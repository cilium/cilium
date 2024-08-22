// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/monitor/api"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
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
	assert.NotEqual(t, received.UUID, uuid.UUID{})

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
	assert.NotEqual(t, received.UUID, uuid.UUID{})

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
	assert.NotEqual(t, received.UUID, uuid.UUID{})

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
	assert.NotEqual(t, received.UUID, uuid.UUID{})

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
	assert.NotEqual(t, received.UUID, uuid.UUID{})

	// Verify that the events channel is empty now.
	select {
	case ev := <-observer.GetEventsChannel():
		assert.Fail(t, "Unexpected event", ev)
	default:
	}
}

func BenchmarkHubbleConsumerSendEvent(b *testing.B) {
	type benchType uint8
	const (
		btAllSent benchType = iota
		btAllLost
		btHalfSent
	)

	body := func(b *testing.B, bt benchType) {
		observer := fakeObserver{
			events: make(chan *observerTypes.MonitorEvent, 1),
			logger: func() *logrus.Entry {
				log := logrus.New()
				log.SetOutput(io.Discard)
				return logrus.NewEntry(log)
			}(),
		}

		var (
			cnsm = NewConsumer(observer)
			data = []byte{0, 1, 2, 3, 4}
			cpu  = 5
		)

		for i := range b.N {
			cnsm.NotifyPerfEvent(data, cpu)
			if bt == btAllSent || (bt == btHalfSent && i%2 == 0) {
				<-observer.events
			}
		}
	}

	b.Run("all sent", func(b *testing.B) { body(b, btAllSent) })
	b.Run("all lost", func(b *testing.B) { body(b, btAllLost) })
	b.Run("half sent", func(b *testing.B) { body(b, btHalfSent) })
}
