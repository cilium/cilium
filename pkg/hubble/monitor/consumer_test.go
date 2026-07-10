// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hubble/defaults"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/monitor/api"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

type fakeObserver struct {
	events chan *observerTypes.MonitorEvent
	logger *slog.Logger
}

func (f fakeObserver) GetEventsChannel() chan *observerTypes.MonitorEvent {
	return f.events
}

func (f fakeObserver) GetLogger() *slog.Logger {
	return f.logger
}

func TestHubbleConsumer(t *testing.T) {
	observer := fakeObserver{
		// For testing, we an events queue with a buffer size of 1
		events: make(chan *observerTypes.MonitorEvent, 1),
		logger: hivetest.Logger(t),
	}
	lostSendInterval := 100 * time.Millisecond
	consumer := NewConsumer(observer, lostSendInterval)
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
	assert.NotEqual(t, uuid.UUID{}, received.UUID)

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
	assert.NotEqual(t, uuid.UUID{}, received.UUID)

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
	assert.NotEqual(t, uuid.UUID{}, received.UUID)

	// The first notification will get through, the others two will be dropped
	consumer.NotifyAgentEvent(1, nil)
	consumer.NotifyPerfEventLost(0, 0) // dropped
	consumer.NotifyPerfEvent(nil, 0)   // dropped

	time.Sleep(lostSendInterval * 2) // Wait for lost event counter interval to elapse

	// try to send other events, which will also be dropped
	// consumer should also try to send lost events but would not succeed
	consumer.NotifyPerfEventLost(0, 0) // dropped
	consumer.NotifyPerfEvent(nil, 0)   // dropped

	// then receive the event before the drops happened
	expected = &observerTypes.MonitorEvent{
		NodeName: nodeTypes.GetName(),
		Payload: &observerTypes.AgentEvent{
			Type: 1,
		},
	}
	received = <-observer.GetEventsChannel()
	assert.Equal(t, expected.NodeName, received.NodeName)
	assert.Equal(t, expected.Payload, received.Payload)
	assert.NotEqual(t, uuid.UUID{}, received.UUID)

	// now that we emptied the channel, the consumer should be able to send
	// the lost events notification, which it tries to do if any are pending
	// before the next event is sent. Since we only have a buffer of size 1,
	// this event will be dropped.
	consumer.NotifyPerfEvent(nil, 0) // dropped

	// receive the lost event notification which is always
	// sent before the next event, and validate we receive
	// the count of lost events before and after the counter
	// interval elapsed.
	expectedPayload := &observerTypes.LostEvent{
		Source:        observerTypes.LostEventSourceEventsQueue,
		NumLostEvents: 4,
		// omit First, Last timestamps on-purpose as they are not predictable
	}
	received = <-observer.GetEventsChannel()
	assert.Equal(t, expected.NodeName, nodeTypes.GetName())
	receivedPayload, ok := received.Payload.(*observerTypes.LostEvent)
	require.Truef(t, ok, "expected payload to be of type *observerTypes.LostEvent, got %T", received.Payload)
	assert.Equal(t, expectedPayload.Source, receivedPayload.Source)
	assert.Equal(t, expectedPayload.NumLostEvents, receivedPayload.NumLostEvents)
	assert.NotEqual(t, uuid.UUID{}, received.UUID)

	// Verify that the events channel is empty now.
	select {
	case ev := <-observer.GetEventsChannel():
		assert.Fail(t, "Unexpected event", "event %v", ev)
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
			logger: func() *slog.Logger {
				return hivetest.Logger(b)
			}(),
		}

		var (
			cnsm = NewConsumer(observer, defaults.LostEventSendInterval)
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
