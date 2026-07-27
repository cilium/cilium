// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/bufuuid"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorConsumer "github.com/cilium/cilium/pkg/monitor/agent/consumer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

// Observer is the receiver of MonitorEvents
type Observer interface {
	GetEventsChannel() chan *observerTypes.MonitorEvent
	GetLogger() *slog.Logger
}

var _ monitorConsumer.MonitorConsumer = (*consumer)(nil)

// consumer is a monitor consumer that sends events to an Observer.
type consumer struct {
	uuider   *bufuuid.Generator
	observer Observer

	lostLock         lock.Mutex
	lostEventCounter *counter.IntervalRangeCounter
	logLimiter       logging.Limiter

	metricLostPerfEvents     prometheus.Counter
	metricLostObserverEvents prometheus.Counter
}

// NewConsumer returns a new consumer that sends events to the provided Observer.
func NewConsumer(observer Observer, lostEventSendInterval time.Duration) *consumer {
	mc := &consumer{
		uuider:           bufuuid.New(),
		observer:         observer,
		lostEventCounter: counter.NewIntervalRangeCounter(lostEventSendInterval),
		logLimiter:       logging.NewLimiter(30*time.Second, 1),

		metricLostPerfEvents: metrics.LostEvents.WithLabelValues(
			strings.ToLower(flowpb.LostEventSource_PERF_EVENT_RING_BUFFER.String())),
		metricLostObserverEvents: metrics.LostEvents.WithLabelValues(
			strings.ToLower(flowpb.LostEventSource_OBSERVER_EVENTS_QUEUE.String())),
	}
	return mc
}

// NotifyAgentEvent implements monitorConsumer.MonitorConsumer.
func (c *consumer) NotifyAgentEvent(typ int, message any) {
	c.sendEvent(func() any {
		return &observerTypes.AgentEvent{
			Type:    typ,
			Message: message,
		}
	})
}

// NotifyPerfEvent implements monitorConsumer.MonitorConsumer.
func (c *consumer) NotifyPerfEvent(data []byte, cpu int) {
	c.sendEvent(func() any {
		return &observerTypes.PerfEvent{
			Data: data,
			CPU:  cpu,
		}
	})
}

// NotifyPerfEventLost implements monitorConsumer.MonitorConsumer.
func (c *consumer) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	c.sendEvent(func() any {
		return &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: numLostEvents,
			CPU:           cpu,
		}
	})
	c.metricLostPerfEvents.Inc()
}

// sendEvent enqueues an event in the observer. If this is not possible, it
// keeps a counter of lost events, which it will try to send at most once per
// configured interval, and on every call to sendEvent until it succeeds.
func (c *consumer) sendEvent(payloader func() any) {
	c.lostLock.Lock()
	defer c.lostLock.Unlock()

	now := time.Now()
	c.trySendLostEventLocked(now)

	select {
	case c.observer.GetEventsChannel() <- c.newEvent(now, payloader):
	default:
		c.incrementLostEventLocked(now)
	}
}

func (c *consumer) newEvent(ts time.Time, payloader func() any) *observerTypes.MonitorEvent {
	ev := &observerTypes.MonitorEvent{
		Timestamp: ts,
		NodeName:  nodeTypes.GetAbsoluteNodeName(),
		Payload:   payloader(),
	}

	c.uuider.NewInto(&ev.UUID)
	return ev
}

// trySendLostEventLocked tries to send a lost event as needed. If it succeeds, it clears the
// lost event counter, otherwise it does nothing so we keep the existing count. It assumes that
// the caller holds c.lostLock.
func (c *consumer) trySendLostEventLocked(ts time.Time) {
	// check if we should send a lost event
	shouldSend := c.lostEventCounter.IsElapsed(ts)
	if !shouldSend {
		return
	}

	count := c.lostEventCounter.Peek()
	lostEvent := c.newEvent(ts, func() any {
		return &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourceEventsQueue,
			NumLostEvents: count.Count,
			First:         count.First,
			Last:          count.Last,
		}
	})

	select {
	case c.observer.GetEventsChannel() <- lostEvent:
		// only clear the counter if we successfully sent the lost event
		c.lostEventCounter.Clear()
	default:
	}
}

// incrementLostEventLocked increments the lost event counter. It also logs a warning message if the
// counter was previously empty and the log limiter allows it. It assumes that the caller holds
// c.lostLock.
func (c *consumer) incrementLostEventLocked(ts time.Time) {
	if c.lostEventCounter.Peek().Count == 0 && c.logLimiter.Allow() {
		c.observer.GetLogger().
			Warn(
				"hubble events queue is full: dropping messages; consider increasing the queue size (hubble-event-queue-size) or provisioning more CPU",
				logfields.RelatedMetric, "hubble_lost_events_total",
			)
	}
	c.lostEventCounter.Increment(ts)
	c.metricLostObserverEvents.Inc()
}
