// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/bufuuid"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	monitorConsumer "github.com/cilium/cilium/pkg/monitor/agent/consumer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

// Observer is the receiver of MonitorEvents
type Observer interface {
	GetEventsChannel() chan *observerTypes.MonitorEvent
	GetLogger() logrus.FieldLogger
}

// consumer implements monitorConsumer.MonitorConsumer
type consumer struct {
	uuider        *bufuuid.Generator
	observer      Observer
	numEventsLost uint64
	lostLock      lock.Mutex
	logLimiter    logging.Limiter

	cachedLostNotification *observerTypes.MonitorEvent

	metricLostPerfEvents     prometheus.Counter
	metricLostObserverEvents prometheus.Counter
}

// NewConsumer returns an initialized pointer to consumer.
func NewConsumer(observer Observer) monitorConsumer.MonitorConsumer {
	mc := &consumer{
		uuider:        bufuuid.New(),
		observer:      observer,
		numEventsLost: 0,
		logLimiter:    logging.NewLimiter(30*time.Second, 1),

		metricLostPerfEvents: metrics.LostEvents.WithLabelValues(
			strings.ToLower(flowpb.LostEventSource_PERF_EVENT_RING_BUFFER.String())),
		metricLostObserverEvents: metrics.LostEvents.WithLabelValues(
			strings.ToLower(flowpb.LostEventSource_OBSERVER_EVENTS_QUEUE.String())),
	}
	return mc
}

// sendEventQueueLostEvents tries to send the current value of the lost events
// counter to the observer. If it succeeds to enqueue a notification, it
// resets the counter. Returns a boolean indicating whether the notification
// has been successfully sent.
func (c *consumer) sendNumLostEvents() bool {
	c.lostLock.Lock()
	defer c.lostLock.Unlock()
	// check again, in case multiple
	// routines contended the lock
	if c.numEventsLost == 0 {
		return true
	}

	if c.cachedLostNotification == nil {
		c.cachedLostNotification = c.newEvent(func() interface{} {
			return &observerTypes.LostEvent{
				Source:        observerTypes.LostEventSourceEventsQueue,
				NumLostEvents: c.numEventsLost,
			}
		})
	} else {
		c.cachedLostNotification.Timestamp = time.Now()
		c.cachedLostNotification.Payload.(*observerTypes.LostEvent).NumLostEvents = c.numEventsLost
	}

	select {
	case c.observer.GetEventsChannel() <- c.cachedLostNotification:
		// We now now safely reset the counter, as at this point have
		// successfully notified the observer about the amount of events
		// that were lost since the previous LostEvent message. Similarly,
		// we reset the cached notification, so that a new one is created
		// the next time.
		c.numEventsLost = 0
		c.cachedLostNotification = nil
		return true
	default:
		// We do not need to bump the numEventsLost counter here, as we will
		// try to send a new LostEvent notification again during the next
		// invocation of sendEvent
		return false
	}
}

// sendEvent enqueues an event in the observer. If this is not possible, it
// keeps a counter of lost events, which it will regularly try to send to the
// observer as well
func (c *consumer) sendEvent(payloader func() interface{}) {
	if c.numEventsLost > 0 {
		if !c.sendNumLostEvents() {
			// We just failed sending the lost notification, hence it doesn't
			// make sense to try and send the actual event, as we'll most
			// likely fail as well.
			c.countDroppedEvent()
			return
		}
	}

	select {
	case c.observer.GetEventsChannel() <- c.newEvent(payloader):
	default:
		c.countDroppedEvent()
	}
}

func (c *consumer) newEvent(payloader func() interface{}) *observerTypes.MonitorEvent {
	ev := &observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  nodeTypes.GetAbsoluteNodeName(),
		Payload:   payloader(),
	}

	c.uuider.NewInto(&ev.UUID)
	return ev
}

// countDroppedEvent logs that the events channel is full
// and counts how many messages it has lost.
func (c *consumer) countDroppedEvent() {
	c.lostLock.Lock()
	defer c.lostLock.Unlock()
	if c.numEventsLost == 0 && c.logLimiter.Allow() {
		c.observer.GetLogger().WithField("related-metric", "hubble_lost_events_total").
			Warning("hubble events queue is full: dropping messages; consider increasing the queue size (hubble-event-queue-size) or provisioning more CPU")
	}
	c.numEventsLost++
	c.metricLostObserverEvents.Inc()
}

// NotifyAgentEvent implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyAgentEvent(typ int, message interface{}) {
	c.sendEvent(func() interface{} {
		return &observerTypes.AgentEvent{
			Type:    typ,
			Message: message,
		}
	})
}

// NotifyPerfEvent implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyPerfEvent(data []byte, cpu int) {
	c.sendEvent(func() interface{} {
		return &observerTypes.PerfEvent{
			Data: data,
			CPU:  cpu,
		}
	})
}

// NotifyPerfEventLost implements monitorConsumer.MonitorConsumer
func (c *consumer) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	c.sendEvent(func() interface{} {
		return &observerTypes.LostEvent{
			Source:        observerTypes.LostEventSourcePerfRingBuffer,
			NumLostEvents: numLostEvents,
			CPU:           cpu,
		}
	})
	c.metricLostPerfEvents.Inc()
}
