package k8s

import (
	"time"

	core_v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
)

// EndpointsChangeTracker carries state about uncommitted changes to an arbitrary number of
// Endpoints, keyed by their namespace and name.
type EndpointsChangeTracker struct {
	// mutex protects the maps below including the concurrent access of each
	// value.
	mutex lock.RWMutex

	log *logrus.Entry
	// lastChangeTriggerTimes maps from the Service's NamespacedName to the times of
	// the triggers that caused its EndpointSlice objects to change. Used to calculate
	// the network-programming-latency metric.
	lastChangeTriggerTime map[ServiceID]time.Time
	// trackerStartTime is the time when the EndpointsChangeTracker was created, so
	// we can avoid generating network-programming-latency metrics for changes that
	// occurred before that.
	trackerStartTime time.Time
}

// NewEndpointsChangeTracker returns a new EndpointsChangeTracker.
func NewEndpointsChangeTracker() *EndpointsChangeTracker {
	return &EndpointsChangeTracker{
		log:                   log.WithField(logfields.LogSubsys, "endpoints-tracker"),
		lastChangeTriggerTime: make(map[ServiceID]time.Time),
		trackerStartTime:      time.Now(),
	}
}

// EndpointUpdate updates the EndpointsChangeTracker to record last change trigger time
// Returns the time when the Endpoints last change trigger time.
func (tracker *EndpointsChangeTracker) EndpointUpdate(serviceID ServiceID, annotations map[string]string, remove bool) (start time.Time) {
	tracker.mutex.Lock()
	defer tracker.mutex.Unlock()

	scopedLog := tracker.log.WithField(logfields.EndpointID, serviceID.String())
	if remove {
		delete(tracker.lastChangeTriggerTime, serviceID)
	} else if len(annotations) > 0 {
		// If the Endpoints object has been updated, update the time stored in
		// lastChangeTriggerTimes.
		old, ok := tracker.lastChangeTriggerTime[serviceID]
		changeTime := getLastChangeTriggerTime(scopedLog, annotations)
		tracker.lastChangeTriggerTime[serviceID] = changeTime

		// skip if the Endpoints object has not changed since the last time
		if ok && (changeTime.Equal(old) || changeTime.Before(old)) {
			return
		}
		// After the agent restarts, it should not accept changes before the restart time
		if changeTime.IsZero() || changeTime.Before(tracker.trackerStartTime) {
			return
		}
		start = changeTime
	}
	return
}

// getLastChangeTriggerTime returns the time.Time value of the
// EndpointsLastChangeTriggerTime annotation stored in the given endpoints
// object or the "zero" time if the annotation wasn't set or was set
// incorrectly.
func getLastChangeTriggerTime(scopedLog *logrus.Entry, annotations map[string]string) time.Time {
	// ignore case when Endpoint is deleted.
	if _, ok := annotations[core_v1.EndpointsLastChangeTriggerTime]; !ok {
		// It's possible that the Endpoints object won't have the
		// EndpointsLastChangeTriggerTime annotation set. In that case return
		// the 'zero value', which is ignored in the upstream code.
		return time.Time{}
	}
	val, err := time.Parse(time.RFC3339Nano, annotations[core_v1.EndpointsLastChangeTriggerTime])
	if err != nil {
		scopedLog.WithField("value", annotations[core_v1.EndpointsLastChangeTriggerTime]).
			WithError(err).
			Error("Error while parsing EndpointsLastChangeTriggerTimeAnnotation")
		// In case of error val = time.Zero, which is ignored in the upstream code.
	}
	return val
}
