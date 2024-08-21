package k8s

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	core_v1 "k8s.io/api/core/v1"
)

func TestEndpointUpdate(t *testing.T) {
	tracker := NewEndpointsChangeTracker()
	serviceID := ServiceID{
		Cluster:   "cluster",
		Name:      "name",
		Namespace: "namespace",
	}
	tracker.EndpointUpdate(serviceID, map[string]string{}, false)
	assert.Len(t, tracker.lastChangeTriggerTime, 0)

	tracker.EndpointUpdate(serviceID, map[string]string{"foo": "bar"}, false)
	assert.Len(t, tracker.lastChangeTriggerTime, 1)

	time2 := tracker.EndpointUpdate(serviceID, map[string]string{core_v1.EndpointsLastChangeTriggerTime: "2023-04-22T21:31:49Z"}, false)
	assert.Len(t, tracker.lastChangeTriggerTime, 1)
	assert.True(t, time2.IsZero())

	newTime := time.Now().Add(5 * time.Minute)
	time3 := tracker.EndpointUpdate(serviceID, map[string]string{core_v1.EndpointsLastChangeTriggerTime: newTime.Format(time.RFC3339Nano)}, false)
	assert.Len(t, tracker.lastChangeTriggerTime, 1)
	assert.True(t, newTime.Equal(tracker.lastChangeTriggerTime[serviceID]))
	assert.True(t, time3.Equal(newTime))

	tracker.EndpointUpdate(serviceID, map[string]string{}, true)
	assert.Len(t, tracker.lastChangeTriggerTime, 0)
}
