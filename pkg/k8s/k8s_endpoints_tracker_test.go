package k8s

import (
	"testing"
	"time"

	core_v1 "k8s.io/api/core/v1"
)

func TestEndpointUpdate(t *testing.T) {
	serviceID := ServiceID{
		Cluster:   "cluster",
		Name:      "name",
		Namespace: "namespace",
	}
	afterTime := time.Now().Add(5 * time.Minute)

	type args struct {
		serviceID   ServiceID
		annotations map[string]string
	}

	tests := []struct {
		name string
		args args
		want time.Time
	}{
		{
			name: "test empty",
			args: args{
				serviceID:   serviceID,
				annotations: map[string]string{},
			},
			want: time.Time{},
		},
		{
			name: "test with annotation",
			args: args{
				serviceID:   serviceID,
				annotations: map[string]string{"foo": "bar"},
			},
			want: time.Time{},
		},
		{
			name: "annotation trigger time before trigger start time",
			args: args{
				serviceID:   serviceID,
				annotations: map[string]string{core_v1.EndpointsLastChangeTriggerTime: "2023-04-22T21:31:49Z"},
			},
			want: time.Time{},
		},
		{
			name: "annotation trigger time after trigger start time",
			args: args{
				serviceID:   serviceID,
				annotations: map[string]string{core_v1.EndpointsLastChangeTriggerTime: afterTime.Format(time.RFC3339Nano)},
			},
			want: afterTime,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewEndpointsChangeTracker()
			if got := tracker.EndpointUpdate(tt.args.serviceID, tt.args.annotations); !got.Equal(tt.want) {
				t.Errorf("EndpointUpdate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpointRemoved(t *testing.T) {
	type args struct {
		serviceID   ServiceID
		initFunc func (tracker *K8sEndpointsChangeTracker)
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "test empty",
			args: args{
				serviceID: ServiceID{
					Cluster:   "cluster",
					Name:      "name",
					Namespace: "namespace",
				},
				initFunc: func(tracker *K8sEndpointsChangeTracker) {},
			},
		},
		{
			name: "test with serviceID",
			args: args{
				serviceID: ServiceID{
					Cluster:   "cluster",
					Name:      "name",
					Namespace: "namespace",
				},
				initFunc: func(tracker *K8sEndpointsChangeTracker) {
					tracker.lastChangeTriggerTime = map[ServiceID]time.Time{
						{Cluster: "cluster", Name: "name", Namespace: "namespace"}: time.Now(),
					}
				},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewEndpointsChangeTracker()
			tt.args.initFunc(tracker)
			tracker.EndpointRemoved(tt.args.serviceID)
			got := len(tracker.lastChangeTriggerTime)
			if got != tt.want {
				t.Errorf("EndpointRemoved() = %v, want %v", got, tt.want)
			}
		})
	}
}
