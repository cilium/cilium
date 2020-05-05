// Copyright 2019 Authors of Hubble
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

package v1

import (
	"net"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/lock"

	"github.com/stretchr/testify/assert"
)

func TestEndpoint_EqualsByID(t *testing.T) {
	type fields struct {
		ContainerID  []string
		ID           uint64
		IPv4         net.IP
		IPv6         net.IP
		PodName      string
		PodNamespace string
	}
	tests := []struct {
		name   string
		fields fields
		arg    *Endpoint
		want   bool
	}{
		{
			name:   "<nil> endpoint",
			fields: fields{},
			arg:    nil,
			want:   false,
		}, {
			name: "compare by a same ID and all other fields different should be considered equal",
			fields: fields{
				ContainerID:  []string{"foo"},
				ID:           1,
				IPv4:         net.ParseIP("2.2.2.2"),
				PodName:      "",
				PodNamespace: "",
			},
			arg: &Endpoint{
				ContainerIDs: []string{"bar"},
				ID:           1,
				IPv4:         net.ParseIP("1.1.1.1"),
				PodName:      "",
				PodNamespace: "",
			},
			want: true,
		},
		{
			name: "compare by a same ID, but different pod name should be considered different",
			fields: fields{
				ContainerID:  []string{"foo"},
				ID:           1,
				IPv4:         net.ParseIP("2.2.2.2"),
				PodName:      "pod-bar",
				PodNamespace: "",
			},
			arg: &Endpoint{
				ContainerIDs: []string{"bar"},
				ID:           1,
				IPv4:         net.ParseIP("1.1.1.1"),
				PodName:      "pod-foo",
				PodNamespace: "",
			},
			want: false,
		},
		{
			name: "compare by a same ID, but different namespace should be considered different",
			fields: fields{
				ContainerID:  []string{"foo"},
				ID:           1,
				IPv4:         net.ParseIP("2.2.2.2"),
				PodName:      "pod-bar",
				PodNamespace: "kube-system",
			},
			arg: &Endpoint{
				ContainerIDs: []string{"bar"},
				ID:           1,
				IPv4:         net.ParseIP("1.1.1.1"),
				PodName:      "pod-bar",
				PodNamespace: "cilium",
			},
			want: false,
		},
		{
			name: "compare by a same ID where podname and podnamespace are empty should be considered equal",
			fields: fields{
				ContainerID:  []string{"foo"},
				ID:           1,
				IPv4:         net.ParseIP("2.2.2.2"),
				PodName:      "",
				PodNamespace: "",
			},
			arg: &Endpoint{
				ContainerIDs: []string{"bar"},
				ID:           1,
				IPv4:         net.ParseIP("1.1.1.1"),
				PodName:      "foo",
				PodNamespace: "default",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{
				ContainerIDs: tt.fields.ContainerID,
				ID:           tt.fields.ID,
				IPv4:         tt.fields.IPv4,
				IPv6:         tt.fields.IPv6,
				PodName:      tt.fields.PodName,
				PodNamespace: tt.fields.PodNamespace,
			}
			if got := e.EqualsByID(tt.arg); got != tt.want {
				t.Errorf("Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpoint_setFrom(t *testing.T) {
	type fields struct {
		ContainerIDs []string
		ID           uint64
		IPv4         net.IP
		IPv6         net.IP
		PodName      string
		PodNamespace string
		Labels       []string
	}
	type args struct {
		o *Endpoint
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Endpoint
	}{
		{
			name: "all fields are copied",
			fields: fields{
				ContainerIDs: nil,
				ID:           0,
				IPv4:         nil,
				IPv6:         nil,
				PodName:      "",
				PodNamespace: "",
				Labels:       nil,
			},
			args: args{
				o: &Endpoint{
					ContainerIDs: []string{"foo"},
					ID:           1,
					IPv4:         net.ParseIP("1.1.1.1"),
					IPv6:         net.ParseIP("fd00::"),
					PodName:      "pod-bar",
					PodNamespace: "cilium",
					Labels:       []string{"a", "b"},
				},
			},
			want: &Endpoint{
				ContainerIDs: []string{"foo"},
				ID:           1,
				IPv4:         net.ParseIP("1.1.1.1"),
				IPv6:         net.ParseIP("fd00::"),
				PodName:      "pod-bar",
				PodNamespace: "cilium",
				Labels:       []string{"a", "b"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Endpoint{
				ContainerIDs: tt.fields.ContainerIDs,
				ID:           tt.fields.ID,
				IPv4:         tt.fields.IPv4,
				IPv6:         tt.fields.IPv6,
				PodName:      tt.fields.PodName,
				PodNamespace: tt.fields.PodNamespace,
			}
			e.setFrom(tt.args.o)
			if !reflect.DeepEqual(e, tt.want) {
				t.Errorf("setFrom() got = %v, want %v", e, tt.want)
			}
		})
	}
}

func TestEndpoints_SyncEndpoints(t *testing.T) {
	es := &Endpoints{
		mutex: lock.RWMutex{},
		eps:   []*Endpoint{},
	}

	eps := []*Endpoint{
		{
			ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
			ID:           1,
			IPv4:         net.ParseIP("1.1.1.1").To4(),
			IPv6:         net.ParseIP("fd00::1").To16(),
			PodName:      "foo",
			PodNamespace: "default",
		},
		{
			ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
			ID:           2,
			IPv4:         net.ParseIP("1.1.1.2").To4(),
			IPv6:         net.ParseIP("fd00::2").To16(),
			PodName:      "bar",
			PodNamespace: "default",
		},
		{
			ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
			ID:           3,
			IPv4:         net.ParseIP("1.1.1.3").To4(),
			IPv6:         net.ParseIP("fd00::3").To16(),
			PodName:      "bar",
			PodNamespace: "kube-system",
		},
	}

	endpointsWanted := []*Endpoint{
		{
			ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
			ID:           1,
			IPv4:         net.ParseIP("1.1.1.1").To4(),
			IPv6:         net.ParseIP("fd00::1").To16(),
			PodName:      "foo",
			PodNamespace: "default",
		},
		{
			ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
			ID:           2,
			IPv4:         net.ParseIP("1.1.1.2").To4(),
			IPv6:         net.ParseIP("fd00::2").To16(),
			PodName:      "bar",
			PodNamespace: "default",
		},
		{
			ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
			ID:           3,
			IPv4:         net.ParseIP("1.1.1.3").To4(),
			IPv6:         net.ParseIP("fd00::3").To16(),
			PodName:      "bar",
			PodNamespace: "kube-system",
		},
	}

	// add 2 new endpoints
	es.SyncEndpoints(eps[0:2])

	es.mutex.RLock()
	// check if the endpoints were added
	assert.EqualValues(t, endpointsWanted[0:2], es.eps)
	es.mutex.RUnlock()

	// Add only the first endpoint,
	es.SyncEndpoints(eps[0:1])

	es.mutex.Lock()
	assert.EqualValues(t, endpointsWanted[0:1], es.eps)
	es.mutex.Unlock()

	// Re-add all endpoints
	es.SyncEndpoints(endpointsWanted)
	es.mutex.RLock()
	// check if the endpoints were added
	assert.EqualValues(t, endpointsWanted, es.eps)
	es.mutex.RUnlock()
}

func TestEndpoints_FindEPs(t *testing.T) {
	type args struct {
		epID      uint64
		namespace string
		podName   string
	}
	tests := []struct {
		name string
		eps  []*Endpoint
		args args
		want []Endpoint
	}{
		{
			name: "return all eps in a particular namespace",
			eps: []*Endpoint{
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
					ID:           1,
					IPv4:         net.ParseIP("1.1.1.1").To4(),
					IPv6:         net.ParseIP("fd00::1").To16(),
					PodName:      "foo",
					PodNamespace: "default",
				},
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
					ID:           2,
					IPv4:         net.ParseIP("1.1.1.2").To4(),
					IPv6:         net.ParseIP("fd00::2").To16(),
					PodName:      "bar",
					PodNamespace: "default",
				},
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb473"},
					ID:           3,
					IPv4:         net.ParseIP("1.1.1.3").To4(),
					IPv6:         net.ParseIP("fd00::3").To16(),
					PodName:      "bar",
					PodNamespace: "kube-system",
				},
			},
			args: args{
				namespace: "default",
			},
			want: []Endpoint{
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
					ID:           1,
					IPv4:         net.ParseIP("1.1.1.1").To4(),
					IPv6:         net.ParseIP("fd00::1").To16(),
					PodName:      "foo",
					PodNamespace: "default",
				},
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
					ID:           2,
					IPv4:         net.ParseIP("1.1.1.2").To4(),
					IPv6:         net.ParseIP("fd00::2").To16(),
					PodName:      "bar",
					PodNamespace: "default",
				},
			},
		},
		{
			name: "return the ep of a pod",
			eps: []*Endpoint{
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
					ID:           1,
					IPv4:         net.ParseIP("1.1.1.1").To4(),
					IPv6:         net.ParseIP("fd00::1").To16(),
					PodName:      "foo",
					PodNamespace: "default",
				},
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
					ID:           2,
					IPv4:         net.ParseIP("1.1.1.2").To4(),
					IPv6:         net.ParseIP("fd00::2").To16(),
					PodName:      "bar",
					PodNamespace: "default",
				},
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb473"},
					ID:           3,
					IPv4:         net.ParseIP("1.1.1.3").To4(),
					IPv6:         net.ParseIP("fd00::3").To16(),
					PodName:      "bar",
					PodNamespace: "kube-system",
				},
			},
			args: args{
				podName:   "bar",
				namespace: "kube-system",
			},
			want: []Endpoint{
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb473"},
					ID:           3,
					IPv4:         net.ParseIP("1.1.1.3").To4(),
					IPv6:         net.ParseIP("fd00::3").To16(),
					PodName:      "bar",
					PodNamespace: "kube-system",
				},
			},
		},
		{
			name: "return eps with the given pod name and namespace",
			eps: []*Endpoint{
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
					ID:           1,
					IPv4:         net.ParseIP("1.1.1.1").To4(),
					IPv6:         net.ParseIP("fd00::1").To16(),
					PodName:      "foo",
					PodNamespace: "default",
				},
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
					ID:           2,
					IPv4:         net.ParseIP("1.1.1.2").To4(),
					IPv6:         net.ParseIP("fd00::2").To16(),
					PodName:      "bar",
					PodNamespace: "default",
				},
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb473"},
					ID:           3,
					IPv4:         net.ParseIP("1.1.1.3").To4(),
					IPv6:         net.ParseIP("fd00::3").To16(),
					PodName:      "bar",
					PodNamespace: "kube-system",
				},
			},
			args: args{
				epID: 2,
			},
			want: []Endpoint{
				{
					ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471"},
					ID:           2,
					IPv4:         net.ParseIP("1.1.1.2").To4(),
					IPv6:         net.ParseIP("fd00::2").To16(),
					PodName:      "bar",
					PodNamespace: "default",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := &Endpoints{eps: tt.eps}
			if got := es.FindEPs(tt.args.epID, tt.args.namespace, tt.args.podName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindEPs() = %v, want %v", got, tt.want)
			}
		})
	}

	// Test that we can modify the endpoint without disrupting the original
	// endpoint
	epWant := Endpoint{
		ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
		ID:           1,
		IPv4:         net.ParseIP("1.1.1.1").To4(),
		IPv6:         net.ParseIP("fd00::1").To16(),
		PodName:      "foo",
		PodNamespace: "default",
	}
	eps := []*Endpoint{&epWant}
	es := &Endpoints{
		mutex: lock.RWMutex{},
		eps:   eps,
	}
	gotEps := es.FindEPs(1, "", "")
	assert.Len(t, gotEps, 1)
	assert.Equal(t, gotEps[0], epWant, 1)
	gotEps[0].ContainerIDs = append(gotEps[0].ContainerIDs, "foo")

	epWantModified := Endpoint{
		ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479", "foo"},
		ID:           1,
		IPv4:         net.ParseIP("1.1.1.1").To4(),
		IPv6:         net.ParseIP("fd00::1").To16(),
		PodName:      "foo",
		PodNamespace: "default",
	}

	assert.NotEqual(t, gotEps[0], epWant, 1)
	assert.Equal(t, gotEps[0], epWantModified, 1)
}

func TestEndpoints_GetEndpoint(t *testing.T) {
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name         string
		eps          []*Endpoint
		args         args
		wantEndpoint *Endpoint
		wantOk       bool
	}{
		{
			name: "found",
			eps: []*Endpoint{
				{
					ID:   15,
					IPv4: net.ParseIP("1.1.1.1"),
				},
			},
			args: args{
				ip: net.ParseIP("1.1.1.1"),
			},
			wantEndpoint: &Endpoint{
				ID:   15,
				IPv4: net.ParseIP("1.1.1.1"),
			},
			wantOk: true,
		},
		{
			name: "not found",
			eps: []*Endpoint{
				{
					ID:   15,
					IPv4: net.ParseIP("1.1.1.1"),
				},
			},
			args: args{
				ip: net.ParseIP("1.1.1.2"),
			},
			wantEndpoint: nil,
			wantOk:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := &Endpoints{eps: tt.eps}
			gotEndpoint, gotOk := es.GetEndpoint(tt.args.ip)
			if !reflect.DeepEqual(gotEndpoint, tt.wantEndpoint) {
				t.Errorf("GetEndpoint() gotEndpoint = %v, want %v", gotEndpoint, tt.wantEndpoint)
			}
			if gotOk != tt.wantOk {
				t.Errorf("GetEndpoint() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func TestEndpoints_DeleteEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		eps     []*Endpoint
		del     *Endpoint
		wantEps []*Endpoint
	}{
		{
			name:    "delete non-existing endpoint",
			eps:     []*Endpoint{{ID: 15}},
			del:     &Endpoint{ID: 12},
			wantEps: []*Endpoint{{ID: 15}},
		}, {
			name:    "delete first endpoint",
			eps:     []*Endpoint{{ID: 15}, {ID: 20}},
			del:     &Endpoint{ID: 15},
			wantEps: []*Endpoint{{ID: 20}},
		}, {
			name:    "delete last endpoint",
			eps:     []*Endpoint{{ID: 15}, {ID: 20}},
			del:     &Endpoint{ID: 20},
			wantEps: []*Endpoint{{ID: 15}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := &Endpoints{eps: tt.eps}
			es.DeleteEndpoint(tt.del)
			assert.Equal(t, tt.wantEps, es.eps)
		})
	}
}

func TestEndpoints_GetEndpointByContainerID(t *testing.T) {
	type args struct {
		id string
	}
	tests := []struct {
		name         string
		eps          []*Endpoint
		args         args
		wantEndpoint *Endpoint
		wantOk       bool
	}{
		{
			name: "found",
			eps: []*Endpoint{
				{
					ID:           15,
					ContainerIDs: []string{"c0", "c1"},
				},
			},
			args: args{
				id: "c1",
			},
			wantEndpoint: &Endpoint{
				ID:           15,
				ContainerIDs: []string{"c0", "c1"},
			},
			wantOk: true,
		},
		{
			name: "not found",
			eps: []*Endpoint{
				{
					ID:           15,
					ContainerIDs: []string{"c0", "c1"},
				},
			},
			args: args{
				id: "c2",
			},
			wantEndpoint: nil,
			wantOk:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := Endpoints{eps: tt.eps}
			gotEndpoint, gotOk := es.GetEndpointByContainerID(tt.args.id)
			assert.Equal(t, tt.wantEndpoint, gotEndpoint)
			assert.Equal(t, tt.wantOk, gotOk)
		})
	}
}

func TestEndpoint_Copy(t *testing.T) {
	ep := &Endpoint{
		ContainerIDs: nil,
		ID:           0,
		IPv4:         nil,
		IPv6:         nil,
		PodName:      "",
		PodNamespace: "",
		Labels:       nil,
	}
	cp := ep.DeepCopy()
	assert.Equal(t, ep, cp)

	ep = &Endpoint{
		ContainerIDs: []string{"c1", "c2"},
		ID:           3,
		IPv4:         net.ParseIP("1.1.1.1"),
		IPv6:         net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		PodName:      "pod1",
		PodNamespace: "ns1",
		Labels:       []string{"a=b", "c=d"},
	}
	cp1 := ep.DeepCopy()
	cp2 := ep.DeepCopy()
	assert.Equal(t, ep, cp2)
	assert.Equal(t, cp1, cp2)
	cp1.ContainerIDs = []string{"c3", "c4"}
	cp1.ID = 4
	cp1.IPv4 = net.ParseIP("2.2.2.2")
	cp1.IPv4 = net.ParseIP("eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee")
	cp1.PodName = "pod1"
	cp1.PodNamespace = "ns1"
	cp1.Labels = []string{"e=f"}
	assert.Equal(t, ep, cp2)
	assert.NotEqual(t, cp1, cp2)
}

func TestEndpoints_GetEndpointByPodName(t *testing.T) {
	type args struct {
		namespace string
		name      string
	}
	tests := []struct {
		name         string
		eps          []*Endpoint
		args         args
		wantEndpoint *Endpoint
		wantOk       bool
	}{
		{
			name: "found",
			eps: []*Endpoint{
				{PodNamespace: "ns1", PodName: "pod1"},
				{PodNamespace: "ns2", PodName: "pod2"},
			},
			args: args{
				namespace: "ns2",
				name:      "pod2",
			},
			wantEndpoint: &Endpoint{
				PodNamespace: "ns2",
				PodName:      "pod2",
			},
			wantOk: true,
		},
		{
			name: "not found",
			eps: []*Endpoint{
				{PodNamespace: "ns1", PodName: "pod1"},
				{PodNamespace: "ns2", PodName: "pod2"},
			},
			args: args{
				namespace: "ns3",
				name:      "pod3",
			},
			wantEndpoint: nil,
			wantOk:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es := Endpoints{eps: tt.eps}
			gotEndpoint, gotOk := es.GetEndpointByPodName(tt.args.namespace, tt.args.name)
			assert.Equal(t, tt.wantEndpoint, gotEndpoint)
			assert.Equal(t, tt.wantOk, gotOk)
		})
	}
}
