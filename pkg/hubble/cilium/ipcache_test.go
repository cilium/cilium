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

package cilium

import (
	"net"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/ipcache"
	"github.com/cilium/cilium/pkg/hubble/logger"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/source"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObserverServer_syncIPCache(t *testing.T) {
	cidr1111 := "1.1.1.1/32"
	cidr2222 := "2.2.2.2/32"
	cidr3333 := "3.3.3.3/32"
	cidr4444 := "4.4.4.4/32"

	ipc := ipcache.New()
	fakeClient := &testutils.FakeCiliumClient{
		FakeGetIPCache: func() ([]*models.IPListEntry, error) {
			id100 := int64(100)

			return []*models.IPListEntry{
				{Cidr: &cidr1111, Identity: &id100},
				{Cidr: &cidr2222, Identity: &id100},
				{Cidr: &cidr3333, Identity: &id100, Metadata: &models.IPListEntryMetadata{
					Source:    string(source.Kubernetes),
					Name:      "pod-3",
					Namespace: "ns-3",
				}},
				{Cidr: &cidr4444, Identity: &id100},
			}, nil
		},
	}

	c := &State{
		ciliumClient: fakeClient,
		ipcache:      ipc,
		log:          logger.GetLogger(),
	}

	ipCacheEvents := make(chan monitorAPI.AgentNotify, 100)
	go func() {
		id100 := uint32(100)
		id200 := uint32(200)

		// stale update, should be ignored
		n, err := monitorAPI.IPCacheNotificationRepr("3.3.3.3/32", id100, &id200, nil, nil, 0, "", "")
		require.NoError(t, err)
		ipCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyIPCacheUpserted, Text: n}

		// delete 2.2.2.2
		n, err = monitorAPI.IPCacheNotificationRepr("2.2.2.2/32", id100, nil, nil, nil, 0, "", "")
		require.NoError(t, err)
		ipCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyIPCacheDeleted, Text: n}

		// reinsert 2.2.2.2 with pod name
		n, err = monitorAPI.IPCacheNotificationRepr("2.2.2.2/32", id100, nil, nil, nil, 0, "ns-2", "pod-2")
		require.NoError(t, err)
		ipCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyIPCacheUpserted, Text: n}

		// update 1.1.1.1 with pod name
		n, err = monitorAPI.IPCacheNotificationRepr("1.1.1.1/32", id100, &id100, nil, nil, 0, "ns-1", "pod-1")
		require.NoError(t, err)
		ipCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyIPCacheUpserted, Text: n}

		// delete 4.4.4.4
		n, err = monitorAPI.IPCacheNotificationRepr("4.4.4.4/32", id100, nil, nil, nil, 0, "", "")
		require.NoError(t, err)
		ipCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyIPCacheDeleted, Text: n}

		close(ipCacheEvents)
	}()

	// blocks until channel is closed
	c.syncIPCache(ipCacheEvents)
	assert.Equal(t, 0, len(ipCacheEvents))

	id100 := identity.NumericIdentity(100)

	tests := []struct {
		ip net.IP
		id ipcache.IPIdentity
		ok bool
	}{
		{ip: net.ParseIP("1.1.1.1"), id: ipcache.IPIdentity{Identity: id100, Namespace: "ns-1", PodName: "pod-1"}, ok: true},
		{ip: net.ParseIP("2.2.2.2"), id: ipcache.IPIdentity{Identity: id100, Namespace: "ns-2", PodName: "pod-2"}, ok: true},
		{ip: net.ParseIP("3.3.3.3"), id: ipcache.IPIdentity{Identity: id100, Namespace: "ns-3", PodName: "pod-3"}, ok: true},
		{ip: net.ParseIP("4.4.4.4"), ok: false},
	}
	for _, tt := range tests {
		gotID, gotOk := ipc.GetIPIdentity(tt.ip)
		if gotID != tt.id {
			t.Errorf("IPCache.GetIPIdentity() gotID = %v, want %v", gotID, tt.id)
		}
		if gotOk != tt.ok {
			t.Errorf("IPCache.GetPodNameOf() gotOk = %v, want %v", gotOk, tt.ok)
		}
	}
}

func TestLegacyPodGetter_GetPodNameOf(t *testing.T) {
	type fields struct {
		IPGetter       getters.IPGetter
		EndpointGetter getters.EndpointGetter
	}
	type args struct {
		ip net.IP
	}
	type want struct {
		id ipcache.IPIdentity
		ok bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "available in ipcache",
			fields: fields{
				IPGetter: &testutils.FakeIPGetter{
					OnGetIPIdentity: func(ip net.IP) (identity ipcache.IPIdentity, ok bool) {
						return ipcache.IPIdentity{Namespace: "default", PodName: "xwing"}, true
					},
				},
				EndpointGetter: &testutils.NoopEndpointGetter,
			},
			args: args{
				ip: net.ParseIP("1.1.1.15"),
			},
			want: want{
				id: ipcache.IPIdentity{Namespace: "default", PodName: "xwing"},
				ok: true,
			},
		},
		{
			name: "available in endpoints",
			fields: fields{
				IPGetter: &testutils.NoopIPGetter,
				EndpointGetter: &testutils.FakeEndpointGetter{
					OnGetEndpointInfo: func(_ net.IP) (v1.EndpointInfo, bool) {
						return &v1.Endpoint{
							ID:           16,
							IPv4:         net.ParseIP("1.1.1.15"),
							PodName:      "deathstar",
							PodNamespace: "default",
						}, true
					},
				},
			},
			args: args{
				ip: net.ParseIP("1.1.1.15"),
			},
			want: want{
				id: ipcache.IPIdentity{Namespace: "default", PodName: "deathstar"},
				ok: true,
			},
		},
		{
			name: "available in both",
			fields: fields{
				IPGetter: &testutils.FakeIPGetter{
					OnGetIPIdentity: func(ip net.IP) (identity ipcache.IPIdentity, ok bool) {
						return ipcache.IPIdentity{Namespace: "default", PodName: "xwing"}, true
					},
				},
				EndpointGetter: &testutils.FakeEndpointGetter{
					OnGetEndpointInfo: func(_ net.IP) (v1.EndpointInfo, bool) {
						return &v1.Endpoint{
							ID:           16,
							IPv4:         net.ParseIP("1.1.1.15"),
							PodName:      "deathstar",
							PodNamespace: "default",
						}, true
					},
				},
			},
			args: args{
				ip: net.ParseIP("1.1.1.15"),
			},
			want: want{
				id: ipcache.IPIdentity{Namespace: "default", PodName: "xwing"},
				ok: true,
			},
		},
		{
			name: "available in none",
			fields: fields{
				IPGetter:       &testutils.NoopIPGetter,
				EndpointGetter: &testutils.NoopEndpointGetter,
			},
			args: args{
				ip: net.ParseIP("1.1.1.15"),
			},
			want: want{
				ok: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &LegacyPodGetter{
				PodGetter:      tt.fields.IPGetter,
				EndpointGetter: tt.fields.EndpointGetter,
			}

			gotID, gotOk := l.GetIPIdentity(tt.args.ip)
			if gotID != tt.want.id {
				t.Errorf("IPCache.GetIPIdentity() gotID = %v, want %v", gotID, tt.want.id)
			}
			if gotOk != tt.want.ok {
				t.Errorf("IPCache.GetPodNameOf() gotOk = %v, want %v", gotOk, tt.want.ok)
			}

		})
	}
}
