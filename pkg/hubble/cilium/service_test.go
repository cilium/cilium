// Copyright 2020 Authors of Hubble
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

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hubble/logger"
	"github.com/cilium/cilium/pkg/hubble/servicecache"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObserverServer_syncServiceCache(t *testing.T) {
	svcc := servicecache.New()
	fakeClient := &testutils.FakeCiliumClient{
		FakeGetServiceCache: func() ([]*models.Service, error) {
			return []*models.Service{
				{
					Spec: &models.ServiceSpec{
						ID:              100,
						FrontendAddress: &models.FrontendAddress{IP: "1.1.1.1", Port: 53},
						Flags:           &models.ServiceSpecFlags{Name: "svc-1", Namespace: "ns-1"},
					},
				}, {
					Spec: &models.ServiceSpec{
						ID:              200,
						FrontendAddress: &models.FrontendAddress{IP: "2.2.2.2", Port: 42},
						Flags:           &models.ServiceSpecFlags{Name: "svc-2", Namespace: "ns-2"},
					},
				}, {
					Spec: &models.ServiceSpec{
						ID:              300,
						FrontendAddress: &models.FrontendAddress{IP: "3.3.3.3", Port: 24},
						Flags:           &models.ServiceSpecFlags{Name: "svc-3", Namespace: "ns-3"},
					},
				}, {
					Spec: &models.ServiceSpec{
						ID:              400,
						FrontendAddress: &models.FrontendAddress{IP: "2001:db8::68", Port: 22},
						Flags:           &models.ServiceSpecFlags{Name: "svc-4", Namespace: "ns-4"},
					},
				},
			}, nil
		},
	}

	c := &State{
		ciliumClient: fakeClient,
		serviceCache: svcc,
		log:          logger.GetLogger(),
	}

	serviceCacheEvents := make(chan monitorAPI.AgentNotify, 100)
	go func() {
		// stale update, should be ignored
		n, err := monitorAPI.ServiceUpsertRepr(
			100,
			monitorAPI.ServiceUpsertNotificationAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53},
			[]monitorAPI.ServiceUpsertNotificationAddr{},
			"",
			"",
			"svc-1",
			"ns-1",
		)
		require.NoError(t, err)
		serviceCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyServiceUpserted, Text: n}

		// delete 2.2.2.2
		n, err = monitorAPI.ServiceDeleteRepr(200)
		require.NoError(t, err)
		serviceCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyServiceDeleted, Text: n}

		// reinsert 2.2.2.2 with new service name
		n, err = monitorAPI.ServiceUpsertRepr(
			200,
			monitorAPI.ServiceUpsertNotificationAddr{IP: net.IPv4(2, 2, 2, 2), Port: 42},
			[]monitorAPI.ServiceUpsertNotificationAddr{},
			"",
			"",
			"svc-2b-or-not-2b",
			"ns-2",
		)
		require.NoError(t, err)
		serviceCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyServiceUpserted, Text: n}

		// update 3.3.3.3 with new port
		n, err = monitorAPI.ServiceUpsertRepr(
			300,
			monitorAPI.ServiceUpsertNotificationAddr{IP: net.IPv4(3, 3, 3, 3), Port: 443},
			[]monitorAPI.ServiceUpsertNotificationAddr{},
			"",
			"",
			"svc-3",
			"ns-3",
		)
		require.NoError(t, err)
		serviceCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyServiceUpserted, Text: n}

		// delete 2001:db8::68
		n, err = monitorAPI.ServiceDeleteRepr(400)
		require.NoError(t, err)
		serviceCacheEvents <- monitorAPI.AgentNotify{Type: monitorAPI.AgentNotifyServiceDeleted, Text: n}

		close(serviceCacheEvents)
	}()

	// blocks until channel is closed
	c.syncServiceCache(serviceCacheEvents)
	assert.Equal(t, 0, len(serviceCacheEvents))

	tests := []struct {
		ip      net.IP
		port    uint16
		service pb.Service
		ok      bool
	}{
		{
			ip:   net.IPv4(1, 1, 1, 1),
			port: 53,
			service: pb.Service{
				Name:      "svc-1",
				Namespace: "ns-1",
			},
			ok: true,
		}, {
			ip:   net.IPv4(2, 2, 2, 2),
			port: 42,
			service: pb.Service{
				Name:      "svc-2b-or-not-2b",
				Namespace: "ns-2",
			},
			ok: true,
		}, {
			ip:   net.IPv4(3, 3, 3, 3),
			port: 443,
			service: pb.Service{
				Name:      "svc-3",
				Namespace: "ns-3",
			},
			ok: true,
		}, {
			ip:      net.ParseIP("2001:db8::68"),
			port:    22,
			service: pb.Service{},
			ok:      false,
		},
	}
	for _, tt := range tests {
		gotService, gotOK := svcc.GetServiceByAddr(tt.ip, tt.port)
		assert.Equal(t, tt.service, gotService)
		if gotOK != tt.ok {
			t.Errorf("ServiceCache.GetServiceByAddr() gotOK = %v, want %v", gotOK, tt.ok)
		}
	}
}
