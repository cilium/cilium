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
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/logger"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/lock"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/stretchr/testify/assert"
)

func TestObserverServer_syncAllEndpoints(t *testing.T) {
	refreshEndpointList = 50 * time.Millisecond
	var (
		returnEmptyEndpoints int32
		endpointsMutex       lock.RWMutex
		endpoints            []*v1.Endpoint
	)

	fakeClient := &testutils.FakeCiliumClient{
		FakeEndpointList: func() ([]*models.Endpoint, error) {
			if atomic.LoadInt32(&returnEmptyEndpoints) != 0 {
				return []*models.Endpoint{}, nil
			}
			eps := []*models.Endpoint{
				{
					ID: 1,
					Status: &models.EndpointStatus{
						ExternalIdentifiers: &models.EndpointIdentifiers{
							ContainerID: "313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479",
							PodName:     "default/foo",
						},
						Networking: &models.EndpointNetworking{
							Addressing: []*models.AddressPair{
								{
									IPV4: "1.1.1.1",
									IPV6: "fd00::1",
								},
							},
						},
					},
				},
				{
					ID: 2,
					Status: &models.EndpointStatus{
						ExternalIdentifiers: &models.EndpointIdentifiers{
							ContainerID: "313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb471",
							PodName:     "default/bar",
						},
						Networking: &models.EndpointNetworking{
							Addressing: []*models.AddressPair{
								{
									IPV4: "1.1.1.2",
									IPV6: "fd00::2",
								},
							},
						},
					},
				},
			}
			return eps, nil
		},
	}

	fakeHandler := &testutils.FakeEndpointsHandler{
		FakeSyncEndpoints: func(newEndpoint []*v1.Endpoint) {
			if len(newEndpoint) == 0 {
				endpointsMutex.Lock()
				endpoints = nil
				endpointsMutex.Unlock()
			}
		},
		FakeUpdateEndpoint: func(ep *v1.Endpoint) {
			endpointsMutex.Lock()
			endpoints = append(endpoints, ep)
			endpointsMutex.Unlock()
		},
	}
	c := &State{
		ciliumClient: fakeClient,
		endpoints:    fakeHandler,
		log:          logger.GetLogger(),
	}
	go c.syncEndpoints()

	time.Sleep(2 * refreshEndpointList)

	endpointsWanted := []*v1.Endpoint{
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
	}
	endpointsMutex.Lock()
	assert.EqualValues(t, endpointsWanted, endpoints)
	endpointsMutex.Unlock()

	// stop returning any endpoints so all of them will be marked as deleted
	atomic.StoreInt32(&returnEmptyEndpoints, 1)
	time.Sleep(2 * refreshEndpointList)
	endpointsWanted = nil
	endpointsMutex.Lock()
	assert.EqualValues(t, endpointsWanted, endpoints)
	endpointsMutex.Unlock()
}

func TestObserverServer_EndpointAddEvent(t *testing.T) {
	once := sync.Once{}
	wg := sync.WaitGroup{}
	wg.Add(2)
	ecn := &monitorAPI.EndpointCreateNotification{
		EndpointRegenNotification: monitorAPI.EndpointRegenNotification{
			ID: 13,
		},
	}
	ecnMarshal, err := json.Marshal(ecn)
	assert.Nil(t, err)
	fakeClient := &testutils.FakeCiliumClient{
		FakeGetEndpoint: func(epID uint64) (*models.Endpoint, error) {
			defer wg.Done()
			assert.Equal(t, uint64(13), epID)
			return &models.Endpoint{
				ID: 13,
				Status: &models.EndpointStatus{
					ExternalIdentifiers: &models.EndpointIdentifiers{
						ContainerID: "123",
						PodName:     "default/bar",
					},
					Networking: &models.EndpointNetworking{
						Addressing: []*models.AddressPair{
							{
								IPV4: "10.0.0.1",
								IPV6: "fd00::1",
							},
						},
					},
				},
			}, nil
		},
	}
	fakeHandler := &testutils.FakeEndpointsHandler{
		FakeUpdateEndpoint: func(ep *v1.Endpoint) {
			once.Do(func() {
				defer wg.Done()
				wanted := &v1.Endpoint{
					ContainerIDs: []string{"123"},
					ID:           13,
					IPv4:         net.ParseIP("10.0.0.1").To4(),
					IPv6:         net.ParseIP("fd00::1").To16(),
					PodName:      "bar",
					PodNamespace: "default",
				}
				assert.Equal(t, wanted, ep)
			})
		},
	}
	epEventsCh := make(chan monitorAPI.AgentNotify, 1)
	c := &State{
		ciliumClient:   fakeClient,
		endpoints:      fakeHandler,
		endpointEvents: epEventsCh,
		log:            logger.GetLogger(),
	}
	go c.consumeEndpointEvents()

	c.GetEndpointEventsChannel() <- monitorAPI.AgentNotify{
		Type: monitorAPI.AgentNotifyEndpointCreated,
		Text: string(ecnMarshal),
	}
	wg.Wait()

	// Endpoint is not found so we don't even add it to the list of endpoints
	wg = sync.WaitGroup{}
	fakeClient = &testutils.FakeCiliumClient{
		FakeGetEndpoint: func(epID uint64) (*models.Endpoint, error) {
			defer wg.Done()
			assert.Equal(t, uint64(13), epID)
			return nil, nil
		},
	}
	wg.Add(1)
	c = &State{
		ciliumClient:   fakeClient,
		endpoints:      fakeHandler,
		endpointEvents: epEventsCh,
		log:            logger.GetLogger(),
	}
	go c.consumeEndpointEvents()

	c.GetEndpointEventsChannel() <- monitorAPI.AgentNotify{
		Type: monitorAPI.AgentNotifyEndpointCreated,
		Text: string(ecnMarshal),
	}
	wg.Wait()
}

func TestObserverServer_EndpointDeleteEvent(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	edn := &monitorAPI.EndpointDeleteNotification{
		EndpointRegenNotification: monitorAPI.EndpointRegenNotification{
			ID: 13,
		},
		PodName:   "bar",
		Namespace: "default",
	}
	ednMarshal, err := json.Marshal(edn)
	assert.Nil(t, err)
	fakeHandler := &testutils.FakeEndpointsHandler{
		FakeDeleteEndpoint: func(ep *v1.Endpoint) {
			defer wg.Done()
			wanted := &v1.Endpoint{
				ID:           13,
				PodName:      "bar",
				PodNamespace: "default",
			}
			assert.Equal(t, wanted, ep)
		},
	}
	epEventsCh := make(chan monitorAPI.AgentNotify, 1)
	c := &State{
		endpoints:      fakeHandler,
		endpointEvents: epEventsCh,
		log:            logger.GetLogger(),
	}
	go c.consumeEndpointEvents()

	c.GetEndpointEventsChannel() <- monitorAPI.AgentNotify{
		Type: monitorAPI.AgentNotifyEndpointDeleted,
		Text: string(ednMarshal),
	}
	wg.Wait()
}

func TestObserverServer_EndpointRegenEvent(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	ern := &monitorAPI.EndpointRegenNotification{
		ID: 13,
	}
	ednMarshal, err := json.Marshal(ern)
	assert.Nil(t, err)
	fakeClient := &testutils.FakeCiliumClient{
		FakeGetEndpoint: func(epID uint64) (*models.Endpoint, error) {
			defer wg.Done()
			assert.Equal(t, uint64(13), epID)
			return &models.Endpoint{
				ID: 13,
				Status: &models.EndpointStatus{
					ExternalIdentifiers: &models.EndpointIdentifiers{
						ContainerID: "123",
						PodName:     "default/bar",
					},
					Networking: &models.EndpointNetworking{
						Addressing: []*models.AddressPair{
							{
								IPV4: "10.0.0.1",
								IPV6: "fd00::1",
							},
						},
					},
				},
			}, nil
		},
	}
	fakeHandler := &testutils.FakeEndpointsHandler{
		FakeUpdateEndpoint: func(ep *v1.Endpoint) {
			defer wg.Done()
			wanted := &v1.Endpoint{
				ContainerIDs: []string{"123"},
				ID:           13,
				IPv4:         net.ParseIP("10.0.0.1").To4(),
				IPv6:         net.ParseIP("fd00::1").To16(),
				PodName:      "bar",
				PodNamespace: "default",
			}
			assert.Equal(t, wanted, ep)
		},
	}
	epEventsCh := make(chan monitorAPI.AgentNotify, 1)
	wg.Add(1)
	c := &State{
		ciliumClient:   fakeClient,
		endpoints:      fakeHandler,
		endpointEvents: epEventsCh,
		log:            logger.GetLogger(),
	}
	go c.consumeEndpointEvents()

	c.GetEndpointEventsChannel() <- monitorAPI.AgentNotify{
		Type: monitorAPI.AgentNotifyEndpointRegenerateSuccess,
		Text: string(ednMarshal),
	}
	wg.Wait()
}

func TestGetNamespace(t *testing.T) {
	ep := models.Endpoint{
		ID:   0,
		Spec: nil,
		Status: &models.EndpointStatus{
			Identity: &models.Identity{
				Labels: []string{"a=b", "c=d", "e=f"},
			},
		},
	}
	assert.Empty(t, GetNamespace(&ep))
	ns := "mynamespace"
	ep.Status.Identity.Labels = []string{"a=b", "c=d", fmt.Sprintf("%s=%s", v1.K8sNamespaceTag, ns)}
	assert.Equal(t, GetNamespace(&ep), ns)
}
