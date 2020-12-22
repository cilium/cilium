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

package agent_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/agent"
	"github.com/cilium/cilium/pkg/monitor/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/assert"
)

type mockEndpoint struct {
	ID        uint64
	Labels    []string
	PodName   string
	Namespace string
}

func (e *mockEndpoint) GetID() uint64           { return e.ID }
func (e *mockEndpoint) GetOpLabels() []string   { return e.Labels }
func (e *mockEndpoint) GetK8sPodName() string   { return e.PodName }
func (e *mockEndpoint) GetK8sNamespace() string { return e.Namespace }

func TestDecodeAgentEvent(t *testing.T) {
	unknownNotification := struct {
		Foo int64
		Bar int32
	}{
		Foo: 23,
		Bar: 42,
	}
	unknownNotificationJSON, _ := json.Marshal(unknownNotification)

	agentStartTS := time.Now()
	protoAgentStartTimestamp, err := ptypes.TimestampProto(agentStartTS)
	assert.NoError(t, err)

	mockEP := &mockEndpoint{
		ID:        65535,
		Labels:    []string{"custom=label", "label=another"},
		PodName:   "devnull",
		Namespace: "hubble",
	}

	oldID := uint32(511)

	tt := []struct {
		name string
		msg  api.AgentNotifyMessage
		ev   *flowpb.AgentEvent
	}{
		{
			name: "empty",
			msg:  api.AgentNotifyMessage{},
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_EVENT_UNKNOWN,
				Notification: &flowpb.AgentEvent_Unknown{
					Unknown: &flowpb.AgentEventUnknown{
						Type:         fmt.Sprintf("%d", api.AgentNotifyUnspec),
						Notification: "null",
					},
				},
			},
		},
		{
			name: "unspecified",
			msg: api.AgentNotifyMessage{
				Type:         api.AgentNotifyUnspec,
				Notification: unknownNotification,
			},
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_EVENT_UNKNOWN,
				Notification: &flowpb.AgentEvent_Unknown{
					Unknown: &flowpb.AgentEventUnknown{
						Type:         fmt.Sprintf("%d", api.AgentNotifyUnspec),
						Notification: string(unknownNotificationJSON),
					},
				},
			},
		},
		{
			name: "type and notification type mismatch",
			msg: api.AgentNotifyMessage{
				Type:         api.AgentNotifyStart,
				Notification: unknownNotification,
			},
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_EVENT_UNKNOWN,
				Notification: &flowpb.AgentEvent_Unknown{
					Unknown: &flowpb.AgentEventUnknown{
						Type:         fmt.Sprintf("%d", api.AgentNotifyStart),
						Notification: string(unknownNotificationJSON),
					},
				},
			},
		},

		{
			name: "StartMessage",
			msg:  api.StartMessage(agentStartTS),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_STARTED,
				Notification: &flowpb.AgentEvent_AgentStart{
					AgentStart: &flowpb.TimeNotification{
						Time: protoAgentStartTimestamp,
					},
				},
			},
		},
		{
			name: "PolicyUpdateMessage",
			msg:  api.PolicyUpdateMessage(42, []string{"hubble=rocks", "cilium=too"}, 7),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_POLICY_UPDATED,
				Notification: &flowpb.AgentEvent_PolicyUpdate{
					PolicyUpdate: &flowpb.PolicyUpdateNotification{
						RuleCount: 42,
						Labels:    []string{"hubble=rocks", "cilium=too"},
						Revision:  7,
					},
				},
			},
		},
		{
			name: "PolicyDeleteMessage",
			msg:  api.PolicyDeleteMessage(23, []string{"foo=bar"}, 255),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_POLICY_DELETED,
				Notification: &flowpb.AgentEvent_PolicyUpdate{
					PolicyUpdate: &flowpb.PolicyUpdateNotification{
						RuleCount: 23,
						Labels:    []string{"foo=bar"},
						Revision:  255,
					},
				},
			},
		},
		{
			name: "EndpointRegenMessage success",
			msg:  api.EndpointRegenMessage(mockEP, nil),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_ENDPOINT_REGENERATE_SUCCESS,
				Notification: &flowpb.AgentEvent_EndpointRegenerate{
					EndpointRegenerate: &flowpb.EndpointRegenNotification{
						Id:     mockEP.GetID(),
						Labels: mockEP.GetOpLabels(),
						Error:  "",
					},
				},
			},
		},
		{
			name: "EndpointRegenMessage failure",
			msg:  api.EndpointRegenMessage(mockEP, errors.New("error regenerating endpoint")),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_ENDPOINT_REGENERATE_FAILURE,
				Notification: &flowpb.AgentEvent_EndpointRegenerate{
					EndpointRegenerate: &flowpb.EndpointRegenNotification{
						Id:     mockEP.GetID(),
						Labels: mockEP.GetOpLabels(),
						Error:  "error regenerating endpoint",
					},
				},
			},
		},
		{
			name: "EndpointCreateMessage",
			msg:  api.EndpointCreateMessage(mockEP),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_ENDPOINT_CREATED,
				Notification: &flowpb.AgentEvent_EndpointUpdate{
					EndpointUpdate: &flowpb.EndpointUpdateNotification{
						Id:        mockEP.GetID(),
						Labels:    mockEP.GetOpLabels(),
						Error:     "",
						PodName:   mockEP.GetK8sPodName(),
						Namespace: mockEP.GetK8sNamespace(),
					},
				},
			},
		},
		{
			name: "EndpointDeleteMessage",
			msg:  api.EndpointDeleteMessage(mockEP),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_ENDPOINT_DELETED,
				Notification: &flowpb.AgentEvent_EndpointUpdate{
					EndpointUpdate: &flowpb.EndpointUpdateNotification{
						Id:        mockEP.GetID(),
						Labels:    mockEP.GetOpLabels(),
						Error:     "",
						PodName:   mockEP.GetK8sPodName(),
						Namespace: mockEP.GetK8sNamespace(),
					},
				},
			},
		},
		{
			name: "IPCacheUpsertedMessage (insert)",
			msg:  api.IPCacheUpsertedMessage("10.0.1.42/32", 1023, nil, net.ParseIP("10.1.5.4"), nil, 0xff, "default", "foobar"),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_IPCACHE_UPSERTED,
				Notification: &flowpb.AgentEvent_IpcacheUpdate{
					IpcacheUpdate: &flowpb.IPCacheNotification{
						Cidr:        "10.0.1.42/32",
						Identity:    1023,
						OldIdentity: nil,
						HostIp:      "10.1.5.4",
						OldHostIp:   "",
						EncryptKey:  0xff,
						Namespace:   "default",
						PodName:     "foobar",
					},
				},
			},
		},
		{
			name: "IPCacheUpsertedMessage (update)",
			msg:  api.IPCacheUpsertedMessage("192.168.10.11/32", 1023, &oldID, net.ParseIP("10.1.5.4"), net.ParseIP("10.2.6.11"), 5, "hubble", "podmcpodface"),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_IPCACHE_UPSERTED,
				Notification: &flowpb.AgentEvent_IpcacheUpdate{
					IpcacheUpdate: &flowpb.IPCacheNotification{
						Cidr:     "192.168.10.11/32",
						Identity: 1023,
						OldIdentity: &wrappers.UInt32Value{
							Value: oldID,
						},
						HostIp:     "10.1.5.4",
						OldHostIp:  "10.2.6.11",
						EncryptKey: 5,
						Namespace:  "hubble",
						PodName:    "podmcpodface",
					},
				},
			},
		},
		{
			name: "IPCacheDeletedMessage",
			msg:  api.IPCacheDeletedMessage("192.168.10.0/24", 6048, nil, net.ParseIP("10.1.5.4"), nil, 0, "", ""),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_IPCACHE_DELETED,
				Notification: &flowpb.AgentEvent_IpcacheUpdate{
					IpcacheUpdate: &flowpb.IPCacheNotification{
						Cidr:        "192.168.10.0/24",
						Identity:    6048,
						OldIdentity: nil,
						HostIp:      "10.1.5.4",
						OldHostIp:   "",
						EncryptKey:  0,
						Namespace:   "",
						PodName:     "",
					},
				},
			},
		},
		{
			name: "ServiceUpsertMessage",
			msg: api.ServiceUpsertMessage(
				214,
				monitorAPI.ServiceUpsertNotificationAddr{
					IP:   net.ParseIP("10.240.12.1"),
					Port: 8080,
				},
				[]monitorAPI.ServiceUpsertNotificationAddr{
					{
						IP:   net.ParseIP("192.168.3.59"),
						Port: 9099,
					},
					{
						IP:   net.ParseIP("192.168.3.57"),
						Port: 7077,
					},
				},
				"ClusterIP",
				"myTrafficPolicy",
				"myService",
				"myNamespace",
			),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_SERVICE_UPSERTED,
				Notification: &flowpb.AgentEvent_ServiceUpsert{
					ServiceUpsert: &flowpb.ServiceUpsertNotification{
						Id: 214,
						FrontendAddress: &flowpb.ServiceUpsertNotificationAddr{
							Ip:   "10.240.12.1",
							Port: 8080,
						},
						BackendAddresses: []*flowpb.ServiceUpsertNotificationAddr{
							{
								Ip:   "192.168.3.59",
								Port: 9099,
							},
							{
								Ip:   "192.168.3.57",
								Port: 7077,
							},
						},
						Type:          "ClusterIP",
						TrafficPolicy: "myTrafficPolicy",
						Name:          "myService",
						Namespace:     "myNamespace",
					},
				},
			},
		},
		{
			name: "ServiceDeleteMessage",
			msg:  api.ServiceDeleteMessage(1048575),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_SERVICE_DELETED,
				Notification: &flowpb.AgentEvent_ServiceDelete{
					ServiceDelete: &flowpb.ServiceDeleteNotification{
						Id: 1048575,
					},
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ev := agent.NotifyMessageToProto(tc.msg)
			assert.Equal(t, tc.ev, ev)
		})
	}
}
