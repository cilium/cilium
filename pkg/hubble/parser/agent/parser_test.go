// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package agent_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/agent"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type mockEndpoint struct {
	ID        uint16
	Labels    []string
	PodName   string
	Namespace string
}

func (e *mockEndpoint) GetID() uint64           { return uint64(e.ID) }
func (e *mockEndpoint) GetOpLabels() []string   { return e.Labels }
func (e *mockEndpoint) GetK8sPodName() string   { return e.PodName }
func (e *mockEndpoint) GetK8sNamespace() string { return e.Namespace }
func (e *mockEndpoint) GetID16() uint16         { return e.ID }

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
	agentStartTSProto := timestamppb.New(agentStartTS)
	assert.NoError(t, agentStartTSProto.CheckValid())

	mockEP := &mockEndpoint{
		ID:        65535,
		Labels:    []string{"custom=label", "label=another"},
		PodName:   "devnull",
		Namespace: "hubble",
	}

	oldID := uint32(511)

	tt := []struct {
		name string
		msg  monitorAPI.AgentNotifyMessage
		ev   *flowpb.AgentEvent
	}{
		{
			name: "empty",
			msg:  monitorAPI.AgentNotifyMessage{},
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_EVENT_UNKNOWN,
				Notification: &flowpb.AgentEvent_Unknown{
					Unknown: &flowpb.AgentEventUnknown{
						Type:         fmt.Sprintf("%d", monitorAPI.AgentNotifyUnspec),
						Notification: "null",
					},
				},
			},
		},
		{
			name: "unspecified",
			msg: monitorAPI.AgentNotifyMessage{
				Type:         monitorAPI.AgentNotifyUnspec,
				Notification: unknownNotification,
			},
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_EVENT_UNKNOWN,
				Notification: &flowpb.AgentEvent_Unknown{
					Unknown: &flowpb.AgentEventUnknown{
						Type:         fmt.Sprintf("%d", monitorAPI.AgentNotifyUnspec),
						Notification: string(unknownNotificationJSON),
					},
				},
			},
		},
		{
			name: "type and notification type mismatch",
			msg: monitorAPI.AgentNotifyMessage{
				Type:         monitorAPI.AgentNotifyStart,
				Notification: unknownNotification,
			},
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_EVENT_UNKNOWN,
				Notification: &flowpb.AgentEvent_Unknown{
					Unknown: &flowpb.AgentEventUnknown{
						Type:         fmt.Sprintf("%d", monitorAPI.AgentNotifyStart),
						Notification: string(unknownNotificationJSON),
					},
				},
			},
		},

		{
			name: "StartMessage",
			msg:  monitorAPI.StartMessage(agentStartTS),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_AGENT_STARTED,
				Notification: &flowpb.AgentEvent_AgentStart{
					AgentStart: &flowpb.TimeNotification{
						Time: agentStartTSProto,
					},
				},
			},
		},
		{
			name: "PolicyUpdateMessage",
			msg:  monitorAPI.PolicyUpdateMessage(42, []string{"hubble=rocks", "cilium=too"}, 7),
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
			msg:  monitorAPI.PolicyDeleteMessage(23, []string{"foo=bar"}, 255),
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
			msg:  monitorAPI.EndpointRegenMessage(mockEP, nil),
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
			msg:  monitorAPI.EndpointRegenMessage(mockEP, errors.New("error regenerating endpoint")),
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
			msg:  monitorAPI.EndpointCreateMessage(mockEP),
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
			msg:  monitorAPI.EndpointDeleteMessage(mockEP),
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
			msg:  monitorAPI.IPCacheUpsertedMessage("10.0.1.42/32", 1023, nil, net.ParseIP("10.1.5.4"), nil, 0xff, "default", "foobar"),
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
			msg:  monitorAPI.IPCacheUpsertedMessage("192.168.10.11/32", 1023, &oldID, net.ParseIP("10.1.5.4"), net.ParseIP("10.2.6.11"), 5, "hubble", "podmcpodface"),
			ev: &flowpb.AgentEvent{
				Type: flowpb.AgentEventType_IPCACHE_UPSERTED,
				Notification: &flowpb.AgentEvent_IpcacheUpdate{
					IpcacheUpdate: &flowpb.IPCacheNotification{
						Cidr:     "192.168.10.11/32",
						Identity: 1023,
						OldIdentity: &wrapperspb.UInt32Value{
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
			msg:  monitorAPI.IPCacheDeletedMessage("192.168.10.0/24", 6048, nil, net.ParseIP("10.1.5.4"), nil, 0, "", ""),
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
			msg: monitorAPI.ServiceUpsertMessage(
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
				"myTrafficPolicyExt",
				"myTrafficPolicyInt",
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
						Type:             "ClusterIP",
						TrafficPolicy:    "myTrafficPolicyExt",
						ExtTrafficPolicy: "myTrafficPolicyExt",
						IntTrafficPolicy: "myTrafficPolicyInt",
						Name:             "myService",
						Namespace:        "myNamespace",
					},
				},
			},
		},
		{
			name: "ServiceDeleteMessage",
			msg:  monitorAPI.ServiceDeleteMessage(1048575),
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
