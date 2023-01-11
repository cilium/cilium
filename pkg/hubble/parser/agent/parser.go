// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func notifyTimeNotificationToProto(typ flowpb.AgentEventType, n monitorAPI.TimeNotification) *flowpb.AgentEvent {
	var ts *timestamppb.Timestamp
	if goTime, err := time.Parse(time.RFC3339Nano, n.Time); err == nil {
		ts = timestamppb.New(goTime)
	}
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_AgentStart{
			AgentStart: &flowpb.TimeNotification{
				Time: ts,
			},
		},
	}
}

func notifyPolicyNotificationToProto(typ flowpb.AgentEventType, n monitorAPI.PolicyUpdateNotification) *flowpb.AgentEvent {
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_PolicyUpdate{
			PolicyUpdate: &flowpb.PolicyUpdateNotification{
				RuleCount: int64(n.RuleCount),
				Labels:    n.Labels,
				Revision:  n.Revision,
			},
		},
	}
}

func notifyEndpointRegenNotificationToProto(typ flowpb.AgentEventType, n monitorAPI.EndpointRegenNotification) *flowpb.AgentEvent {
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_EndpointRegenerate{
			EndpointRegenerate: &flowpb.EndpointRegenNotification{
				Id:     n.ID,
				Labels: n.Labels,
				Error:  n.Error,
			},
		},
	}
}

func notifyEndpointUpdateNotificationToProto(typ flowpb.AgentEventType, n monitorAPI.EndpointNotification) *flowpb.AgentEvent {
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_EndpointUpdate{
			EndpointUpdate: &flowpb.EndpointUpdateNotification{
				Id:        n.ID,
				Labels:    n.Labels,
				Error:     n.Error,
				PodName:   n.PodName,
				Namespace: n.Namespace,
			},
		},
	}
}
func notifyIPCacheNotificationToProto(typ flowpb.AgentEventType, n monitorAPI.IPCacheNotification) *flowpb.AgentEvent {
	var oldIdentity *wrapperspb.UInt32Value
	if n.OldIdentity != nil {
		oldIdentity = &wrapperspb.UInt32Value{
			Value: *n.OldIdentity,
		}
	}
	var hostIPString string
	if n.HostIP != nil {
		hostIPString = n.HostIP.String()
	}
	var oldHostIPString string
	if n.OldHostIP != nil {
		oldHostIPString = n.OldHostIP.String()
	}
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_IpcacheUpdate{
			IpcacheUpdate: &flowpb.IPCacheNotification{
				Cidr:        n.CIDR,
				Identity:    n.Identity,
				OldIdentity: oldIdentity,
				HostIp:      hostIPString,
				OldHostIp:   oldHostIPString,
				EncryptKey:  uint32(n.EncryptKey),
				Namespace:   n.Namespace,
				PodName:     n.PodName,
			},
		},
	}
}

func notifyServiceUpsertedToProto(typ flowpb.AgentEventType, n monitorAPI.ServiceUpsertNotification) *flowpb.AgentEvent {
	feAddr := &flowpb.ServiceUpsertNotificationAddr{
		Ip:   n.Frontend.IP.String(),
		Port: uint32(n.Frontend.Port),
	}
	beAddrs := make([]*flowpb.ServiceUpsertNotificationAddr, 0, len(n.Backends))
	for _, be := range n.Backends {
		var ipStr string
		if be.IP != nil {
			ipStr = be.IP.String()
		}
		beAddrs = append(beAddrs, &flowpb.ServiceUpsertNotificationAddr{
			Ip:   ipStr,
			Port: uint32(be.Port),
		})
	}
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_ServiceUpsert{
			ServiceUpsert: &flowpb.ServiceUpsertNotification{
				Id:               n.ID,
				FrontendAddress:  feAddr,
				BackendAddresses: beAddrs,
				Type:             n.Type,
				TrafficPolicy:    n.ExtTrafficPolicy,
				ExtTrafficPolicy: n.ExtTrafficPolicy,
				IntTrafficPolicy: n.IntTrafficPolicy,
				Name:             n.Name,
				Namespace:        n.Namespace,
			},
		},
	}
}

func notifyServiceDeletedToProto(typ flowpb.AgentEventType, n monitorAPI.ServiceDeleteNotification) *flowpb.AgentEvent {
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_ServiceDelete{
			ServiceDelete: &flowpb.ServiceDeleteNotification{
				Id: n.ID,
			},
		},
	}
}

func notifyUnknownToProto(typ flowpb.AgentEventType, msg monitorAPI.AgentNotifyMessage) *flowpb.AgentEvent {
	n, _ := json.Marshal(msg.Notification)
	return &flowpb.AgentEvent{
		Type: typ,
		Notification: &flowpb.AgentEvent_Unknown{
			Unknown: &flowpb.AgentEventUnknown{
				Type:         fmt.Sprintf("%d", msg.Type),
				Notification: string(n),
			},
		},
	}
}

func NotifyMessageToProto(msg monitorAPI.AgentNotifyMessage) *flowpb.AgentEvent {
	switch n := msg.Notification.(type) {
	case monitorAPI.TimeNotification:
		if msg.Type == monitorAPI.AgentNotifyStart {
			return notifyTimeNotificationToProto(flowpb.AgentEventType_AGENT_STARTED, n)
		}
	case monitorAPI.PolicyUpdateNotification:
		if msg.Type == monitorAPI.AgentNotifyPolicyUpdated {
			return notifyPolicyNotificationToProto(flowpb.AgentEventType_POLICY_UPDATED, n)
		} else if msg.Type == monitorAPI.AgentNotifyPolicyDeleted {
			return notifyPolicyNotificationToProto(flowpb.AgentEventType_POLICY_DELETED, n)
		}
	case monitorAPI.EndpointRegenNotification:
		if msg.Type == monitorAPI.AgentNotifyEndpointRegenerateSuccess {
			return notifyEndpointRegenNotificationToProto(flowpb.AgentEventType_ENDPOINT_REGENERATE_SUCCESS, n)
		} else if msg.Type == monitorAPI.AgentNotifyEndpointRegenerateFail {
			return notifyEndpointRegenNotificationToProto(flowpb.AgentEventType_ENDPOINT_REGENERATE_FAILURE, n)
		}
	case monitorAPI.EndpointNotification:
		if msg.Type == monitorAPI.AgentNotifyEndpointCreated {
			return notifyEndpointUpdateNotificationToProto(flowpb.AgentEventType_ENDPOINT_CREATED, n)
		} else if msg.Type == monitorAPI.AgentNotifyEndpointDeleted {
			return notifyEndpointUpdateNotificationToProto(flowpb.AgentEventType_ENDPOINT_DELETED, n)
		}
	case monitorAPI.IPCacheNotification:
		if msg.Type == monitorAPI.AgentNotifyIPCacheUpserted {
			return notifyIPCacheNotificationToProto(flowpb.AgentEventType_IPCACHE_UPSERTED, n)
		} else if msg.Type == monitorAPI.AgentNotifyIPCacheDeleted {
			return notifyIPCacheNotificationToProto(flowpb.AgentEventType_IPCACHE_DELETED, n)
		}
	case monitorAPI.ServiceUpsertNotification:
		if msg.Type == monitorAPI.AgentNotifyServiceUpserted {
			return notifyServiceUpsertedToProto(flowpb.AgentEventType_SERVICE_UPSERTED, n)
		}
	case monitorAPI.ServiceDeleteNotification:
		if msg.Type == monitorAPI.AgentNotifyServiceDeleted {
			return notifyServiceDeletedToProto(flowpb.AgentEventType_SERVICE_DELETED, n)
		}
	}
	return notifyUnknownToProto(flowpb.AgentEventType_AGENT_EVENT_UNKNOWN, msg)
}
