// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dropeventemitter

import (
	"context"
	"slices"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	client "github.com/cilium/cilium/pkg/k8s/client"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metaslimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimscheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/time"
)

type DropEventEmitter struct {
	reasons    []string
	recorder   record.EventRecorder
	k8sWatcher watchers.CacheAccessK8SWatcher
}

func NewDropEventEmitter(interval time.Duration, reasons []string, k8s client.Clientset, watcher watchers.CacheAccessK8SWatcher) *DropEventEmitter {
	broadcaster := record.NewBroadcasterWithCorrelatorOptions(record.CorrelatorOptions{
		BurstSize:            1,
		QPS:                  1 / float32(interval.Seconds()),
		MaxEvents:            1,
		MaxIntervalInSeconds: int(interval.Seconds()),
		MessageFunc:          func(event *v1.Event) string { return event.Message },
	})
	broadcaster.StartRecordingToSink(&typedv1.EventSinkImpl{Interface: k8s.CoreV1().Events("")})

	return &DropEventEmitter{
		reasons:    reasons,
		recorder:   broadcaster.NewRecorder(slimscheme.Scheme, v1.EventSource{Component: "cilium"}),
		k8sWatcher: watcher,
	}
}

func (e *DropEventEmitter) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	reason := strings.ToLower(flow.DropReasonDesc.String())

	// Only handle packet drops due to policy related to a Pod
	if flow.Verdict != flowpb.Verdict_DROPPED ||
		!slices.Contains(e.reasons, reason) ||
		(flow.TrafficDirection == flowpb.TrafficDirection_INGRESS &&
			flow.Destination.PodName == "") ||
		(flow.TrafficDirection == flowpb.TrafficDirection_EGRESS &&
			flow.Source.PodName == "") {
		return nil
	}

	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		message := "Incoming packet dropped (" + reason + ") from " +
			e.endpointToString(flow.IP.Source, flow.Source) + " " +
			e.l4protocolToString(flow.L4)
		e.recorder.Event(&slimv1.Pod{
			TypeMeta: metaslimv1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metaslimv1.ObjectMeta{
				Name:      flow.Destination.PodName,
				Namespace: flow.Destination.Namespace,
			},
		}, v1.EventTypeWarning, "PacketDrop", message)
	} else {
		message := "Outgoing packet dropped (" + reason + ") to " +
			e.endpointToString(flow.IP.Destination, flow.Destination) + " " +
			e.l4protocolToString(flow.L4)

		objMeta := metaslimv1.ObjectMeta{
			Name:      flow.Source.PodName,
			Namespace: flow.Source.Namespace,
		}
		if e.k8sWatcher != nil {
			pod, err := e.k8sWatcher.GetCachedPod(flow.Source.Namespace, flow.Source.PodName)
			if err == nil {
				objMeta.UID = pod.UID
			}
		}
		podObj := slimv1.Pod{
			TypeMeta: metaslimv1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: objMeta,
		}
		e.recorder.Event(&podObj, v1.EventTypeWarning, "PacketDrop", message)
	}

	return nil
}

func (e *DropEventEmitter) endpointToString(ip string, endpoint *flowpb.Endpoint) string {
	if endpoint.PodName != "" {
		return endpoint.Namespace + "/" + endpoint.PodName + " (" + ip + ")"
	} else if identity.NumericIdentity(endpoint.Identity).IsReservedIdentity() {
		return identity.NumericIdentity(endpoint.Identity).String() + " (" + ip + ")"
	} else {
		return ip
	}
}

func (e *DropEventEmitter) l4protocolToString(l4 *flowpb.Layer4) string {
	switch l4.Protocol.(type) {
	case *flowpb.Layer4_TCP:
		return "TCP/" + strconv.Itoa(int(l4.GetTCP().DestinationPort))
	case *flowpb.Layer4_UDP:
		return "UDP/" + strconv.Itoa(int(l4.GetUDP().DestinationPort))
	case *flowpb.Layer4_ICMPv4:
		return "ICMPv4"
	case *flowpb.Layer4_ICMPv6:
		return "ICMPv6"
	case *flowpb.Layer4_SCTP:
		return "SCTP"
	}
	return ""
}
