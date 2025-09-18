// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dropeventemitter

import (
	"context"
	"log/slog"
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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type dropEventEmitter struct {
	broadcaster record.EventBroadcaster
	recorder    record.EventRecorder
	k8sWatcher  watchers.CacheAccessK8SWatcher

	reasons []flowpb.DropReason
}

func new(log *slog.Logger, interval time.Duration, reasons []string, k8s client.Clientset, watcher watchers.CacheAccessK8SWatcher) *dropEventEmitter {
	broadcaster := record.NewBroadcasterWithCorrelatorOptions(record.CorrelatorOptions{
		BurstSize:            1,
		QPS:                  1 / float32(interval.Seconds()),
		MaxEvents:            1,
		MaxIntervalInSeconds: int(interval.Seconds()),
		MessageFunc:          func(event *v1.Event) string { return event.Message },
	})
	broadcaster.StartRecordingToSink(&typedv1.EventSinkImpl{Interface: k8s.CoreV1().Events("")})

	rs := make([]flowpb.DropReason, 0, len(reasons))
	for _, reason := range reasons {
		if v, ok := flowpb.DropReason_value[strings.ToUpper(reason)]; ok {
			rs = append(rs, flowpb.DropReason(v))
		} else {
			log.Warn("Ignoring invalid drop reason", logfields.Reason, reason)
		}
	}

	return &dropEventEmitter{
		broadcaster: broadcaster,
		recorder:    broadcaster.NewRecorder(slimscheme.Scheme, v1.EventSource{Component: "cilium"}),
		k8sWatcher:  watcher,
		reasons:     rs,
	}
}

func (e *dropEventEmitter) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Only handle packet drops due to policy related to a Pod
	if flow.Verdict != flowpb.Verdict_DROPPED ||
		!slices.Contains(e.reasons, flow.GetDropReasonDesc()) ||
		(flow.TrafficDirection == flowpb.TrafficDirection_INGRESS && flow.Destination.PodName == "") ||
		(flow.TrafficDirection == flowpb.TrafficDirection_EGRESS && flow.Source.PodName == "") {
		return nil
	}

	reason := strings.ToLower(flow.DropReasonDesc.String())
	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		message := "Incoming packet dropped (" + reason + ") from " +
			endpointToString(flow.IP.Source, flow.Source) + " " +
			l4protocolToString(flow.L4)
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
			endpointToString(flow.IP.Destination, flow.Destination) + " " +
			l4protocolToString(flow.L4)

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

func (e *dropEventEmitter) Shutdown() {
	e.broadcaster.Shutdown()
}

func endpointToString(ip string, endpoint *flowpb.Endpoint) string {
	if endpoint.PodName != "" {
		return endpoint.Namespace + "/" + endpoint.PodName + " (" + ip + ")"
	}
	if identity.NumericIdentity(endpoint.Identity).IsReservedIdentity() {
		return identity.NumericIdentity(endpoint.Identity).String() + " (" + ip + ")"
	}
	return ip
}

func l4protocolToString(l4 *flowpb.Layer4) string {
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
