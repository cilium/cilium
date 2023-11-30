// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dropeventemitter

import (
	"context"
	"strconv"

	v1 "k8s.io/api/core/v1"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metaslimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimscheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/scheme"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/time"
)

type DropEventEmitter struct {
	history     map[string]time.Time
	historySize int
	interval    time.Duration
	broadcaster record.EventBroadcaster
	recorder    record.EventRecorder
}

func NewDropEventEmitter(interval time.Duration, historySize int, k8s client.Clientset) *DropEventEmitter {
	emitter := DropEventEmitter{
		history:     map[string]time.Time{},
		historySize: historySize,
		interval:    interval,
		broadcaster: record.NewBroadcaster(),
	}
	emitter.broadcaster.StartRecordingToSink(&typedv1.EventSinkImpl{Interface: k8s.CoreV1().Events("")})
	emitter.recorder = emitter.broadcaster.NewRecorder(slimscheme.Scheme, v1.EventSource{Component: "cilium"})

	return &emitter
}

func (e *DropEventEmitter) expireHistory(now time.Time) {
	for combo, timestamp := range e.history {
		// Very simple rate limiter. Also remove future entries due to DST.
		if now.Add(-e.interval).After(timestamp) || now.Before(timestamp) {
			delete(e.history, combo)
		}
	}
}

func (e *DropEventEmitter) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	// Only handle packet drops due to policy related to a Pod
	if flow.Verdict != flowpb.Verdict_DROPPED ||
		flow.DropReasonDesc != flowpb.DropReason_POLICY_DENIED ||
		(flow.TrafficDirection == flowpb.TrafficDirection_INGRESS &&
			flow.Destination.PodName == "") ||
		(flow.TrafficDirection == flowpb.TrafficDirection_EGRESS &&
			flow.Source.PodName == "") {
		return nil
	}

	now := time.Now()
	e.expireHistory(now)
	// Event has already been emitted for this source/destination combination
	// in the last interval (defaults to two minutes).
	if _, exists := e.history[flow.IP.Source+"/"+flow.IP.Destination]; exists {
		return nil
	}

	// Stop handling drops when the history gets too large. This event emitter
	// is not important enough to take down the cilium agent.
	if len(e.history) > e.historySize {
		return nil
	}

	// Add src/dst combo to the rate limiter history
	e.history[flow.IP.Source+"/"+flow.IP.Destination] = now

	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		message := "Incoming packet dropped from" +
			" " + e.endpointToString(flow.IP.Source, flow.Source) +
			" " + e.l4protocolToString(flow.L4)
		e.recorder.Event(&slimv1.Pod{
			ObjectMeta: metaslimv1.ObjectMeta{
				Name:      flow.Destination.PodName,
				Namespace: flow.Destination.Namespace,
			},
		}, v1.EventTypeWarning, "PacketDrop", message)
	} else {
		message := "Outgoing packet dropped to" +
			" " + e.endpointToString(flow.IP.Destination, flow.Destination) +
			" " + e.l4protocolToString(flow.L4)
		e.recorder.Event(&slimv1.Pod{
			ObjectMeta: metaslimv1.ObjectMeta{
				Name:      flow.Source.PodName,
				Namespace: flow.Source.Namespace,
			},
		}, v1.EventTypeWarning, "PacketDrop", message)
	}

	return nil
}

func (e *DropEventEmitter) endpointToString(ip string, endpoint *flowpb.Endpoint) string {
	if endpoint.PodName != "" {
		return endpoint.Namespace + "/" + endpoint.PodName + " (" + ip + ")"
	} else if identity.NumericIdentity(endpoint.Identity).IsReservedIdentity() {
		return identity.NumericIdentity(endpoint.Identity).String() + "( " + ip + ")"
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
