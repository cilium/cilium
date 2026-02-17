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
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/hubble/ir"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	client "github.com/cilium/cilium/pkg/k8s/client"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metaslimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimscheme "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type endpointsLookup interface {
	LookupCiliumID(id uint16) *endpoint.Endpoint
}

type endpointInterface interface {
	GetRealizedL4PolicyRuleOriginModel() (policy *models.L4Policy, policyRevision uint64, err error)
}

type dropEventEmitter struct {
	broadcaster     record.EventBroadcaster
	recorder        record.EventRecorder
	k8sWatcher      watchers.CacheAccessK8SWatcher
	showPolicies    bool
	rateLimiter     *rate.Limiter
	reasons         []flowpb.DropReason
	endpointsLookup endpointsLookup
}

func new(log *slog.Logger, interval time.Duration, reasons []string, showPolicies bool, rateLimit int64, k8s client.Clientset, watcher watchers.CacheAccessK8SWatcher, endpointsLookup endpointsLookup) *dropEventEmitter {
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
	var rateLimiter *rate.Limiter
	if rateLimit > 0 {
		rateLimiter = rate.NewLimiter(time.Second, rateLimit)
	}
	return &dropEventEmitter{
		broadcaster:     broadcaster,
		recorder:        broadcaster.NewRecorder(slimscheme.Scheme, v1.EventSource{Component: "cilium"}),
		k8sWatcher:      watcher,
		reasons:         rs,
		showPolicies:    showPolicies,
		endpointsLookup: endpointsLookup,
		rateLimiter:     rateLimiter,
	}
}

func (e *dropEventEmitter) ProcessFlow(ctx context.Context, flow *ir.Flow) error {
	if e.rateLimiter != nil && !e.rateLimiter.Allow() {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Only handle packet drops due to policy related to a Pod
	if flow.Verdict != flowpb.Verdict_DROPPED ||
		!slices.Contains(e.reasons, flow.DropReasonDesc) ||
		(flow.TrafficDirection == flowpb.TrafficDirection_INGRESS && flow.Destination.PodName == "") ||
		(flow.TrafficDirection == flowpb.TrafficDirection_EGRESS && flow.Source.PodName == "") {
		return nil
	}

	reason := strings.ToLower(flow.DropReasonDesc.String())

	typeMeta := metaslimv1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}

	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		message := "Incoming packet dropped (" + reason + ") from " +
			endpointToString(flow.IP.Source.String(), flow.Source) + " " +
			l4protocolToString(flow.L4) + "."

		if e.showPolicies {
			policies, err := e.dropEventPoliciesToString(flow)
			if err != nil {
				return err
			}
			if policies != "" {
				message += " " + policies
			}
		}

		e.recorder.Event(&slimv1.Pod{
			TypeMeta: typeMeta,
			ObjectMeta: metaslimv1.ObjectMeta{
				Name:      flow.Destination.PodName,
				Namespace: flow.Destination.Namespace,
			},
		}, v1.EventTypeWarning, "PacketDrop", message)
	} else {
		message := "Outgoing packet dropped (" + reason + ") to " +
			endpointToString(flow.IP.Destination.String(), flow.Destination) + " " +
			l4protocolToString(flow.L4) + "."

		if e.showPolicies {
			policies, err := e.dropEventPoliciesToString(flow)
			if err != nil {
				return err
			}
			if policies != "" {
				message += " " + policies
			}
		}

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
			TypeMeta:   typeMeta,
			ObjectMeta: objMeta,
		}
		e.recorder.Event(&podObj, v1.EventTypeWarning, "PacketDrop", message)
	}

	return nil
}

func (e *dropEventEmitter) Shutdown() {
	e.broadcaster.Shutdown()
}

func endpointToString(ip string, endpoint ir.Endpoint) string {
	if endpoint.PodName != "" {
		return endpoint.Namespace + "/" + endpoint.PodName + " (" + ip + ")"
	}
	if identity.NumericIdentity(endpoint.Identity).IsReservedIdentity() {
		return identity.NumericIdentity(endpoint.Identity).String() + " (" + ip + ")"
	}
	return ip
}

func l4protocolToString(l4 ir.Layer4) string {
	switch {
	case !l4.TCP.IsEmpty():
		return "TCP/" + strconv.Itoa(int(l4.TCP.DestinationPort))
	case !l4.UDP.IsEmpty():
		return "UDP/" + strconv.Itoa(int(l4.UDP.DestinationPort))
	case !l4.ICMPv4.IsEmpty():
		return "ICMPv4"
	case !l4.ICMPv6.IsEmpty():
		return "ICMPv6"
	case !l4.SCTP.IsEmpty():
		return "SCTP"
	case !l4.IGMP.IsEmpty():
		return "IGMP"
	case !l4.VRRP.IsEmpty():
		return "VRRP"
	}

	return ""
}

func (e *dropEventEmitter) getLocalEndpoint(flow *ir.Flow) *endpoint.Endpoint {
	var endpointID uint16
	if flow.TrafficDirection == flowpb.TrafficDirection_INGRESS {
		endpointID = uint16(flow.Destination.ID)
	} else {
		endpointID = uint16(flow.Source.ID)
	}
	return e.endpointsLookup.LookupCiliumID(endpointID)
}

func getPolicyRulesFromEndpoint(direction flowpb.TrafficDirection, ep endpointInterface) ([]*models.PolicyRule, uint64, error) {
	if ep == nil {
		return nil, 0, nil
	}
	realizedPolicy, policyRevision, err := ep.GetRealizedL4PolicyRuleOriginModel()
	if err != nil || realizedPolicy == nil {
		return nil, 0, err
	}
	if direction == flowpb.TrafficDirection_INGRESS {
		return realizedPolicy.Ingress, policyRevision, nil
	}
	return realizedPolicy.Egress, policyRevision, nil
}

func parsePolicyRules(l4Rules []*models.PolicyRule, policyRevision uint64) (networkPolicies set.Set[string], clusterwideNetworkPolicies set.Set[string]) {
	for _, rules := range l4Rules {
		if rules == nil {
			continue
		}
		for _, policyLabels := range rules.DerivedFromRules {
			policy := utils.GetPolicyFromLabels(policyLabels, policyRevision)
			if policy == nil {
				continue
			}
			if policy.Namespace == "" {
				clusterwideNetworkPolicies.Insert(policy.Kind + "/" + policy.Name)
				continue
			}
			networkPolicies.Insert(policy.Kind + "/" + policy.Name)
		}
	}
	return
}

func parsePolicyCorrelation(direction flowpb.TrafficDirection, ingressDeniedBy []ir.Policy, egressDeniedBy []ir.Policy) (networkPolicies set.Set[string], clusterwideNetworkPolicies set.Set[string]) {
	var policies []ir.Policy
	if direction == flowpb.TrafficDirection_INGRESS {
		policies = ingressDeniedBy
	} else {
		policies = egressDeniedBy
	}
	for _, policy := range policies {
		if policy.Namespace == "" {
			clusterwideNetworkPolicies.Insert(policy.Kind + "/" + policy.Name)
			continue
		}
		networkPolicies.Insert(policy.Kind + "/" + policy.Name)
	}
	return
}

func (e *dropEventEmitter) dropEventPoliciesToString(flow *ir.Flow) (string, error) {
	var parts []string
	prefix := "Denied by"
	var networkPolicies, clusterwideNetworkPolicies set.Set[string]
	// If the drop event is caused by a deny policy, policy correlation will identify the denying policy.
	if flow.DropReasonDesc == flowpb.DropReason_POLICY_DENY {
		networkPolicies, clusterwideNetworkPolicies = parsePolicyCorrelation(flow.TrafficDirection, flow.IngressDeniedBy, flow.EgressDeniedBy)
	}
	// If the drop event is not caused by a direct deny policy or policy correlation is turned off,
	// show all applied network policies.
	if networkPolicies.Empty() && clusterwideNetworkPolicies.Empty() {
		prefix = "Applied"
		flowPolicyRules, policyRevision, err := getPolicyRulesFromEndpoint(flow.TrafficDirection, e.getLocalEndpoint(flow))
		if err != nil {
			return "", err
		}
		networkPolicies, clusterwideNetworkPolicies = parsePolicyRules(flowPolicyRules, policyRevision)
	}
	if !networkPolicies.Empty() {
		parts = append(parts, prefix+" policies: "+networkPolicies.String()+".")
	}
	if !clusterwideNetworkPolicies.Empty() {
		parts = append(parts, prefix+" clusterwide policies: "+clusterwideNetworkPolicies.String()+".")
	}
	return strings.Join(parts, " "), nil
}
