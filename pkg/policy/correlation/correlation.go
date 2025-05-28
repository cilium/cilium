// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package correlation

import (
	"log/slog"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"
)

// CorrelatePolicy updates the IngressAllowedBy/EgressAllowedBy fields on the
// provided flow.
func CorrelatePolicy(logger *slog.Logger, endpointGetter getters.EndpointGetter, f *flowpb.Flow) {
	if f.GetEventType().GetType() != int32(monitorAPI.MessageTypePolicyVerdict) {
		// If it's not a policy verdict, we don't care.
		return
	}

	// We are only interested in flows which are either allowed (i.e. the verdict is either
	// FORWARDED or REDIRECTED) or explicitly denied (i.e. DROPPED, and matched by a deny policy),
	// since we cannot usefully annotate the verdict otherwise. (Put differently, which policy
	// should be listed in {in|e}gress_denied_by for an unmatched flow?)
	verdict := f.GetVerdict()
	allowed := verdict == flowpb.Verdict_FORWARDED || verdict == flowpb.Verdict_REDIRECTED
	denied := verdict == flowpb.Verdict_DROPPED && f.GetDropReasonDesc() == flowpb.DropReason_POLICY_DENY
	if !(allowed || denied) {
		return
	}

	// extract fields relevant for looking up the policy
	direction, endpointID, remoteIdentity, proto, dport := extractFlowKey(f)
	if dport == 0 || proto == 0 {
		logger.Debug(
			"failed to extract flow key",
			logfields.EndpointID, endpointID,
		)
		return
	}

	// obtain reference to endpoint on which the policy verdict was taken
	epInfo, ok := endpointGetter.GetEndpointInfoByID(endpointID)
	if !ok {
		logger.Debug(
			"failed to lookup endpoint",
			logfields.EndpointID, endpointID,
		)
		return
	}

	info, ok := lookupPolicyForKey(epInfo,
		policy.KeyForDirection(direction).WithIdentity(remoteIdentity).WithPortProto(proto, dport),
		f.GetPolicyMatchType())
	if !ok {
		logger.Debug(
			"unable to find policy for policy verdict notification",
			logfields.Identity, remoteIdentity,
			logfields.Port, dport,
			logfields.Protocol, proto,
			logfields.TrafficDirection, direction,
		)
		return
	}

	rules := toProto(info)
	switch {
	case direction == trafficdirection.Egress && allowed:
		f.EgressAllowedBy = rules
	case direction == trafficdirection.Egress && denied:
		f.EgressDeniedBy = rules
	case direction == trafficdirection.Ingress && allowed:
		f.IngressAllowedBy = rules
	case direction == trafficdirection.Ingress && denied:
		f.IngressDeniedBy = rules
	}
}

func extractFlowKey(f *flowpb.Flow) (
	direction trafficdirection.TrafficDirection,
	endpointID uint16,
	remoteIdentity identity.NumericIdentity,
	proto u8proto.U8proto,
	dport uint16) {

	switch f.GetTrafficDirection() {
	case flowpb.TrafficDirection_EGRESS:
		direction = trafficdirection.Egress
		// We only get a uint32 because proto has no 16-bit types.
		endpointID = uint16(f.GetSource().GetID())
		remoteIdentity = identity.NumericIdentity(f.GetDestination().GetIdentity())
	case flowpb.TrafficDirection_INGRESS:
		direction = trafficdirection.Ingress
		endpointID = uint16(f.GetDestination().GetID())
		remoteIdentity = identity.NumericIdentity(f.GetSource().GetIdentity())
	default:
		direction = trafficdirection.Invalid
		endpointID = 0
		remoteIdentity = identity.IdentityUnknown
	}

	if tcp := f.GetL4().GetTCP(); tcp != nil {
		proto = u8proto.TCP
		dport = uint16(tcp.GetDestinationPort())
	} else if udp := f.GetL4().GetUDP(); udp != nil {
		proto = u8proto.UDP
		dport = uint16(udp.GetDestinationPort())
	} else if icmpv4 := f.GetL4().GetICMPv4(); icmpv4 != nil {
		proto = u8proto.ICMP
		dport = uint16(icmpv4.Type)
	} else if icmpv6 := f.GetL4().GetICMPv6(); icmpv6 != nil {
		proto = u8proto.ICMPv6
		dport = uint16(icmpv6.Type)
	} else if sctp := f.GetL4().GetSCTP(); sctp != nil {
		proto = u8proto.SCTP
		dport = uint16(sctp.GetDestinationPort())
	} else {
		proto = u8proto.ANY
		dport = 0
	}

	return
}

func lookupPolicyForKey(ep getters.EndpointInfo, key policy.Key, matchType uint32) (policyTypes.PolicyCorrelationInfo, bool) {
	switch matchType {
	case monitorAPI.PolicyMatchL3L4:
		// Check for L4 policy rules.
		//
		// Consider the network policy:
		//
		// spec:
		//  podSelector: {}
		//  ingress:
		//  - podSelector:
		//      matchLabels:
		//        app: client
		//    ports:
		//    - port: 80
		//      protocol: TCP
	case monitorAPI.PolicyMatchL3Proto:
		// Check for L3 policy rules with protocol (but no port).
		//
		// Consider the network policy:
		//
		// spec:
		//  podSelector: {}
		//  ingress:
		//  - podSelector:
		//      matchLabels:
		//        app: client
		//    ports:
		//    - protocol: TCP
		key = policy.KeyForDirection(key.TrafficDirection()).WithIdentity(key.Identity).WithProto(key.Nexthdr)
	case monitorAPI.PolicyMatchL4Only:
		// Check for port-specific rules.
		// This covers the case where one or more identities are allowed by network policy.
		//
		// Consider the network policy:
		//
		// spec:
		//  podSelector: {}
		//  ingress:
		//  - ports:
		//    - port: 80
		//      protocol: TCP // protocol is optional for this match.
		key = policy.KeyForDirection(key.TrafficDirection()).WithPortProto(key.Nexthdr, key.DestPort)
	case monitorAPI.PolicyMatchProtoOnly:
		// Check for protocol-only policies.
		//
		// Consider the network policy:
		//
		// spec:
		//  podSelector: {}
		//  ingress:
		//  - ports:
		//    - protocol: TCP
		key = policy.KeyForDirection(key.TrafficDirection()).WithProto(key.Nexthdr)
	case monitorAPI.PolicyMatchL3Only:
		// Check for L3 policy rules.
		//
		// Consider the network policy:
		//
		// spec:
		//  podSelector: {}
		//  ingress:
		//  - podSelector:
		//      matchLabels:
		//        app: client
		key = policy.KeyForDirection(key.TrafficDirection()).WithIdentity(key.Identity)
	case monitorAPI.PolicyMatchAll:
		// Check for allow-all policy rules.
		//
		// Consider the network policy:
		//
		// spec:
		//  podSelector: {}
		//  ingress:
		//  - {}
		key = policy.KeyForDirection(key.TrafficDirection())
	}
	return ep.GetPolicyCorrelationInfoForKey(key)
}

func toProto(info policyTypes.PolicyCorrelationInfo) (policies []*flowpb.Policy) {
	for model := range labels.ModelsFromLabelArrayListString(info.RuleLabels) {
		policies = append(policies, policyFromModel(model, info))
	}
	return policies
}

// policyFromModel derives and sets fields in the flow policy from the label set array and policy
// correlation information.
//
// This function supports namespaced and cluster-scoped resources.
func policyFromModel(model []string, info policyTypes.PolicyCorrelationInfo) *flowpb.Policy {
	f := &flowpb.Policy{
		Labels:   model,
		Revision: info.Revision,
	}

	for _, str := range model {
		k8sLen := len(source.Kubernetes)
		if len(str) > k8sLen && str[k8sLen] == ':' {
			str = str[k8sLen+1:]
			if i := strings.IndexByte(str, '='); i > 0 {
				key := str[:i]
				value := str[i+1:]
				switch key {
				case k8sConst.PolicyLabelName:
					f.Name = value
				case k8sConst.PolicyLabelNamespace:
					f.Namespace = value
				case k8sConst.PolicyLabelDerivedFrom:
					f.Kind = value
				default:
					if f.Kind != "" && f.Name != "" && f.Namespace != "" {
						return f
					}
				}
			}
		}
	}

	return f
}
