// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package correlation

import (
	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"
)

var logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-flow-policy-correlation")

// CorrelatePolicy updates the IngressAllowedBy/EgressAllowedBy fields on the
// provided flow.
func CorrelatePolicy(endpointGetter getters.EndpointGetter, f *flowpb.Flow) {
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
		logger.WithField(logfields.EndpointID, endpointID).Debug("failed to extract flow key")
		return
	}

	// obtain reference to endpoint on which the policy verdict was taken
	epInfo, ok := endpointGetter.GetEndpointInfoByID(endpointID)
	if !ok {
		logger.WithField(logfields.EndpointID, endpointID).Debug("failed to lookup endpoint")
		return
	}

	derivedFrom, rev, ok := lookupPolicyForKey(epInfo,
		policy.KeyForDirection(direction).WithIdentity(remoteIdentity).WithPortProto(proto, dport),
		f.GetPolicyMatchType())
	if !ok {
		logger.WithFields(logrus.Fields{
			logfields.Identity:         remoteIdentity,
			logfields.Port:             dport,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
		}).Debug("unable to find policy for policy verdict notification")
		return
	}

	rules := toProto(derivedFrom, rev)
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

func lookupPolicyForKey(ep getters.EndpointInfo, key policy.Key, matchType uint32) (derivedFrom labels.LabelArrayList, rev uint64, ok bool) {
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
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(key)
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
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(
			policy.KeyForDirection(key.TrafficDirection()).WithPortProto(key.Nexthdr, key.DestPort))
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
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(
			policy.KeyForDirection(key.TrafficDirection()).WithProto(key.Nexthdr))
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
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(
			policy.KeyForDirection(key.TrafficDirection()).WithIdentity(key.Identity))
	case monitorAPI.PolicyMatchAll:
		// Check for allow-all policy rules.
		//
		// Consider the network policy:
		//
		// spec:
		//  podSelector: {}
		//  ingress:
		//  - {}
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(
			policy.KeyForDirection(key.TrafficDirection()))
	}

	return derivedFrom, rev, ok
}

func toProto(derivedFrom labels.LabelArrayList, rev uint64) (policies []*flowpb.Policy) {
	for i, lbl := range derivedFrom {
		// derivedFrom may contain a duplicate policies if the policy had
		// multiple that contributed to the same policy map entry.
		// We can easily detect the duplicates here, because derivedFrom is
		// sorted.
		if i > 0 && lbl.Equals(derivedFrom[i-1]) {
			continue
		}

		policy := &flowpb.Policy{
			Labels:   lbl.GetModel(),
			Revision: rev,
		}
		populate(policy, lbl)
		policies = append(policies, policy)
	}

	return policies
}

// populate derives and sets fields in the flow policy from the label set array.
//
// This function supports namespaced and cluster-scoped resources.
func populate(f *flowpb.Policy, lbl labels.LabelArray) {
	var kind, ns, name string
	for _, l := range lbl {
		if l.Source != string(source.Kubernetes) {
			continue
		}
		switch l.Key {
		case k8sConst.PolicyLabelName:
			name = l.Value
		case k8sConst.PolicyLabelNamespace:
			ns = l.Value
		case k8sConst.PolicyLabelDerivedFrom:
			kind = l.Value
		}

		if kind != "" && name != "" && ns != "" {
			break
		}
	}

	f.Kind = kind
	f.Namespace = ns
	f.Name = name
}
