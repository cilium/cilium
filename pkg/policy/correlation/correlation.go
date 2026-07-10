// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package correlation

import (
	"log/slog"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
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
	// FORWARDED or REDIRECTED), denied by policy (i.e. DROPPED with a policy deny reason),
	// or audited (i.e. AUDIT, which represents traffic allowed due to audit mode that would
	// have been denied otherwise).
	verdict := f.GetVerdict()
	allowed := verdict == flowpb.Verdict_FORWARDED || verdict == flowpb.Verdict_REDIRECTED
	dropReason := f.GetDropReasonDesc()
	denied := verdict == flowpb.Verdict_DROPPED &&
		(dropReason == flowpb.DropReason_POLICY_DENY || dropReason == flowpb.DropReason_POLICY_DENIED)
	audited := verdict == flowpb.Verdict_AUDIT
	if !(allowed || denied || audited) {
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

	info, ok := epInfo.GetPolicyCorrelationInfoForKey(
		policy.KeyForDirection(direction).WithIdentity(remoteIdentity).WithPortProto(proto, dport),
	)
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
	case direction == trafficdirection.Egress && (denied || audited):
		f.EgressDeniedBy = rules
	case direction == trafficdirection.Ingress && allowed:
		f.IngressAllowedBy = rules
	case direction == trafficdirection.Ingress && (denied || audited):
		f.IngressDeniedBy = rules
	}
	// policy log is independent of verdict
	f.PolicyLog = info.Log
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
	} else if vrrp := f.GetL4().GetVRRP(); vrrp != nil {
		proto = u8proto.VRRP
		dport = 0
	} else if igmp := f.GetL4().GetIGMP(); igmp != nil {
		proto = u8proto.IGMP
		dport = 0
	} else {
		proto = u8proto.ANY
		dport = 0
	}

	return
}

func toProto(info policyTypes.PolicyCorrelationInfo) (policies []*flowpb.Policy) {
	for model := range labels.ModelsFromLabelArrayListString(info.RuleLabels) {
		policies = append(policies, utils.GetPolicyFromLabels(model, info.Revision))
	}
	return policies
}
