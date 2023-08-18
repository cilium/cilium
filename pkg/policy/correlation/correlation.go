// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package correlation

import (
	"net/netip"

	"github.com/sirupsen/logrus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
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
	if f.GetEventType().GetType() != int32(monitorAPI.MessageTypePolicyVerdict) ||
		f.GetVerdict() != flowpb.Verdict_FORWARDED {
		// we are only interested in policy verdict notifications for forwarded flows
		return
	}

	// extract fields relevant for looking up the policy
	direction, endpointIP, remoteIdentity, proto, dport := extractFlowKey(f)
	if dport == 0 || proto == 0 {
		logger.WithField(logfields.IPAddr, endpointIP).Debug("failed to extract flow key")
		return
	}

	// obtain reference to endpoint on which the policy verdict was taken
	epInfo, ok := endpointGetter.GetEndpointInfo(endpointIP)
	if !ok {
		logger.WithField(logfields.IPAddr, endpointIP).Debug("failed to lookup endpoint")
		return
	}

	derivedFrom, rev, ok := lookupPolicyForKey(epInfo, policy.Key{
		Identity:         uint32(remoteIdentity),
		DestPort:         dport,
		Nexthdr:          uint8(proto),
		TrafficDirection: uint8(direction),
	})
	if !ok {
		logger.WithFields(logrus.Fields{
			logfields.Identity:         remoteIdentity,
			logfields.Port:             dport,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
		}).Debug("unable to find policy for policy verdict notification")
		return
	}

	allowedBy := toProto(derivedFrom, rev)
	switch direction {
	case trafficdirection.Egress:
		f.EgressAllowedBy = allowedBy
	case trafficdirection.Ingress:
		f.IngressAllowedBy = allowedBy
	}
}

func extractFlowKey(f *flowpb.Flow) (
	direction trafficdirection.TrafficDirection,
	endpointIP netip.Addr,
	remoteIdentity identity.NumericIdentity,
	proto u8proto.U8proto,
	dport uint16) {

	switch f.GetTrafficDirection() {
	case flowpb.TrafficDirection_EGRESS:
		direction = trafficdirection.Egress
		endpointIP, _ = netip.ParseAddr(f.GetIP().GetSource())
		remoteIdentity = identity.NumericIdentity(f.GetDestination().GetIdentity())
	case flowpb.TrafficDirection_INGRESS:
		direction = trafficdirection.Ingress
		endpointIP, _ = netip.ParseAddr(f.GetIP().GetDestination())
		remoteIdentity = identity.NumericIdentity(f.GetSource().GetIdentity())
	default:
		direction = trafficdirection.Invalid
		endpointIP = netip.IPv4Unspecified()
		remoteIdentity = identity.IdentityUnknown
	}

	if tcp := f.GetL4().GetTCP(); tcp != nil {
		proto = u8proto.TCP
		dport = uint16(tcp.GetDestinationPort())
	} else if udp := f.GetL4().GetUDP(); udp != nil {
		proto = u8proto.UDP
		dport = uint16(udp.GetDestinationPort())
	} else {
		proto = u8proto.ANY
		dport = 0
	}

	return
}

func lookupPolicyForKey(ep v1.EndpointInfo, key policy.Key) (derivedFrom labels.LabelArrayList, rev uint64, ok bool) {
	// Check for L4 policy rules
	derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(key)

	// TODO: We should inspect f.GetPolicyMatchType() to reduce the number of lookups here
	if !ok {
		// Check for L3 policy rules
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
			Identity:         key.Identity,
			DestPort:         0,
			Nexthdr:          0,
			TrafficDirection: key.TrafficDirection,
		})
	}

	if !ok {
		// Check for allow-all policy rules
		derivedFrom, rev, ok = ep.GetRealizedPolicyRuleLabelsForKey(policy.Key{
			Identity:         0,
			DestPort:         0,
			Nexthdr:          0,
			TrafficDirection: key.TrafficDirection,
		})
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

		var ns, name string
		for _, l := range lbl {
			if l.Source == string(source.Kubernetes) {
				switch l.Key {
				case k8sConst.PolicyLabelName:
					name = l.Value
				case k8sConst.PolicyLabelNamespace:
					ns = l.Value
				}
			}

			if name != "" && ns != "" {
				policy.Name = name
				policy.Namespace = ns
				break
			}
		}

		policies = append(policies, policy)
	}

	return policies
}
