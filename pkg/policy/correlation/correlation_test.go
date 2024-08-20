// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package correlation

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestCorrelatePolicy(t *testing.T) {
	localIP := "1.2.3.4"
	localIdentity := uint32(1234)
	localID := uint32(12)
	remoteIP := "5.6.7.8"
	remoteIdentity := uint32(5678)
	remoteID := uint32(56)
	dstPort := uint32(443)

	flow := &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL3L4,
	}

	policyLabel := utils.GetPolicyLabels("foo-namespace", "web-policy", "1234-5678", utils.ResourceTypeCiliumNetworkPolicy)
	policyKey := policy.EgressKey().WithIdentity(identity.NumericIdentity(remoteIdentity)).WithTCPPort(uint16(dstPort))
	ep := &testutils.FakeEndpointInfo{
		ID:           uint64(localID),
		Identity:     identity.NumericIdentity(localIdentity),
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayList{
			policyKey: {policyLabel},
		},
		PolicyRevision: 1,
	}

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfoByID: func(id uint16) (endpoint getters.EndpointInfo, ok bool) {
			if uint64(id) == ep.ID {
				return ep, true
			}
			t.Fatalf("did not expect endpoint retrieval for non-local endpoint: %d", id)
			return nil, false
		},
	}

	CorrelatePolicy(endpointGetter, flow)

	expected := []*flowpb.Policy{
		{
			Name:      "web-policy",
			Namespace: "foo-namespace",
			Kind:      utils.ResourceTypeCiliumNetworkPolicy,
			Labels: []string{
				"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
				"k8s:io.cilium.k8s.policy.name=web-policy",
				"k8s:io.cilium.k8s.policy.namespace=foo-namespace",
				"k8s:io.cilium.k8s.policy.uid=1234-5678",
			},
			Revision: 1,
		},
	}

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check same flow at egress with deny
	flow = &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_DROPPED,
		DropReasonDesc:   flowpb.DropReason_POLICY_DENY,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL3L4,
	}
	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressAllowedBy)
	require.Nil(t, flow.IngressAllowedBy)
	require.Nil(t, flow.IngressDeniedBy)
	if diff := cmp.Diff(expected, flow.EgressDeniedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check port+proto rule.
	flow = &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL4Only,
	}

	policyKey = policy.EgressKey().WithTCPPort(uint16(dstPort))
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(localID),
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayList{
			policyKey: {policyLabel},
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check port-only rule.
	policyKey = policy.EgressKey().WithPort(uint16(dstPort))
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(localID),
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayList{
			policyKey: {policyLabel},
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check protocol-only rule.
	flow = &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchProtoOnly,
	}

	policyKey = policy.EgressKey().WithProto(u8proto.TCP)
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(localID),
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayList{
			policyKey: {policyLabel},
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check allow-all rule.
	flow = &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchAll,
	}

	policyKey = policy.EgressKey()
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(localID),
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayList{
			policyKey: {policyLabel},
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check same flow at ingress
	flow = &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_INGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL3Only,
	}

	policyKey = policy.IngressKey().WithIdentity(identity.NumericIdentity(localIdentity))
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(remoteID),
		Identity:     identity.NumericIdentity(remoteIdentity),
		IPv4:         net.ParseIP(remoteIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayList{
			policyKey: {policyLabel},
		},
		PolicyRevision: 1,
	}
	endpointGetter = &testutils.FakeEndpointGetter{
		OnGetEndpointInfoByID: func(id uint16) (endpoint getters.EndpointInfo, ok bool) {
			if uint64(id) == ep.ID {
				return ep, true
			}
			t.Fatalf("did not expect endpoint retrieval for non-remote endpoint: %d", id)
			return nil, false
		},
	}
	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.EgressAllowedBy)
	if diff := cmp.Diff(expected, flow.IngressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check same flow at ingress with deny
	flow = &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_DROPPED,
		DropReasonDesc:   flowpb.DropReason_POLICY_DENY,
		TrafficDirection: flowpb.TrafficDirection_INGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL3Only,
	}
	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressAllowedBy)
	require.Nil(t, flow.IngressAllowedBy)
	require.Nil(t, flow.EgressDeniedBy)
	if diff := cmp.Diff(expected, flow.IngressDeniedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// match ccnp
	flow = &flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      localIP,
			Destination: remoteIP,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: dstPort,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       localID,
			Identity: localIdentity,
		},
		Destination: &flowpb.Endpoint{
			ID:       remoteID,
			Identity: remoteIdentity,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL3L4,
	}

	policyLabel = utils.GetPolicyLabels("", "ccnp", "1234-5678", utils.ResourceTypeCiliumClusterwideNetworkPolicy)
	policyKey = policy.EgressKey().WithIdentity(identity.NumericIdentity(remoteIdentity)).WithTCPPort(uint16(dstPort))
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(localID),
		Identity:     identity.NumericIdentity(localIdentity),
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayList{
			policyKey: {policyLabel},
		},
		PolicyRevision: 1,
	}

	endpointGetter = &testutils.FakeEndpointGetter{
		OnGetEndpointInfoByID: func(id uint16) (endpoint getters.EndpointInfo, ok bool) {
			if uint64(id) == ep.ID {
				return ep, true
			}
			t.Fatalf("did not expect endpoint retrieval for non-local endpoint: %d", id)
			return nil, false
		},
	}

	CorrelatePolicy(endpointGetter, flow)

	expected = []*flowpb.Policy{
		{
			Name: "ccnp",
			Kind: utils.ResourceTypeCiliumClusterwideNetworkPolicy,
			Labels: []string{
				"k8s:io.cilium.k8s.policy.derived-from=CiliumClusterwideNetworkPolicy",
				"k8s:io.cilium.k8s.policy.name=ccnp",
				"k8s:io.cilium.k8s.policy.uid=1234-5678",
			},
			Revision: 1,
		},
	}

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}
}
