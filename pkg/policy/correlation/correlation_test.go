// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package correlation

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cilium/cilium/api/v1/flow"
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/cookie"
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
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
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

	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

	require.Nil(t, flow.EgressDeniedBy)
	require.Nil(t, flow.IngressDeniedBy)
	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// check identity and protocol-only rule.
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
		PolicyMatchType: monitorAPI.PolicyMatchL3Proto,
	}

	policyKey = policy.EgressKey().WithIdentity(identity.NumericIdentity(remoteIdentity)).WithProto(u8proto.TCP)
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(localID),
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
		},
		PolicyRevision: 1,
	}

	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
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
	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
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

	CorrelatePolicy(hivetest.Logger(t), endpointGetter, flow)

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

func TestCorrelatePolicyFromCookie(t *testing.T) {
	uu := map[string]struct {
		flow   *flowpb.Flow
		cookie *cookie.BakedCookie
		ea, ed []*flow.Policy
		ia, id []*flow.Policy
	}{
		"empty": {
			flow:   &flowpb.Flow{},
			cookie: cookie.NewBakedCookie("", nil),
		},

		"egress": {
			flow: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					Type: monitorAPI.MessageTypePolicyVerdict,
				},
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				IP: &flowpb.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_TCP{
						TCP: &flowpb.TCP{
							DestinationPort: 8000,
						},
					},
				},
				Source: &flowpb.Endpoint{
					ID:       1000,
					Identity: 1000,
				},
				Destination: &flowpb.Endpoint{
					ID:       2000,
					Identity: 2000,
				},
				PolicyMatchType: monitorAPI.PolicyMatchL3L4,
			},
			cookie: cookie.NewBakedCookie(
				"["+
					"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy"+" "+
					"k8s:io.cilium.k8s.policy.name=p-1"+" "+
					"k8s:io.cilium.k8s.policy.namespace=ns-1"+" "+
					"k8s:io.cilium.k8s.policy.uid=1234-5678"+
					"]",
				[]string{"bozo!"},
			),
			ea: []*flow.Policy{
				{
					Name:      "p-1",
					Namespace: "ns-1",
					Kind:      utils.ResourceTypeCiliumNetworkPolicy,
					Labels: []string{
						"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
						"k8s:io.cilium.k8s.policy.name=p-1",
						"k8s:io.cilium.k8s.policy.namespace=ns-1",
						"k8s:io.cilium.k8s.policy.uid=1234-5678",
					},
				},
			},
		},

		"egress-deny": {
			flow: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					Type: monitorAPI.MessageTypePolicyVerdict,
				},
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENY,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				IP: &flowpb.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_TCP{
						TCP: &flowpb.TCP{
							DestinationPort: 8000,
						},
					},
				},
				Source: &flowpb.Endpoint{
					ID:       1000,
					Identity: 1000,
				},
				Destination: &flowpb.Endpoint{
					ID:       2000,
					Identity: 2000,
				},
				PolicyMatchType: monitorAPI.PolicyMatchL3L4,
			},
			cookie: cookie.NewBakedCookie(
				"["+
					"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy"+" "+
					"k8s:io.cilium.k8s.policy.name=p-1"+" "+
					"k8s:io.cilium.k8s.policy.namespace=ns-1"+" "+
					"k8s:io.cilium.k8s.policy.uid=1234-5678"+
					"]",
				[]string{"bozo!"},
			),
			ed: []*flow.Policy{
				{
					Name:      "p-1",
					Namespace: "ns-1",
					Kind:      utils.ResourceTypeCiliumNetworkPolicy,
					Labels: []string{
						"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
						"k8s:io.cilium.k8s.policy.name=p-1",
						"k8s:io.cilium.k8s.policy.namespace=ns-1",
						"k8s:io.cilium.k8s.policy.uid=1234-5678",
					},
				},
			},
		},

		"ingress": {
			flow: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					Type: monitorAPI.MessageTypePolicyVerdict,
				},
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP: &flowpb.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_TCP{
						TCP: &flowpb.TCP{
							DestinationPort: 8000,
						},
					},
				},
				Source: &flowpb.Endpoint{
					ID:       1000,
					Identity: 1000,
				},
				Destination: &flowpb.Endpoint{
					ID:       2000,
					Identity: 2000,
				},
				PolicyMatchType: monitorAPI.PolicyMatchL3L4,
			},
			cookie: cookie.NewBakedCookie(
				"["+
					"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy"+" "+
					"k8s:io.cilium.k8s.policy.name=p-1"+" "+
					"k8s:io.cilium.k8s.policy.namespace=ns-1"+" "+
					"k8s:io.cilium.k8s.policy.uid=1234-5678"+
					"]",
				[]string{"bozo!"},
			),
			ia: []*flow.Policy{
				{
					Name:      "p-1",
					Namespace: "ns-1",
					Kind:      utils.ResourceTypeCiliumNetworkPolicy,
					Labels: []string{
						"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
						"k8s:io.cilium.k8s.policy.name=p-1",
						"k8s:io.cilium.k8s.policy.namespace=ns-1",
						"k8s:io.cilium.k8s.policy.uid=1234-5678",
					},
				},
			},
		},

		"ingress-deny": {
			flow: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					Type: monitorAPI.MessageTypePolicyVerdict,
				},
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENY,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP: &flowpb.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_TCP{
						TCP: &flowpb.TCP{
							DestinationPort: 8000,
						},
					},
				},
				Source: &flowpb.Endpoint{
					ID:       1000,
					Identity: 1000,
				},
				Destination: &flowpb.Endpoint{
					ID:       2000,
					Identity: 2000,
				},
				PolicyMatchType: monitorAPI.PolicyMatchL3L4,
			},
			cookie: cookie.NewBakedCookie(
				"["+
					"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy"+" "+
					"k8s:io.cilium.k8s.policy.name=p-1"+" "+
					"k8s:io.cilium.k8s.policy.namespace=ns-1"+" "+
					"k8s:io.cilium.k8s.policy.uid=1234-5678"+
					"]",
				[]string{"bozo!"},
			),
			id: []*flow.Policy{
				{
					Name:      "p-1",
					Namespace: "ns-1",
					Kind:      utils.ResourceTypeCiliumNetworkPolicy,
					Labels: []string{
						"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
						"k8s:io.cilium.k8s.policy.name=p-1",
						"k8s:io.cilium.k8s.policy.namespace=ns-1",
						"k8s:io.cilium.k8s.policy.uid=1234-5678",
					},
				},
			},
		},

		"egress-multi": {
			flow: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					Type: monitorAPI.MessageTypePolicyVerdict,
				},
				Verdict:          flowpb.Verdict_FORWARDED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				IP: &flowpb.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
				},
				L4: &flowpb.Layer4{
					Protocol: &flowpb.Layer4_TCP{
						TCP: &flowpb.TCP{
							DestinationPort: 8000,
						},
					},
				},
				Source: &flowpb.Endpoint{
					ID:       1000,
					Identity: 1000,
				},
				Destination: &flowpb.Endpoint{
					ID:       2000,
					Identity: 2000,
				},
				PolicyMatchType: monitorAPI.PolicyMatchL3L4,
			},
			cookie: cookie.NewBakedCookie(
				"["+
					"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy"+" "+
					"k8s:io.cilium.k8s.policy.name=p-1"+" "+
					"k8s:io.cilium.k8s.policy.namespace=ns-1"+" "+
					"k8s:io.cilium.k8s.policy.uid=1234-5678"+
					"], "+
					"["+
					"k8s:io.cilium.k8s.policy.derived-from=CiliumClusterwideNetworkPolicy"+" "+
					"k8s:io.cilium.k8s.policy.name=p-2"+" "+
					"k8s:io.cilium.k8s.policy.uid=1234-5679"+
					"]",
				[]string{"bozo!"},
			),
			ea: []*flow.Policy{
				{
					Name:      "p-1",
					Namespace: "ns-1",
					Kind:      utils.ResourceTypeCiliumNetworkPolicy,
					Labels: []string{
						"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
						"k8s:io.cilium.k8s.policy.name=p-1",
						"k8s:io.cilium.k8s.policy.namespace=ns-1",
						"k8s:io.cilium.k8s.policy.uid=1234-5678",
					},
				},

				{
					Name:      "p-2",
					Namespace: "",
					Kind:      utils.ResourceTypeCiliumClusterwideNetworkPolicy,
					Labels: []string{
						"k8s:io.cilium.k8s.policy.derived-from=CiliumClusterwideNetworkPolicy",
						"k8s:io.cilium.k8s.policy.name=p-2",
						"k8s:io.cilium.k8s.policy.uid=1234-5679",
					},
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			epg := &testutils.FakeEndpointGetter{
				OnGetCookie: func(id uint32) (epCookie *cookie.BakedCookie, ok bool) {
					return u.cookie, true
				},
			}

			CorrelatePolicyFromCookie(hivetest.Logger(t), 42, epg, u.flow)
			assert.Equal(t, u.ea, u.flow.EgressAllowedBy)
			assert.Equal(t, u.ed, u.flow.EgressDeniedBy)
			assert.Equal(t, u.ia, u.flow.IngressAllowedBy)
			assert.Equal(t, u.id, u.flow.IngressDeniedBy)
		})
	}
}

func BenchmarkCorrelatePolicy(b *testing.B) {
	flow := flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      "1.2.3.4",
			Destination: "5.6.7.8",
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: 443,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       12,
			Identity: 1234,
		},
		Destination: &flowpb.Endpoint{
			ID:       56,
			Identity: 5678,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL3L4,
	}

	policyLabel := utils.GetPolicyLabels("foo-namespace", "web-policy", "1234-5678", utils.ResourceTypeCiliumNetworkPolicy)
	policyKey := policy.EgressKey().WithIdentity(identity.NumericIdentity(5678)).WithTCPPort(443)
	ep := &testutils.FakeEndpointInfo{
		ID:           12,
		Identity:     identity.NumericIdentity(1234),
		IPv4:         net.ParseIP("1.2.3.4"),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policy.Key]labels.LabelArrayListString{
			policyKey: labels.LabelArrayList{policyLabel}.ArrayListString(),
		},
		PolicyRevision: 1,
	}

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfoByID: func(id uint16) (endpoint getters.EndpointInfo, ok bool) {
			if uint64(id) == ep.ID {
				return ep, true
			}
			b.Fatalf("did not expect endpoint retrieval for non-local endpoint: %d", id)
			return nil, false
		},
	}

	logger := hivetest.Logger(b)
	for b.Loop() {
		CorrelatePolicy(logger, endpointGetter, &flow)
	}
}

func BenchmarkCorrelatePolicyFromCookie(b *testing.B) {
	flow := flowpb.Flow{
		EventType: &flowpb.CiliumEventType{
			Type: monitorAPI.MessageTypePolicyVerdict,
		},
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		IP: &flowpb.IP{
			Source:      "1.1.1.1",
			Destination: "2.2.2.2",
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{
				TCP: &flowpb.TCP{
					DestinationPort: 8000,
				},
			},
		},
		Source: &flowpb.Endpoint{
			ID:       1000,
			Identity: 1000,
		},
		Destination: &flowpb.Endpoint{
			ID:       2000,
			Identity: 2000,
		},
		PolicyMatchType: monitorAPI.PolicyMatchL3L4,
	}
	c := cookie.NewBakedCookie(
		"["+
			"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy"+" "+
			"k8s:io.cilium.k8s.policy.name=p-1"+" "+
			"k8s:io.cilium.k8s.policy.namespace=ns-1"+" "+
			"k8s:io.cilium.k8s.policy.uid=1234-5678"+
			"]",
		[]string{"bozo!"},
	)

	epg := &testutils.FakeEndpointGetter{
		OnGetCookie: func(id uint32) (*cookie.BakedCookie, bool) {
			return c, true
		},
	}

	logger := hivetest.Logger(b)
	for b.Loop() {
		CorrelatePolicyFromCookie(logger, 42, epg, &flow)
	}
}

func Benchmark_policyFromCookie(b *testing.B) {
	lbls := []string{
		"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
		"k8s:io.cilium.k8s.policy.name=p-1",
		"k8s:io.cilium.k8s.policy.namespace=ns-1",
		"k8s:io.cilium.k8s.policy.uid=1234-5678",
	}
	for b.Loop() {
		_ = policyFromCookie(lbls)
	}
}

func Benchmark_policiesFromCookie(b *testing.B) {
	c := cookie.NewBakedCookie(
		"["+
			"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy"+" "+
			"k8s:io.cilium.k8s.policy.name=p-1"+" "+
			"k8s:io.cilium.k8s.policy.namespace=ns-1"+" "+
			"k8s:io.cilium.k8s.policy.uid=1234-5678"+
			"]",
		[]string{"bozo!"},
	)
	for b.Loop() {
		_ = policiesFromCookie(c)
	}
}
