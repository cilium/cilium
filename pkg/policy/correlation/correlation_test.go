// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package correlation

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestCorrelatePolicy(t *testing.T) {
	localIP := "1.2.3.4"
	localID := uint64(1234)
	remoteIP := "5.6.7.8"
	remoteID := uint64(5678)
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
			Identity: uint32(localID),
		},
		Destination: &flowpb.Endpoint{
			Identity: uint32(remoteID),
		},
	}

	policyLabel := utils.GetPolicyLabels("foo-namespace", "web-policy", "1234-5678", utils.ResourceTypeCiliumNetworkPolicy)
	policyKey := policy.Key{
		Identity:         uint32(remoteID),
		DestPort:         uint16(dstPort),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Egress.Uint8(),
	}
	ep := &testutils.FakeEndpointInfo{
		ID:           localID,
		Identity:     identity.NumericIdentity(localID),
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
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
			if ip == netip.MustParseAddr(localIP) {
				return ep, true
			}
			t.Fatal("did not expect endpoint retrieval for non-local endpoint")
			return nil, false
		},
	}

	CorrelatePolicy(endpointGetter, flow)

	expected := []*flowpb.Policy{
		{
			Name:      "web-policy",
			Namespace: "foo-namespace",
			Labels: []string{
				"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
				"k8s:io.cilium.k8s.policy.name=web-policy",
				"k8s:io.cilium.k8s.policy.namespace=foo-namespace",
				"k8s:io.cilium.k8s.policy.uid=1234-5678",
			},
			Revision: 1,
		},
	}

	require.Nil(t, flow.IngressAllowedBy)
	if diff := cmp.Diff(expected, flow.EgressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}

	// do the other direction
	flow.EgressAllowedBy = nil
	flow.IngressAllowedBy = nil
	// swap the local/remote
	localIP, remoteIP = remoteIP, localIP
	remoteID, localID = localID, remoteID
	flow.TrafficDirection = flowpb.TrafficDirection_INGRESS
	flow.Source, flow.Destination = flow.Destination, flow.Source
	flow.IP.Source, flow.IP.Destination = flow.IP.Destination, flow.IP.Source

	policyKey = policy.Key{
		Identity:         uint32(localID),
		DestPort:         uint16(dstPort),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	}
	ep = &testutils.FakeEndpointInfo{
		ID:           uint64(remoteID),
		Identity:     identity.NumericIdentity(remoteID),
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
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
			if ip == netip.MustParseAddr(remoteIP) {
				return ep, true
			}
			t.Fatal("did not expect endpoint retrieval for non-remote endpoint")
			return nil, false
		},
	}
	CorrelatePolicy(endpointGetter, flow)

	require.Nil(t, flow.EgressAllowedBy)
	if diff := cmp.Diff(expected, flow.IngressAllowedBy, protocmp.Transform()); diff != "" {
		t.Fatalf("not equal (-want +got):\n%s", diff)
	}
}
