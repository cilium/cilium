// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dropeventemitter

import (
	"context"
	"fmt"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	"github.com/stretchr/testify/assert"
)

const (
	fakePodName = "pod"
	fakePodUid  = "79f04581-a0e7-4a42-a020-db51cf21a605"
)

func TestEndpointToString(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		endpoint *flowpb.Endpoint
		expect   string
	}{
		{
			name:     fakePodName,
			ip:       "1.2.3.4",
			endpoint: &flowpb.Endpoint{PodName: fakePodName, Namespace: "namespace"},
			expect:   "namespace/pod (1.2.3.4)",
		},
		{
			name:     "node",
			ip:       "1.2.3.4",
			endpoint: &flowpb.Endpoint{Identity: identity.ReservedIdentityRemoteNode.Uint32()},
			expect:   identity.ReservedIdentityRemoteNode.String() + " (1.2.3.4)",
		},
		{
			name:     "unknown",
			ip:       "1.2.3.4",
			endpoint: &flowpb.Endpoint{Identity: identity.MaxLocalIdentity.Uint32() + 1},
			expect:   "1.2.3.4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &DropEventEmitter{}
			str := e.endpointToString(tt.ip, tt.endpoint)
			assert.Equal(t, str, tt.expect)
		})
	}
}

func TestL4protocolToString(t *testing.T) {
	tests := []struct {
		name   string
		l4     *flowpb.Layer4
		expect string
	}{
		{
			name:   "udp/512",
			l4:     &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 512}}},
			expect: "UDP/512",
		},
		{
			name:   "tcp/443",
			l4:     &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			expect: "TCP/443",
		},
		{
			name:   "unknown",
			l4:     &flowpb.Layer4{},
			expect: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &DropEventEmitter{}
			str := e.l4protocolToString(tt.l4)
			assert.Equal(t, str, tt.expect)
		})
	}
}

func TestProcessFlow(t *testing.T) {
	tests := []struct {
		name   string
		flow   *flowpb.Flow
		expect string
	}{
		{
			name: "valid ingress drop event",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "Incoming packet dropped (policy_denied) from unknown (1.2.3.4) TCP/443",
		},
		{
			name: "valid egress drop event to node",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				Destination:      &flowpb.Endpoint{Identity: identity.ReservedIdentityRemoteNode.Uint32()},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 512}}},
			},
			expect: "Outgoing packet dropped (policy_denied) to remote-node (5.6.7.8) UDP/512",
		},
		{
			name: "ingress drop event not matching reason",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_AUTH_REQUIRED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
		{
			name: "ingress verdict is not dropped",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_ERROR,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
		{
			name: "ingress but no destination pod",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{Namespace: "namespace", PodName: fakePodName},
				Destination:      &flowpb.Endpoint{},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
		{
			name: "egress but no source pod",
			flow: &flowpb.Flow{
				Verdict:          flowpb.Verdict_DROPPED,
				DropReasonDesc:   flowpb.DropReason_POLICY_DENIED,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				IP:               &flowpb.IP{Source: "1.2.3.4", Destination: "5.6.7.8"},
				Source:           &flowpb.Endpoint{},
				Destination:      &flowpb.Endpoint{},
				L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
			},
			expect: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeRecorder := &FakeRecorder{
				Events:        make(chan string, 3),
				IncludeObject: true,
			}
			e := &DropEventEmitter{
				reasons:    []string{"policy_denied"},
				recorder:   fakeRecorder,
				k8sWatcher: &fakeK8SWatcher{},
			}
			if err := e.ProcessFlow(context.Background(), tt.flow); err != nil {
				t.Errorf("DropEventEmitter.ProcessFlow() error = %v", err)
			}
			if tt.expect == "" {
				assert.Len(t, fakeRecorder.Events, 0)
			} else {
				assert.Len(t, fakeRecorder.Events, 1)
				event := <-fakeRecorder.Events
				assert.Contains(t, event, tt.expect)
				if tt.flow.Destination.PodName == fakePodName && tt.flow.TrafficDirection == flowpb.TrafficDirection_EGRESS {
					assert.Contains(t, event, fakePodUid)
				}
			}
		})
	}
}

type fakeK8SWatcher struct {
}

func (k *fakeK8SWatcher) GetCachedNamespace(namespace string) (*slim_corev1.Namespace, error) {
	return nil, nil
}
func (k *fakeK8SWatcher) GetCachedPod(namespace, name string) (*slim_corev1.Pod, error) {
	if name == fakePodName {
		return &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: fakePodName,
				UID:  fakePodUid,
			},
		}, nil
	}
	return nil, fmt.Errorf("pod not found in cache : %s", name)
}
