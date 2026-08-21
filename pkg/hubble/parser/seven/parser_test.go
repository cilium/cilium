// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	fakeTimestamp = "2006-01-02T15:04:05.999999999Z"
	fakeNodeInfo  = accesslog.NodeAddressInfo{
		IPv4: "192.168.1.100",
		IPv6: " fd01::a",
	}
	fakeSourceEndpoint = accesslog.EndpointInfo{
		ID:       1234,
		IPv4:     "10.16.32.10",
		IPv6:     "f00d::a10:0:0:abcd",
		Identity: 9876,
		Labels:   labels.ParseLabelArray("k1=v1", "k2=v2"),
	}
	fakeDestinationEndpoint = accesslog.EndpointInfo{
		ID:       4321,
		IPv4:     "10.16.32.20",
		IPv6:     "f00d::a10:0:0:1234",
		Port:     80,
		Identity: 6789,
		Labels:   labels.ParseLabelArray("k3=v3", "k4=v4"),
	}
)

func BenchmarkL7Decode(b *testing.B) {
	requestPath, err := url.Parse("http://myhost/some/path")
	require.NoError(b, err)
	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeResponse,
		Timestamp:           fakeTimestamp,
		NodeAddressInfo:     fakeNodeInfo,
		ObservationPoint:    accesslog.Ingress,
		SourceEndpoint:      fakeDestinationEndpoint,
		DestinationEndpoint: fakeSourceEndpoint,
		IPVersion:           accesslog.VersionIPv4,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.TCP),
		ServiceInfo:         nil,
		DropReason:          nil,
		HTTP: &accesslog.LogRecordHTTP{
			Code:     404,
			Method:   "POST",
			URL:      requestPath,
			Protocol: "HTTP/1.1",
			Headers: http.Header{
				"Host":        {"myhost"},
				"Traceparent": {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			},
		},
	}
	lr.SourceEndpoint.Port = 80
	lr.DestinationEndpoint.Port = 56789

	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter
	endpointGetter := &testutils.NoopEndpointGetter

	parser, err := New(hivetest.Logger(b), dnsGetter, ipGetter, serviceGetter, endpointGetter)
	require.NoError(b, err)

	f := &flowpb.Flow{}
	b.ReportAllocs()

	for b.Loop() {
		_ = parser.Decode(lr, f)
	}
}

func Test_decodeVerdict(t *testing.T) {
	assert.Equal(t, flowpb.Verdict_FORWARDED, decodeVerdict(accesslog.VerdictForwarded))
	assert.Equal(t, flowpb.Verdict_DROPPED, decodeVerdict(accesslog.VerdictDenied))
	assert.Equal(t, flowpb.Verdict_ERROR, decodeVerdict(accesslog.VerdictError))
	assert.Equal(t, flowpb.Verdict_REDIRECTED, decodeVerdict(accesslog.VerdictRedirected))
	assert.Equal(t, flowpb.Verdict_VERDICT_UNKNOWN, decodeVerdict("bad"))
}

func Test_decodeEndpoint(t *testing.T) {
	epi := accesslog.EndpointInfo{
		ID:       1234,
		Identity: 9876,
		Labels: labels.ParseLabelArray(
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.kubernetes.pod.namespace=kube-system",
			"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
			"k8s:k8s-app=hubble-ui",
			"k8s:app.kubernetes.io/name=hubble-ui",
			"k8s:app.kubernetes.io/part-of=cilium",
		),
	}
	expected := &flowpb.Endpoint{
		ID:          1234,
		Identity:    9876,
		ClusterName: "default",
		Namespace:   "kube-system",
		Labels: []string{
			"k8s:app.kubernetes.io/name=hubble-ui",
			"k8s:app.kubernetes.io/part-of=cilium",
			"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.kubernetes.pod.namespace=kube-system",
			"k8s:k8s-app=hubble-ui",
		},
		PodName: "hubble-ui",
		PodUid:  "hubble-ui-uid",
	}
	ep := decodeEndpoint(epi, "kube-system", "hubble-ui", "hubble-ui-uid")
	assert.Equal(t, expected, ep)

	ep = decodeEndpoint(epi, "kube-system", "hubble-ui", "")
	assert.Empty(t, ep.GetPodUid())
}

func TestUpdateEndpointFromLocalPodMetadata(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	controller := true
	localPod := &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{
		GenerateName: "local-pod-",
		OwnerReferences: []slim_metav1.OwnerReference{{
			Kind:       "StatefulSet",
			Name:       "local-workload",
			Controller: &controller,
		}},
	}}
	localWorkload := []*flowpb.Workload{{Kind: "StatefulSet", Name: "local-workload"}}
	tests := []struct {
		name            string
		endpointID      uint32
		localEndpointID uint64
		localNamespace  string
		localPodName    string
		localPodUID     string
		wantNamespace   string
		wantPodName     string
		wantPodUID      string
		wantWorkloads   []*flowpb.Workload
	}{
		{
			name:            "local metadata overrides IPCache metadata",
			endpointID:      1234,
			localEndpointID: 1234,
			localNamespace:  "local-namespace",
			localPodName:    "local-pod",
			localPodUID:     "local-pod-uid",
			wantNamespace:   "local-namespace",
			wantPodName:     "local-pod",
			wantPodUID:      "local-pod-uid",
			wantWorkloads:   localWorkload,
		},
		{
			name:            "empty local UID preserves IPCache metadata",
			endpointID:      1234,
			localEndpointID: 1234,
			localNamespace:  "local-namespace",
			localPodName:    "local-pod",
			wantNamespace:   "ipcache-namespace",
			wantPodName:     "ipcache-pod",
			wantPodUID:      "ipcache-pod-uid",
			wantWorkloads:   localWorkload,
		},
		{
			name:            "different local endpoint preserves IPCache metadata",
			endpointID:      1234,
			localEndpointID: 4321,
			localNamespace:  "local-namespace",
			localPodName:    "local-pod",
			localPodUID:     "local-pod-uid",
			wantNamespace:   "ipcache-namespace",
			wantPodName:     "ipcache-pod",
			wantPodUID:      "ipcache-pod-uid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &Parser{
				endpointGetter: &testutils.FakeEndpointGetter{
					OnGetEndpointInfo: func(netip.Addr) (getters.EndpointInfo, bool) {
						return &testutils.FakeEndpointInfo{
							ID:           tt.localEndpointID,
							PodNamespace: tt.localNamespace,
							PodName:      tt.localPodName,
							PodUID:       tt.localPodUID,
							Pod:          localPod,
						}, true
					},
				},
			}
			endpoint := &flowpb.Endpoint{
				ID:        tt.endpointID,
				Namespace: "ipcache-namespace",
				PodName:   "ipcache-pod",
				PodUid:    "ipcache-pod-uid",
			}

			parser.updateEndpointFromLocal(ip, endpoint)

			assert.Equal(t, tt.wantNamespace, endpoint.GetNamespace())
			assert.Equal(t, tt.wantPodName, endpoint.GetPodName())
			assert.Equal(t, tt.wantPodUID, endpoint.GetPodUid())
			assert.Equal(t, tt.wantWorkloads, endpoint.GetWorkloads())
		})
	}
}
