// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package threefour

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/common"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
)

// ipTuple is the addressing used for the source/destination of a flow.
type ipTuple struct {
	src, dst netip.Addr
}

var (
	localIP  = netip.MustParseAddr("1.2.3.4")
	localEP  = uint16(1234)
	hostEP   = uint16(0x1092)
	remoteIP = netip.MustParseAddr("5.6.7.8")
	remoteID = identity.NumericIdentity(5678)
	xlatedIP = netip.MustParseAddr("10.11.12.13")
	srcMAC   = net.HardwareAddr{1, 2, 3, 4, 5, 6}
	dstMAC   = net.HardwareAddr{7, 8, 9, 0, 1, 2}

	egressTuple       = ipTuple{src: localIP, dst: remoteIP}
	ingressTuple      = ipTuple{src: remoteIP, dst: localIP}
	xlatedEgressTuple = ipTuple{src: xlatedIP, dst: remoteIP}

	fooBarLabel           = labels.LabelArrayList{labels.ParseLabelArray("foo=bar")}
	remotePolicyKey       = policy.EgressKey().WithIdentity(remoteID)
	defaultEndpointGetter = &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			if ip == localIP {
				return &testutils.FakeEndpointInfo{
					ID: uint64(localEP),
					PolicyMap: map[policyTypes.Key]string{
						remotePolicyKey: fooBarLabel.String(),
					},
					PolicyRevision: 1,
				}, true
			}
			return nil, false
		},
	}
)

func directionFromProto(direction flowpb.TrafficDirection) trafficdirection.TrafficDirection {
	switch direction {
	case flowpb.TrafficDirection_INGRESS:
		return trafficdirection.Ingress
	case flowpb.TrafficDirection_EGRESS:
		return trafficdirection.Egress
	default:
		return trafficdirection.Invalid
	}
}

func TestL34DecodeEmpty(t *testing.T) {
	parser, err := New(hivetest.Logger(t), &testutils.NoopEndpointGetter, &testutils.NoopIdentityGetter,
		&testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter,
		&testutils.NoopLinkGetter)
	require.NoError(t, err)

	var d []byte
	f := &flowpb.Flow{}
	err = parser.Decode(d, f)
	assert.Equal(t, err, errors.ErrEmptyData)
}

func TestL34Decode(t *testing.T) {
	// SOURCE          					DESTINATION           TYPE   SUMMARY
	// 192.168.60.11:6443(sun-sr-https)  10.16.236.178:54222   L3/4   TCP Flags: ACK
	d := []byte{
		4, 7, 0, 0, 7, 124, 26, 57, 66, 0, 0, 0, 66, 0, 0, 0, // NOTIFY_CAPTURE_HDR
		1, 0, 0, 0, // source labels
		0, 0, 0, 0, // destination labels
		0, 0, // destination ID
		0x81,       // "established" trace reason with the encrypt bit set
		0,          // flags
		0, 0, 0, 0, // ifindex
		246, 141, 178, 45, 33, 217, 246, 141, 178,
		45, 33, 217, 8, 0, 69, 0, 0, 52, 234, 28, 64, 0, 64, 6, 120, 49, 192,
		168, 60, 11, 10, 16, 236, 178, 25, 43, 211, 206, 42, 239, 210, 28, 180,
		152, 129, 103, 128, 16, 1, 152, 216, 156, 0, 0, 1, 1, 8, 10, 0, 90, 176,
		98, 0, 90, 176, 97, 0, 0}

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			if ip == netip.MustParseAddr("10.16.236.178") {
				return &testutils.FakeEndpointInfo{
					ID:           1234,
					Identity:     5678,
					PodName:      "pod-10.16.236.178",
					PodNamespace: "default",
					Pod: &slim_corev1.Pod{
						ObjectMeta: slim_metav1.ObjectMeta{
							OwnerReferences: []slim_metav1.OwnerReference{
								{
									Kind: "ReplicaSet",
									Name: "pod",
								},
							},
						},
					},
				}, true
			}
			return nil, false
		},
	}
	dnsGetter := &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip netip.Addr) (names []string) {
			if epID == 1234 {
				switch {
				case ip.String() == "192.168.60.11":
					return []string{"host-192.168.60.11"}
				}
			}
			return nil
		},
	}
	ipGetter := &testutils.FakeIPGetter{
		OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
			if ip == netip.MustParseAddr("192.168.60.11") {
				return &ipcache.K8sMetadata{
					Namespace: "remote",
					PodName:   "pod-192.168.60.11",
				}
			}
			return nil
		},
		OnLookupSecIDByIP: func(ip netip.Addr) (ipcache.Identity, bool) {
			// pretend IP belongs to a pod on a remote node
			if ip == netip.MustParseAddr("192.168.60.11") {
				// This numeric identity will be ignored because the above
				// TraceNotify event already contains the source identity
				return ipcache.Identity{
					ID:     1234,
					Source: source.Unspec,
				}, true
			}
			return ipcache.Identity{}, false
		},
	}
	serviceGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
			if ip == netip.MustParseAddr("192.168.60.11") && (port == 6443) {
				return &flowpb.Service{
					Name:      "service-1234",
					Namespace: "remote",
				}
			}
			if ip == netip.MustParseAddr("10.16.236.178") && (port == 54222) {
				return &flowpb.Service{
					Name:      "service-4321",
					Namespace: "default",
				}
			}
			return nil
		},
	}
	identityCache := &testutils.NoopIdentityGetter
	parser, err := New(hivetest.Logger(t), endpointGetter, identityCache, dnsGetter, ipGetter, serviceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(d, f)
	require.NoError(t, err)

	assert.Equal(t, []string{"host-192.168.60.11"}, f.GetSourceNames())
	assert.Equal(t, "192.168.60.11", f.GetIP().GetSource())
	assert.Empty(t, f.GetIP().GetSourceXlated())
	assert.Equal(t, flowpb.TraceReason_ESTABLISHED, f.GetTraceReason())
	assert.True(t, f.GetIP().GetEncrypted())
	assert.Equal(t, uint32(6443), f.L4.GetTCP().GetSourcePort())
	assert.Equal(t, "pod-192.168.60.11", f.GetSource().GetPodName())
	assert.Equal(t, "remote", f.GetSource().GetNamespace())
	assert.Equal(t, "service-1234", f.GetSourceService().GetName())
	assert.Equal(t, "remote", f.GetSourceService().GetNamespace())
	assert.Equal(t, uint32(1), f.GetSource().GetIdentity())

	assert.Equal(t, []string(nil), f.GetDestinationNames())
	assert.Equal(t, "10.16.236.178", f.GetIP().GetDestination())
	assert.Equal(t, uint32(54222), f.L4.GetTCP().GetDestinationPort())
	assert.Equal(t, "pod-10.16.236.178", f.GetDestination().GetPodName())
	assert.Equal(t, "default", f.GetDestination().GetNamespace())
	assert.Equal(t, "service-4321", f.GetDestinationService().GetName())
	assert.Equal(t, "default", f.GetDestinationService().GetNamespace())
	assert.Equal(t, uint32(5678), f.GetDestination().GetIdentity())

	assert.Equal(t, int32(monitorAPI.MessageTypeTrace), f.GetEventType().GetType())
	assert.Equal(t, int32(monitorAPI.TraceFromHost), f.GetEventType().GetSubType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, &flowpb.TCPFlags{ACK: true}, f.L4.GetTCP().GetFlags())

	assert.Equal(t, flowpb.TraceObservationPoint_FROM_HOST, f.GetTraceObservationPoint())

	nilParser, err := New(hivetest.Logger(t), nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	err = nilParser.Decode(d, f)
	require.NoError(t, err)

	// ICMP packet so no ports until that support is merged into master
	//
	// SOURCE              DESTINATION          TYPE   SUMMARY
	// ff02::1:ff00:b3e5   f00d::a10:0:0:9195   L3/4
	d2 := []byte{
		4, 5, 168, 11, 95, 22, 242, 184, 86, 0, 0, 0, 86, 0, 0, 0, 104, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 51, 255, 0, 179, 229, 18, 145,
		6, 226, 34, 26, 134, 221, 96, 0, 0, 0, 0, 32, 58, 255, 255, 2, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 1, 255, 0, 179, 229, 240, 13, 0, 0, 0, 0, 0, 0, 10,
		16, 0, 0, 0, 0, 145, 149, 135, 0, 80, 117, 0, 0, 0, 0, 240, 13, 0, 0, 0,
		0, 0, 0, 10, 16, 0, 0, 0, 0, 179, 229, 1, 1, 18, 145, 6, 226, 34, 26, 0,
		0, 0, 0, 0, 0}

	endpointGetter = &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			if ip == netip.MustParseAddr("ff02::1:ff00:b3e5") {
				return &testutils.FakeEndpointInfo{
					ID: 1234,
				}, true
			}
			return nil, false
		},
	}
	dnsGetter = &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip netip.Addr) (names []string) {
			if epID == 1234 {
				switch {
				case ip.String() == "f00d::a10:0:0:9195":
					return []string{"host-f00d::a10:0:0:9195"}
				}
			}
			return nil
		},
	}
	ipGetter = &testutils.NoopIPGetter
	serviceGetter = &testutils.NoopServiceGetter
	parser, err = New(hivetest.Logger(t), endpointGetter, identityCache, dnsGetter, ipGetter, serviceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	err = parser.Decode(d2, f)
	require.NoError(t, err)

	// second packet is ICMPv6 and the flags should be totally wiped out
	assert.Equal(t, []string(nil), f.GetSourceNames())
	assert.Equal(t, "ff02::1:ff00:b3e5", f.GetIP().GetSource())
	assert.Empty(t, f.GetIP().GetSourceXlated())
	assert.Equal(t, &flowpb.ICMPv6{Type: 135}, f.L4.GetICMPv6())
	assert.Empty(t, f.GetSource().GetPodName())
	assert.Empty(t, f.GetSource().GetNamespace())

	assert.Equal(t, []string{"host-f00d::a10:0:0:9195"}, f.GetDestinationNames())
	assert.Equal(t, "f00d::a10:0:0:9195", f.GetIP().GetDestination())
	assert.Empty(t, f.GetDestination().GetPodName())
	assert.Empty(t, f.GetDestination().GetNamespace())

	assert.Equal(t, int32(monitorAPI.MessageTypeTrace), f.GetEventType().GetType())
	assert.Equal(t, int32(monitorAPI.TraceFromLxc), f.GetEventType().GetSubType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, (*flowpb.TCPFlags)(nil), f.L4.GetTCP().GetFlags())

	assert.Equal(t, flowpb.TraceObservationPoint_FROM_ENDPOINT, f.GetTraceObservationPoint())

	err = nilParser.Decode(d, f)
	require.NoError(t, err)
}

func BenchmarkL34Decode(b *testing.B) {
	d := []byte{4, 7, 0, 0, 7, 124, 26, 57, 66, 0, 0, 0, 66, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 246, 141, 178, 45, 33, 217, 246, 141,
		178, 45, 33, 217, 8, 0, 69, 0, 0, 52, 234, 28, 64, 0, 64, 6, 120, 49, 192,
		168, 60, 11, 10, 16, 236, 178, 25, 43, 211, 206, 42, 239, 210, 28, 180, 152,
		129, 103, 128, 16, 1, 152, 216, 156, 0, 0, 1, 1, 8, 10, 0, 90, 176, 98, 0,
		90, 176, 97, 0, 0}

	endpointGetter := &testutils.NoopEndpointGetter
	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter
	identityCache := &testutils.NoopIdentityGetter
	parser, err := New(hivetest.Logger(b), endpointGetter, identityCache, dnsGetter, ipGetter, serviceGetter, &testutils.NoopLinkGetter)
	require.NoError(b, err)

	f := &flowpb.Flow{}
	b.ReportAllocs()

	for b.Loop() {
		_ = parser.Decode(d, f)
	}
}

func TestDecodeTraceNotify(t *testing.T) {
	for _, c := range []struct {
		Name       string
		IsL3Device bool
	}{{"L3Device", true}, {"L2Device", false}} {
		t.Run(c.Name, func(t *testing.T) {
			tn := monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				SrcLabel: 123,
				DstLabel: 456,
				Version:  monitor.TraceNotifyVersion1,
			}
			lay := []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
					DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					Version:  4,
					IHL:      5,
					Length:   49,
					Id:       0xCECB,
					TTL:      64,
					Protocol: layers.IPProtocolUDP,
					SrcIP:    net.IPv4(1, 2, 3, 4),
					DstIP:    net.IPv4(1, 2, 3, 4),
				},
				&layers.UDP{
					SrcPort: 23939,
					DstPort: 32412,
				},
			}

			if c.IsL3Device {
				tn.Flags = monitor.TraceNotifyFlagIsL3Device
				lay = lay[1:]
			}

			buf := &bytes.Buffer{}
			err := binary.Write(buf, byteorder.Native, &tn)
			require.NoError(t, err)
			buffer := gopacket.NewSerializeBuffer()
			err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, lay...)
			require.NoError(t, err)
			buf.Write(buffer.Bytes())
			require.NoError(t, err)
			identityGetter := &testutils.FakeIdentityGetter{OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
				if securityIdentity == uint32(tn.SrcLabel) {
					return &identity.Identity{Labels: labels.NewLabelsFromModel([]string{"k8s:src=label", "k8s:io.cilium.k8s.policy.cluster=cluster-name"})}, nil
				} else if securityIdentity == uint32(tn.DstLabel) {
					return &identity.Identity{Labels: labels.NewLabelsFromModel([]string{"k8s:dst=label", "k8s:io.cilium.k8s.policy.cluster=cluster-name"})}, nil
				}
				return nil, fmt.Errorf("identity not found for %d", securityIdentity)
			}}

			parser, err := New(hivetest.Logger(t), &testutils.NoopEndpointGetter, identityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
			require.NoError(t, err)

			f := &flowpb.Flow{}
			err = parser.Decode(buf.Bytes(), f)
			require.NoError(t, err)
			assert.Equal(t, []string{"k8s:io.cilium.k8s.policy.cluster=cluster-name", "k8s:src=label"}, f.GetSource().GetLabels())
			assert.Equal(t, []string{"k8s:dst=label", "k8s:io.cilium.k8s.policy.cluster=cluster-name"}, f.GetDestination().GetLabels())
			assert.Equal(t, "cluster-name", f.GetSource().GetClusterName())
			assert.Equal(t, "cluster-name", f.GetDestination().GetClusterName())
			assert.Equal(t, uint32(23939), f.GetL4().GetUDP().GetSourcePort())
			assert.Equal(t, uint32(32412), f.GetL4().GetUDP().GetDestinationPort())
		})
	}
}

func TestDecodeDropNotify(t *testing.T) {
	for _, c := range []struct {
		Name       string
		IsL3Device bool
	}{{"L3Device", true}, {"L2Device", false}} {
		t.Run(c.Name, func(t *testing.T) {
			dn := monitor.DropNotify{
				Type:     byte(monitorAPI.MessageTypeDrop),
				File:     1, // bpf_host.c
				Line:     42,
				SrcLabel: 123,
				DstLabel: 456,
				Version:  monitor.DropNotifyVersion2,
			}
			lay := []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
					DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					Version:  4,
					IHL:      5,
					Length:   49,
					Id:       0xCECB,
					TTL:      64,
					Protocol: layers.IPProtocolUDP,
					SrcIP:    net.IPv4(1, 2, 3, 4),
					DstIP:    net.IPv4(1, 2, 3, 4),
				},
				&layers.UDP{
					SrcPort: 23939,
					DstPort: 32412,
				},
			}

			if c.IsL3Device {
				dn.Flags = monitor.TraceNotifyFlagIsL3Device
				lay = lay[1:]
			}

			buf := &bytes.Buffer{}
			err := binary.Write(buf, byteorder.Native, &dn)
			require.NoError(t, err)
			buffer := gopacket.NewSerializeBuffer()
			err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, lay...)
			require.NoError(t, err)
			buf.Write(buffer.Bytes())
			require.NoError(t, err)
			identityGetter := &testutils.FakeIdentityGetter{
				OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
					if securityIdentity == uint32(dn.SrcLabel) {
						return &identity.Identity{Labels: labels.NewLabelsFromModel([]string{"k8s:src=label"})}, nil
					} else if securityIdentity == uint32(dn.DstLabel) {
						return &identity.Identity{Labels: labels.NewLabelsFromModel([]string{"k8s:dst=label"})}, nil
					}
					return nil, fmt.Errorf("identity not found for %d", securityIdentity)
				},
			}

			parser, err := New(hivetest.Logger(t), &testutils.NoopEndpointGetter, identityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
			require.NoError(t, err)

			f := &flowpb.Flow{}
			err = parser.Decode(buf.Bytes(), f)
			require.NoError(t, err)
			assert.Equal(t, []string{"k8s:src=label"}, f.GetSource().GetLabels())
			assert.Equal(t, []string{"k8s:dst=label"}, f.GetDestination().GetLabels())
			assert.NotNil(t, f.GetFile())
			assert.Equal(t, "bpf_host.c", f.GetFile().GetName())
			assert.Equal(t, uint32(42), f.GetFile().GetLine())
			assert.Equal(t, uint32(23939), f.GetL4().GetUDP().GetSourcePort())
			assert.Equal(t, uint32(32412), f.GetL4().GetUDP().GetDestinationPort())
		})
	}
}

func TestDecodePolicyVerdictNotify(t *testing.T) {
	localIP := "1.2.3.4"
	localID := uint64(12)
	localIdentity := identity.NumericIdentity(1234)
	remoteIP := "5.6.7.8"
	remoteIdentity := identity.NumericIdentity(5678)
	dstPort := uint32(443)

	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
			if identity.NumericIdentity(securityIdentity) == remoteIdentity {
				return &identity.Identity{ID: remoteIdentity, Labels: labels.NewLabelsFromModel([]string{"k8s:dst=label"})}, nil
			}
			return nil, fmt.Errorf("identity not found for %d", securityIdentity)
		},
	}

	policyLabel := utils.GetPolicyLabels("foo-namespace", "web-policy", "1234-5678", utils.ResourceTypeCiliumNetworkPolicy)
	policyKey := policy.EgressKey().WithIdentity(remoteIdentity).WithTCPPort(uint16(dstPort))
	ep := &testutils.FakeEndpointInfo{
		ID:           localID,
		Identity:     localIdentity,
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policyTypes.Key]string{
			policyKey: labels.LabelArrayList{policyLabel}.String(),
		},
		PolicyRevision: 1,
	}
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			if ip == netip.MustParseAddr(localIP) {
				return ep, true
			}
			return nil, false
		},
		OnGetEndpointInfoByID: func(id uint16) (endpoint getters.EndpointInfo, ok bool) {
			if uint64(id) == ep.ID {
				return ep, true
			}
			return nil, false
		},
	}

	parser, err := New(hivetest.Logger(t), endpointGetter, identityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	// PolicyVerdictNotify for forwarded flow
	var flags uint8
	flags |= monitorAPI.PolicyEgress
	flags |= monitorAPI.PolicyMatchL3L4 << monitor.PolicyVerdictNotifyFlagMatchTypeBitOffset
	pvn := monitor.PolicyVerdictNotify{
		Type:        byte(monitorAPI.MessageTypePolicyVerdict),
		SubType:     0,
		Flags:       flags,
		RemoteLabel: remoteIdentity,
		Verdict:     0, // CTX_ACT_OK
		Source:      uint16(localID),
	}
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP:    net.ParseIP(localIP),
		DstIP:    net.ParseIP(remoteIP),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		DstPort: layers.TCPPort(dstPort),
	}
	data, err := testutils.CreateL3L4Payload(pvn, &eth, &ip, &tcp)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(monitorAPI.MessageTypePolicyVerdict), f.GetEventType().GetType())
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(monitorAPI.PolicyMatchL3L4), f.GetPolicyMatchType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, []string{"k8s:dst=label"}, f.GetDestination().GetLabels())

	expectedPolicy := []*flowpb.Policy{
		{
			Name:      "web-policy",
			Namespace: "foo-namespace",
			Kind:      "CiliumNetworkPolicy",
			Labels: []string{
				"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy",
				"k8s:io.cilium.k8s.policy.name=web-policy",
				"k8s:io.cilium.k8s.policy.namespace=foo-namespace",
				"k8s:io.cilium.k8s.policy.uid=1234-5678",
			},
			Revision: 1,
		},
	}
	if diff := cmp.Diff(expectedPolicy, f.GetEgressAllowedBy(), protocmp.Transform()); diff != "" {
		t.Errorf("not equal (-want +got):\n%s", diff)
	}

	// PolicyVerdictNotify for dropped flow
	flags = monitorAPI.PolicyIngress
	pvn = monitor.PolicyVerdictNotify{
		Type:        byte(monitorAPI.MessageTypePolicyVerdict),
		SubType:     0,
		Flags:       flags,
		RemoteLabel: remoteIdentity,
		Verdict:     -151, // drop reason: Stale or unroutable IP
	}
	data, err = testutils.CreateL3L4Payload(pvn)
	require.NoError(t, err)

	f.Reset()
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(monitorAPI.MessageTypePolicyVerdict), f.GetEventType().GetType())
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(151), f.GetDropReason())
	assert.Equal(t, flowpb.DropReason(151), f.GetDropReasonDesc())
	assert.Equal(t, flowpb.Verdict_DROPPED, f.GetVerdict())
	assert.Equal(t, []string{"k8s:dst=label"}, f.GetSource().GetLabels())
}

func TestNetworkPolicyCorrelationDisabled(t *testing.T) {
	localIP := "1.2.3.4"
	localID := uint64(12)
	localIdentity := identity.NumericIdentity(1234)
	remoteIP := "5.6.7.8"
	remoteIdentity := identity.NumericIdentity(5678)
	dstPort := uint32(443)

	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
			if identity.NumericIdentity(securityIdentity) == remoteIdentity {
				return &identity.Identity{ID: remoteIdentity, Labels: labels.NewLabelsFromModel([]string{"k8s:dst=label"})}, nil
			}
			return nil, fmt.Errorf("identity not found for %d", securityIdentity)
		},
	}

	policyLabel := utils.GetPolicyLabels("foo-namespace", "web-policy", "1234-5678", utils.ResourceTypeCiliumNetworkPolicy)
	policyKey := policy.EgressKey().WithIdentity(remoteIdentity).WithTCPPort(uint16(dstPort))
	ep := &testutils.FakeEndpointInfo{
		ID:           localID,
		Identity:     localIdentity,
		IPv4:         net.ParseIP(localIP),
		PodName:      "xwing",
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
		PolicyMap: map[policyTypes.Key]string{
			policyKey: labels.LabelArrayList{policyLabel}.String(),
		},
		PolicyRevision: 1,
	}
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			if ip == netip.MustParseAddr(localIP) {
				return ep, true
			}
			return nil, false
		},
		OnGetEndpointInfoByID: func(id uint16) (endpoint getters.EndpointInfo, ok bool) {
			if uint64(id) == ep.ID {
				return ep, true
			}
			return nil, false
		},
	}

	opts := []options.Option{options.WithNetworkPolicyCorrelation(false)}
	parser, err := New(hivetest.Logger(t), endpointGetter, identityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter, opts...)
	require.NoError(t, err)

	// PolicyVerdictNotify for forwarded egress flow
	var flags uint8
	flags |= monitorAPI.PolicyEgress
	flags |= monitorAPI.PolicyMatchL3L4 << monitor.PolicyVerdictNotifyFlagMatchTypeBitOffset
	pvn := monitor.PolicyVerdictNotify{
		Type:        byte(monitorAPI.MessageTypePolicyVerdict),
		SubType:     0,
		Flags:       flags,
		RemoteLabel: remoteIdentity,
		Verdict:     0, // CTX_ACT_OK
		Source:      uint16(localID),
	}
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP:    net.ParseIP(localIP),
		DstIP:    net.ParseIP(remoteIP),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		DstPort: layers.TCPPort(dstPort),
	}
	data, err := testutils.CreateL3L4Payload(pvn, &eth, &ip, &tcp)

	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(monitorAPI.MessageTypePolicyVerdict), f.GetEventType().GetType())
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(monitorAPI.PolicyMatchL3L4), f.GetPolicyMatchType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, []string{"k8s:dst=label"}, f.GetDestination().GetLabels())
	assert.Equal(t, []*flowpb.Policy([]*flowpb.Policy(nil)), f.GetEgressAllowedBy())

	// PolicyVerdictNotify for forwarded ingress flow
	flags = monitorAPI.PolicyIngress
	flags |= monitorAPI.PolicyMatchL3L4 << monitor.PolicyVerdictNotifyFlagMatchTypeBitOffset
	pvn = monitor.PolicyVerdictNotify{
		Type:        byte(monitorAPI.MessageTypePolicyVerdict),
		SubType:     0,
		Flags:       flags,
		RemoteLabel: remoteIdentity,
		Verdict:     0,
	}

	data, err = testutils.CreateL3L4Payload(pvn)
	require.NoError(t, err)

	f.Reset()
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(monitorAPI.MessageTypePolicyVerdict), f.GetEventType().GetType())
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(monitorAPI.PolicyMatchL3L4), f.GetPolicyMatchType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, []string{"k8s:dst=label"}, f.GetSource().GetLabels())
	assert.Equal(t, []*flowpb.Policy([]*flowpb.Policy(nil)), f.GetIngressAllowedBy())
}

func TestDecodeDropReason(t *testing.T) {
	reason := uint8(130)
	dn := monitor.DropNotify{
		Type:    byte(monitorAPI.MessageTypeDrop),
		SubType: reason,
		Version: monitor.DropNotifyVersion2,
	}
	data, err := testutils.CreateL3L4Payload(dn)
	require.NoError(t, err)

	parser, err := New(hivetest.Logger(t), nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, uint32(reason), f.GetDropReason())
	assert.Equal(t, flowpb.DropReason(reason), f.GetDropReasonDesc())
}

func TestDecodeTraceReason(t *testing.T) {
	parser, err := New(hivetest.Logger(t), nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	parseFlow := func(event any, srcIPv4, dstIPv4 string) *flowpb.Flow {
		data, err := testutils.CreateL3L4Payload(event,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
				DstMAC:       net.HardwareAddr{7, 8, 9, 0, 1, 2},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{SrcIP: net.ParseIP(srcIPv4), DstIP: net.ParseIP(dstIPv4)})
		require.NoError(t, err)
		f := &flowpb.Flow{}
		err = parser.Decode(data, f)
		require.NoError(t, err)
		return f
	}

	var tt = []struct {
		name   string
		reason uint8
		want   flowpb.TraceReason
	}{
		{
			name:   "unknown",
			reason: monitor.TraceReasonUnknown,
			want:   flowpb.TraceReason_TRACE_REASON_UNKNOWN,
		},
		{
			name:   "new",
			reason: monitor.TraceReasonPolicy,
			want:   flowpb.TraceReason_NEW,
		},
		{
			name:   "established",
			reason: monitor.TraceReasonCtEstablished,
			want:   flowpb.TraceReason_ESTABLISHED,
		},
		{
			name:   "reply",
			reason: monitor.TraceReasonCtReply,
			want:   flowpb.TraceReason_REPLY,
		},
		{
			name:   "related",
			reason: monitor.TraceReasonCtRelated,
			want:   flowpb.TraceReason_RELATED,
		},
		{
			// "reopened" is deprecated, as the datapath no longer returns it
			name:   "reopened",
			reason: monitor.TraceReasonCtDeprecatedReopened,
			want:   flowpb.TraceReason_REOPENED,
		},
		{
			name:   "srv6-encap",
			reason: monitor.TraceReasonSRv6Encap,
			want:   flowpb.TraceReason_SRV6_ENCAP,
		},
		{
			name:   "srv6-decap",
			reason: monitor.TraceReasonSRv6Decap,
			want:   flowpb.TraceReason_SRV6_DECAP,
		},
		{
			name:   "encrypt-overlay",
			reason: monitor.TraceReasonEncryptOverlay,
			want:   flowpb.TraceReason_ENCRYPT_OVERLAY,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tn := monitor.TraceNotify{
				Type:   byte(monitorAPI.MessageTypeTrace),
				Reason: tc.reason,
			}
			f := parseFlow(tn, "1.2.3.4", "5.6.7.8")
			assert.Equal(t, tc.want, f.GetTraceReason())
			assert.False(t, f.GetIP().GetEncrypted())
		})
		t.Run(tc.name+" encrypted", func(t *testing.T) {
			tn := monitor.TraceNotify{
				Type:   byte(monitorAPI.MessageTypeTrace),
				Reason: tc.reason | monitor.TraceReasonEncryptMask,
			}
			f := parseFlow(tn, "1.2.3.4", "5.6.7.8")
			assert.Equal(t, tc.want, f.GetTraceReason())
			assert.True(t, f.GetIP().GetEncrypted())
		})
	}
}

func TestDecodeLocalIdentity(t *testing.T) {
	tn := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		SrcLabel: 123 | identity.IdentityScopeLocal,
		DstLabel: 456 | identity.IdentityScopeLocal,
	}
	data, err := testutils.CreateL3L4Payload(tn)
	require.NoError(t, err)
	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
			return &identity.Identity{Labels: labels.NewLabelsFromModel([]string{"unspec:some=label", "cidr:1.2.3.4/12", "cidr:1.2.3.4/11"})}, nil
		},
	}

	parser, err := New(hivetest.Logger(t), nil, identityGetter, nil, nil, nil, nil)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, []string{"cidr:1.2.3.4/12", "unspec:some=label"}, f.GetSource().GetLabels())
	assert.Equal(t, []string{"cidr:1.2.3.4/12", "unspec:some=label"}, f.GetDestination().GetLabels())
}

func TestDecodeTrafficDirection(t *testing.T) {
	localIP := netip.MustParseAddr("1.2.3.4")
	localEP := uint16(1234)
	hostEP := uint16(0x1092)
	remoteIP := netip.MustParseAddr("5.6.7.8")
	remoteID := identity.NumericIdentity(5678)

	policyLabel := labels.LabelArrayList{labels.ParseLabelArray("foo=bar")}
	policyKey := policy.EgressKey().WithIdentity(remoteID)
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			if ip == localIP {
				return &testutils.FakeEndpointInfo{
					ID: uint64(localEP),
					PolicyMap: map[policyTypes.Key]string{
						policyKey: policyLabel.String(),
					},
					PolicyRevision: 1,
				}, true
			}
			return nil, false
		},
	}

	parser, err := New(hivetest.Logger(t), endpointGetter, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	parseFlow := func(event any, srcIPv4, dstIPv4 netip.Addr) *flowpb.Flow {
		data, err := testutils.CreateL3L4Payload(event,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
				DstMAC:       net.HardwareAddr{7, 8, 9, 0, 1, 2},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{SrcIP: srcIPv4.AsSlice(), DstIP: dstIPv4.AsSlice()})
		require.NoError(t, err)
		f := &flowpb.Flow{}
		err = parser.Decode(data, f)
		require.NoError(t, err)
		return f
	}

	// DROP at unknown endpoint
	dn := monitor.DropNotify{
		Type:    byte(monitorAPI.MessageTypeDrop),
		Version: monitor.DropNotifyVersion2,
	}
	f := parseFlow(dn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// DROP Egress
	dn = monitor.DropNotify{
		Type:    byte(monitorAPI.MessageTypeDrop),
		Source:  localEP,
		Version: monitor.DropNotifyVersion2,
	}
	f = parseFlow(dn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// DROP Ingress
	dn = monitor.DropNotify{
		Type:    byte(monitorAPI.MessageTypeDrop),
		Source:  localEP,
		Version: monitor.DropNotifyVersion2,
	}
	f = parseFlow(dn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())

	// TRACE_TO_LXC at unknown endpoint
	tn := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		ObsPoint: monitorAPI.TraceToLxc,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_LXC Egress
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceToLxc,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TO_NETWORK Egress (SNAT)
	tnv1 := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   hostEP,
		ObsPoint: monitorAPI.TraceToNetwork,
		Version:  monitor.TraceNotifyVersion1,
		OrigIP:   types.IPv6{1, 2, 3, 4}, // localIP
	}
	f = parseFlow(tnv1, netip.MustParseAddr("10.11.12.13"), remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_LXC Egress, reversed by CT_REPLY
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceToLxc,
		Reason:   monitor.TraceReasonCtReply,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_HOST Ingress
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceToHost,
	}
	f = parseFlow(tn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())

	// TRACE_TO_HOST Ingress, reversed by CT_REPLY
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceToHost,
		Reason:   monitor.TraceReasonCtReply,
	}
	f = parseFlow(tn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())

	// TRACE_FROM_LXC unknown
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceFromLxc,
		Reason:   monitor.TraceReasonUnknown,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_FROM_LXC unknown (encrypted)
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceFromLxc,
		Reason:   monitor.TraceReasonUnknown | monitor.TraceReasonEncryptMask,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_STACK Encrypt Overlay
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   hostEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonEncryptOverlay,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_STACK SRV6 decap Ingress
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   hostEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonSRv6Decap,
	}
	f = parseFlow(tn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())

	// TRACE_TO_STACK SRV6 encap Egress
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonSRv6Encap,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// PolicyVerdictNotify Egress
	pvn := monitor.PolicyVerdictNotify{
		Type:        byte(monitorAPI.MessageTypePolicyVerdict),
		Source:      localEP,
		Flags:       monitorAPI.PolicyEgress,
		RemoteLabel: remoteID,
	}
	f = parseFlow(pvn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	ep, ok := endpointGetter.GetEndpointInfo(localIP)
	assert.True(t, ok)
	strLbls, rev, ok := ep.GetRealizedPolicyRuleLabelsForKey(
		policy.KeyForDirection(directionFromProto(f.GetTrafficDirection())).
			WithIdentity(identity.NumericIdentity(f.GetDestination().GetIdentity())))
	assert.True(t, ok)
	lbls := labels.LabelArrayListFromString(strLbls)
	assert.Equal(t, lbls, policyLabel)
	assert.Equal(t, uint64(1), rev)

	// PolicyVerdictNotify Ingress
	pvn = monitor.PolicyVerdictNotify{
		Type:   byte(monitorAPI.MessageTypePolicyVerdict),
		Source: localEP,
		Flags:  monitorAPI.PolicyIngress,
	}
	f = parseFlow(pvn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())
}

func TestDecodeIsReply(t *testing.T) {
	localIP := net.ParseIP("1.2.3.4")
	localEP := uint16(1234)
	hostEP := uint16(0x1092)
	remoteIP := net.ParseIP("5.6.7.8")

	parser, err := New(hivetest.Logger(t), nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	parseFlow := func(event any, srcIPv4, dstIPv4 net.IP) *flowpb.Flow {
		data, err := testutils.CreateL3L4Payload(event,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
				DstMAC:       net.HardwareAddr{7, 8, 9, 0, 1, 2},
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{SrcIP: srcIPv4, DstIP: dstIPv4})
		require.NoError(t, err)
		f := &flowpb.Flow{}
		err = parser.Decode(data, f)
		require.NoError(t, err)
		return f
	}

	// TRACE_TO_LXC
	tn := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		ObsPoint: monitorAPI.TraceToLxc,
		Reason:   monitor.TraceReasonCtReply,
	}
	f := parseFlow(tn, localIP, remoteIP)
	assert.NotNil(t, f.GetIsReply())
	assert.True(t, f.GetIsReply().GetValue())
	assert.True(t, f.GetReply())

	// TRACE_FROM_LXC
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		ObsPoint: monitorAPI.TraceFromLxc,
		Reason:   monitor.TraceReasonUnknown,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// TRACE_FROM_LXC encrypted
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		ObsPoint: monitorAPI.TraceFromLxc,
		Reason:   monitor.TraceReasonUnknown | monitor.TraceReasonEncryptMask,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// TRACE_TO_STACK srv6-decap
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   hostEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonSRv6Decap,
	}
	f = parseFlow(tn, remoteIP, localIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// TRACE_TO_STACK srv6-decap (encrypted)
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   hostEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonSRv6Decap | monitor.TraceReasonEncryptMask,
	}
	f = parseFlow(tn, remoteIP, localIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// TRACE_TO_STACK srv6-encap
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonSRv6Encap,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// TRACE_TO_STACK srv6-encap (encrypted)
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonSRv6Encap | monitor.TraceReasonEncryptMask,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// TRACE_TO_STACK Encrypted Overlay
	tn = monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   hostEP,
		ObsPoint: monitorAPI.TraceToStack,
		Reason:   monitor.TraceReasonEncryptOverlay,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// PolicyVerdictNotify forward statically assumes is_reply=false
	pvn := monitor.PolicyVerdictNotify{
		Type:    byte(monitorAPI.MessageTypePolicyVerdict),
		Verdict: 0,
	}
	f = parseFlow(pvn, localIP, remoteIP)
	assert.NotNil(t, f.GetIsReply())
	assert.False(t, f.GetIsReply().GetValue())
	assert.False(t, f.GetReply())

	// PolicyVerdictNotify drop statically assumes is_reply=unknown
	pvn = monitor.PolicyVerdictNotify{
		Type:    byte(monitorAPI.MessageTypePolicyVerdict),
		Verdict: -151, // drop reason: Stale or unroutable IP
	}
	f = parseFlow(pvn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())

	// DropNotify statically assumes is_reply=unknown
	dn := monitor.DropNotify{
		Type: byte(monitorAPI.MessageTypeDrop),
	}
	f = parseFlow(dn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.False(t, f.GetReply())
}

func Test_filterCIDRLabels(t *testing.T) {
	type args struct {
		labels []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "mixed",
			args: args{
				labels: []string{
					"b",
					"cidr:1.1.1.1/23",
					"a",
					"d",
					"cidr:1.1.1.1/24",
				},
			},
			want: []string{"b", "a", "d", "cidr:1.1.1.1/24"},
		}, {
			name: "mixed, IPv6",
			args: args{
				labels: []string{
					"b",
					"cidr:2a00-1450-400a-800--0/85", // - is used instead of : in the address because labels cannot contain :
					"a",
					"d",
					"cidr:2a00-1450-400a-800--0/107",
				},
			},
			want: []string{"b", "a", "d", "cidr:2a00-1450-400a-800--0/107"},
		}, {
			name: "no-cidr",
			args: args{
				labels: []string{"b", "c", "a"},
			},
			want: []string{"b", "c", "a"},
		}, {
			name: "cidr-only",
			args: args{
				labels: []string{
					"cidr:1.1.1.1/0",
					"cidr:1.1.1.1/32",
					"cidr:1.1.1.1/16",
				},
			},
			want: []string{"cidr:1.1.1.1/32"},
		}, {
			name: "cidr-only, IPv6",
			args: args{
				labels: []string{
					"cidr:2a00-1450-400a-800--0/85", // - is used instead of : in the address because labels cannot contain :
					"cidr:2a00-1450-400a-800--0/95",
					"cidr:2a00-1450-400a-800--0/107",
				},
			},
			want: []string{"cidr:2a00-1450-400a-800--0/107"},
		}, {
			name: "empty",
			args: args{
				labels: []string{},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.FilterCIDRLabels(hivetest.Logger(t), tt.args.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTraceNotifyOriginalIP(t *testing.T) {
	f := &flowpb.Flow{}
	parser, err := New(hivetest.Logger(t), &testutils.NoopEndpointGetter, nil, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	v0 := monitor.TraceNotify{
		Type:    byte(monitorAPI.MessageTypeTrace),
		Version: monitor.TraceNotifyVersion0,
	}
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP: net.ParseIP("10.0.0.2"),
		DstIP: net.ParseIP("10.0.0.3"),
	}
	data, err := testutils.CreateL3L4Payload(v0, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)

	err = parser.Decode(data, f)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", f.IP.Source)
	assert.Empty(t, f.IP.SourceXlated)

	v1 := monitor.TraceNotify{
		Type:    byte(monitorAPI.MessageTypeTrace),
		Version: monitor.TraceNotifyVersion1,
		OrigIP:  [16]byte{1, 1, 1, 1},
	}
	data, err = testutils.CreateL3L4Payload(v1, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)
	err = parser.Decode(data, f)
	require.NoError(t, err)
	assert.Equal(t, "1.1.1.1", f.IP.Source)
	assert.Equal(t, "10.0.0.2", f.IP.SourceXlated)

	v1 = monitor.TraceNotify{
		Type:    byte(monitorAPI.MessageTypeTrace),
		Version: monitor.TraceNotifyVersion1,
		OrigIP:  [16]byte{10, 0, 0, 2},
	}
	data, err = testutils.CreateL3L4Payload(v1, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)
	err = parser.Decode(data, f)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.2", f.IP.Source)
	assert.Empty(t, f.IP.SourceXlated)
}

func TestICMP(t *testing.T) {
	parser, err := New(hivetest.Logger(t), &testutils.NoopEndpointGetter, nil, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)
	message := monitor.TraceNotify{
		Type:    byte(monitorAPI.MessageTypeTrace),
		Version: monitor.TraceNotifyVersion1,
	}

	// icmpv4
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP:    net.ParseIP("10.0.0.2"),
		DstIP:    net.ParseIP("10.0.0.3"),
		Protocol: layers.IPProtocolICMPv4,
	}
	icmpv4 := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(1, 2),
	}
	v4data, err := testutils.CreateL3L4Payload(message, &eth, &ip, &icmpv4)
	require.NoError(t, err)
	v4flow := &flowpb.Flow{}
	err = parser.Decode(v4data, v4flow)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), v4flow.GetL4().GetICMPv4().Type)
	assert.Equal(t, uint32(2), v4flow.GetL4().GetICMPv4().Code)

	// icmpv4
	ethv6 := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv6,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{2, 3, 4, 5, 6, 7},
	}
	ipv6 := layers.IPv6{
		Version:    0x6,
		NextHeader: 0x3a,
		SrcIP:      net.ParseIP("::"),
		DstIP:      net.ParseIP("::"),
	}
	icmpv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(3, 4),
	}
	v6data, err := testutils.CreateL3L4Payload(message, &ethv6, &ipv6, &icmpv6)
	require.NoError(t, err)
	v6flow := &flowpb.Flow{}
	err = parser.Decode(v6data, v6flow)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), v6flow.GetL4().GetICMPv6().Type)
	assert.Equal(t, uint32(4), v6flow.GetL4().GetICMPv6().Code)
}

func TestTraceNotifyLocalEndpoint(t *testing.T) {
	f := &flowpb.Flow{}

	ep := &testutils.FakeEndpointInfo{
		ID:           1234,
		Identity:     4567,
		IPv4:         net.ParseIP("1.1.1.1"),
		PodName:      "xwing",
		PodNamespace: "kube-system",
		Labels: []string{
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.kubernetes.pod.namespace=kube-system",
			"k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=kube-system",
			"k8s:org=alliance",
			"k8s:class=xwing",
			"k8s:app.kubernetes.io/name=xwing",
		},
	}
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			return ep, true
		},
	}

	parser, err := New(hivetest.Logger(t), endpointGetter, nil, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	v0 := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		SrcLabel: 456, // takes precedence over ep.Identity
		Version:  monitor.TraceNotifyVersion0,
	}

	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP:    net.ParseIP("10.0.0.2"),
		DstIP:    net.ParseIP("10.0.0.3"),
		Protocol: layers.IPProtocolTCP,
	}
	data, err := testutils.CreateL3L4Payload(v0, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)

	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, uint32(ep.ID), f.Source.ID)
	assert.Equal(t, uint32(v0.SrcLabel), f.Source.Identity)
	assert.Equal(t, "default", f.GetSource().GetClusterName())
	assert.Equal(t, ep.PodNamespace, f.Source.Namespace)
	assert.Equal(t, common.SortAndFilterLabels(hivetest.Logger(t), ep.Labels, ep.Identity), f.Source.Labels)
	assert.Equal(t, ep.PodName, f.Source.PodName)
}

func TestDebugCapture(t *testing.T) {
	f := &flowpb.Flow{}

	parser, err := New(hivetest.Logger(t), &testutils.NoopEndpointGetter, &testutils.NoopIdentityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	// The testutils.NoopLinkGetter above will mock out the device name
	// lookup to always return 'lo', so we can just hardcode it here and
	// check that the events below get decoded with this link name.
	loIfName := "lo"
	loIfIndex := uint32(1)

	dbg := monitor.DebugCapture{
		Type:    monitorAPI.MessageTypeCapture,
		SubType: monitor.DbgCaptureDelivery,
		Arg1:    loIfIndex,
	}

	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP:    net.ParseIP("10.0.0.2"),
		DstIP:    net.ParseIP("10.0.0.3"),
		Protocol: layers.IPProtocolTCP,
	}
	data, err := testutils.CreateL3L4Payload(dbg, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)

	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(dbg.Type), f.EventType.Type)
	assert.Equal(t, int32(dbg.SubType), f.EventType.SubType)
	assert.Equal(t, flowpb.DebugCapturePoint_DBG_CAPTURE_DELIVERY, f.DebugCapturePoint)
	assert.Equal(t, ip.SrcIP.String(), f.IP.Source)
	assert.Equal(t, ip.DstIP.String(), f.IP.Destination)
	assert.NotNil(t, f.L4.GetTCP())

	assert.Equal(t, &flowpb.NetworkInterface{
		Index: loIfIndex,
		Name:  loIfName,
	}, f.Interface)

	nilParser, err := New(hivetest.Logger(t), nil, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	err = nilParser.Decode(data, f)
	require.NoError(t, err)

	dbg = monitor.DebugCapture{
		Type:    monitorAPI.MessageTypeCapture,
		SubType: monitor.DbgCaptureProxyPost,
		Arg1:    byteorder.HostToNetwork32(1234),
	}
	data, err = testutils.CreateL3L4Payload(dbg)
	require.NoError(t, err)

	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(dbg.Type), f.EventType.Type)
	assert.Equal(t, int32(dbg.SubType), f.EventType.SubType)
	assert.Equal(t, flowpb.DebugCapturePoint_DBG_CAPTURE_PROXY_POST, f.DebugCapturePoint)
	assert.Equal(t, uint32(1234), f.ProxyPort)

	err = nilParser.Decode(data, f)
	require.NoError(t, err)
}

func TestTraceNotifyProxyPort(t *testing.T) {
	f := &flowpb.Flow{}
	parser, err := New(hivetest.Logger(t), &testutils.NoopEndpointGetter, nil, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	v0 := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Version:  monitor.TraceNotifyVersion0,
		ObsPoint: monitorAPI.TraceToProxy,
		DstID:    uint16(1234),
	}
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP: net.ParseIP("10.0.0.2"),
		DstIP: net.ParseIP("10.0.0.3"),
	}
	data, err := testutils.CreateL3L4Payload(v0, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)

	err = parser.Decode(data, f)
	require.NoError(t, err)
	assert.Equal(t, uint32(1234), f.ProxyPort)

	v1 := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Version:  monitor.TraceNotifyVersion1,
		ObsPoint: monitorAPI.TraceToProxy,
		DstID:    uint16(4321),
		OrigIP:   [16]byte{1, 1, 1, 1},
	}
	data, err = testutils.CreateL3L4Payload(v1, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)
	err = parser.Decode(data, f)
	require.NoError(t, err)
	assert.Equal(t, uint32(4321), f.ProxyPort)
}

func TestDecode_DropNotify(t *testing.T) {
	parser, err := New(hivetest.Logger(t), defaultEndpointGetter, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	template := &flowpb.Flow{
		EventType:   &flowpb.CiliumEventType{Type: 1},
		Summary:     flowpb.IPVersion_IPv4.String(),
		Type:        flowpb.FlowType_L3_L4,
		Verdict:     flowpb.Verdict_DROPPED,
		Source:      &flowpb.Endpoint{},
		Destination: &flowpb.Endpoint{},
		Ethernet: &flowpb.Ethernet{
			Source:      srcMAC.String(),
			Destination: dstMAC.String(),
		},
		IP: &flowpb.IP{
			IpVersion:   flowpb.IPVersion_IPv4,
			Source:      localIP.String(),
			Destination: remoteIP.String(),
		},
	}

	testCases := []struct {
		name    string
		event   monitor.DropNotify
		ipTuple ipTuple
		want    *flowpb.Flow
	}{
		{
			name: "drop_unknown",
			event: monitor.DropNotify{
				Type:    byte(monitorAPI.MessageTypeDrop),
				File:    2,
				Line:    42,
				Version: monitor.DropNotifyVersion2,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				Source: &flowpb.Endpoint{ID: 1234},
				File: &flowpb.FileInfo{
					Name: "bpf_lxc.c",
					Line: 42,
				},
			},
		},
		{
			name: "drop_egress",
			event: monitor.DropNotify{
				Type:    byte(monitorAPI.MessageTypeDrop),
				Source:  localEP,
				File:    6,
				Line:    12,
				Version: monitor.DropNotifyVersion2,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				Source:           &flowpb.Endpoint{ID: 1234},
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
				File: &flowpb.FileInfo{
					Name: "bpf_network.c",
					Line: 12,
				},
			},
		},
		{
			name: "drop_ingress",
			event: monitor.DropNotify{
				Type:    byte(monitorAPI.MessageTypeDrop),
				Source:  localEP,
				File:    4,
				Line:    44,
				Version: monitor.DropNotifyVersion2,
			},
			ipTuple: ingressTuple,
			want: &flowpb.Flow{
				IP: &flowpb.IP{
					Source:      remoteIP.String(),
					Destination: localIP.String(),
				},
				Destination: &flowpb.Endpoint{
					ID: uint32(localEP),
				},
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
				File: &flowpb.FileInfo{
					Name: "bpf_xdp.c",
					Line: 44,
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want := proto.Clone(template)
			proto.Merge(want, tc.want)

			data, err := testutils.CreateL3L4Payload(tc.event,
				&layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{SrcIP: tc.ipTuple.src.AsSlice(), DstIP: tc.ipTuple.dst.AsSlice()},
			)
			if err != nil {
				t.Fatalf("Unexpected error from CreateL3L4Payload(%T, ...): %v", tc.event, err)
			}

			got := &flowpb.Flow{}
			if err := parser.Decode(data, got); err != nil {
				t.Fatalf("Unexpected error from Decode(data, %T): %v", got, err)
			}

			opts := []cmp.Option{
				protocmp.Transform(),
				protocmp.IgnoreFields(&flowpb.Flow{}, "reply"),
			}
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("Unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecode_TraceNotify(t *testing.T) {
	parser, err := New(hivetest.Logger(t), defaultEndpointGetter, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	getTemplate := func(isL3Device bool) *flowpb.Flow {
		template := &flowpb.Flow{
			EventType:   &flowpb.CiliumEventType{Type: 4},
			Summary:     flowpb.IPVersion_IPv4.String(),
			Type:        flowpb.FlowType_L3_L4,
			Verdict:     flowpb.Verdict_FORWARDED,
			Source:      &flowpb.Endpoint{},
			Destination: &flowpb.Endpoint{},
			Ethernet: &flowpb.Ethernet{
				Source:      srcMAC.String(),
				Destination: dstMAC.String(),
			},
			IP: &flowpb.IP{
				IpVersion:   flowpb.IPVersion_IPv4,
				Source:      localIP.String(),
				Destination: remoteIP.String(),
			},
			TraceObservationPoint: flowpb.TraceObservationPoint_TO_ENDPOINT,
		}
		if isL3Device {
			template.Ethernet = nil
		}
		return template
	}

	testCases := []struct {
		name    string
		event   any
		ipTuple ipTuple
		want    *flowpb.Flow
	}{
		{
			name: "v0_unknown",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				ObsPoint: monitorAPI.TraceToLxc,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				Source:      &flowpb.Endpoint{ID: 1234},
				IsReply:     wrapperspb.Bool(false),
				TraceReason: flowpb.TraceReason_NEW,
			},
		},
		{
			name: "v0_to_lxc",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceToLxc,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				Source:           &flowpb.Endpoint{ID: 1234},
				IsReply:          wrapperspb.Bool(false),
				TraceReason:      flowpb.TraceReason_NEW,
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
			},
		},
		{
			name: "v1_to_network",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   hostEP,
				ObsPoint: monitorAPI.TraceToNetwork,
				Version:  monitor.TraceNotifyVersion1,
				OrigIP:   types.IPv6{1, 2, 3, 4}, // localIP
			},
			ipTuple: xlatedEgressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 11,
				},
				IP: &flowpb.IP{
					SourceXlated: xlatedIP.String(),
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				IsReply:               wrapperspb.Bool(false),
				TraceReason:           flowpb.TraceReason_NEW,
				TrafficDirection:      flowpb.TrafficDirection_EGRESS,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_NETWORK,
			},
		},
		{
			name: "v1_to_crypto",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   hostEP,
				ObsPoint: monitorAPI.TraceToCrypto,
				Version:  monitor.TraceNotifyVersion1,
				Reason:   monitor.TraceReasonUnknown,
				Flags:    monitor.TraceNotifyFlagIsL3Device,
				OrigIP:   types.IPv6{1, 2, 3, 4},
			},
			ipTuple: xlatedEgressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 13,
				},
				IP: &flowpb.IP{
					SourceXlated: xlatedIP.String(),
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceReason:           flowpb.TraceReason_TRACE_REASON_UNKNOWN,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_CRYPTO,
			},
		},
		{
			name: "v1_from_crypto",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   hostEP,
				ObsPoint: monitorAPI.TraceFromCrypto,
				Version:  monitor.TraceNotifyVersion1,
				Reason:   monitor.TraceReasonUnknown,
				Flags:    monitor.TraceNotifyFlagIsL3Device,
				OrigIP:   types.IPv6{1, 2, 3, 4},
			},
			ipTuple: xlatedEgressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 12,
				},
				IP: &flowpb.IP{
					SourceXlated: xlatedIP.String(),
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceReason:           flowpb.TraceReason_TRACE_REASON_UNKNOWN,
				TraceObservationPoint: flowpb.TraceObservationPoint_FROM_CRYPTO,
			},
		},
		{
			name: "v0_to_lxc_reply",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceToLxc,
				Reason:   monitor.TraceReasonCtReply,
			},
			ipTuple: xlatedEgressTuple,
			want: &flowpb.Flow{
				IP: &flowpb.IP{
					Source: xlatedIP.String(),
				},
				TrafficDirection:      flowpb.TrafficDirection_EGRESS,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_ENDPOINT,
				IsReply:               wrapperspb.Bool(true),
				TraceReason:           flowpb.TraceReason_REPLY,
			},
		},
		{
			name: "v0_to_host",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceToHost,
			},
			ipTuple: ingressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 2,
				},
				IP: &flowpb.IP{
					Source:      remoteIP.String(),
					Destination: localIP.String(),
				},
				Destination:           &flowpb.Endpoint{ID: 1234},
				IsReply:               wrapperspb.Bool(false),
				TraceReason:           flowpb.TraceReason_NEW,
				TrafficDirection:      flowpb.TrafficDirection_INGRESS,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_HOST,
			},
		},
		{
			name: "v0_to_host_reply",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceToHost,
				Reason:   monitor.TraceReasonCtReply,
			},
			ipTuple: ingressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 2,
				},
				IP: &flowpb.IP{
					Source:      remoteIP.String(),
					Destination: localIP.String(),
				},
				Destination:           &flowpb.Endpoint{ID: 1234},
				TrafficDirection:      flowpb.TrafficDirection_EGRESS,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_HOST,
				IsReply:               wrapperspb.Bool(true),
				TraceReason:           flowpb.TraceReason_REPLY,
			},
		},
		{
			name: "v0_from_lxc",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceFromLxc,
				Reason:   monitor.TraceReasonUnknown,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 5,
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceObservationPoint: flowpb.TraceObservationPoint_FROM_ENDPOINT,
			},
		},
		{
			name: "v0_from_lxc_encrypted",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceFromLxc,
				Reason:   monitor.TraceReasonUnknown,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 5,
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceObservationPoint: flowpb.TraceObservationPoint_FROM_ENDPOINT,
			},
		},
		{
			name: "v0_unknown_encrypted",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceFromLxc,
				Reason:   monitor.TraceReasonUnknown,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 5,
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceObservationPoint: flowpb.TraceObservationPoint_FROM_ENDPOINT,
			},
		},
		{
			name: "v0_from_lxc_unknown_encrypted",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceFromLxc,
				Reason:   monitor.TraceReasonUnknown | monitor.TraceReasonEncryptMask,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 5,
				},
				IP: &flowpb.IP{
					Encrypted: true,
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceObservationPoint: flowpb.TraceObservationPoint_FROM_ENDPOINT,
			},
		},
		{
			name: "v0_to_stack_encrypt_overlay",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   hostEP,
				ObsPoint: monitorAPI.TraceToStack,
				Reason:   monitor.TraceReasonEncryptOverlay,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 3,
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceReason:           flowpb.TraceReason_ENCRYPT_OVERLAY,
				TrafficDirection:      flowpb.TrafficDirection_EGRESS,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_STACK,
			},
		},
		{
			name: "v0_to_stack_srv6_decap",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   hostEP,
				ObsPoint: monitorAPI.TraceToStack,
				Reason:   monitor.TraceReasonSRv6Decap,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 3,
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceReason:           flowpb.TraceReason_SRV6_DECAP,
				TrafficDirection:      flowpb.TrafficDirection_INGRESS,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_STACK,
			},
		},
		{
			name: "v0_to_stack_srv6_encap",
			event: monitor.TraceNotify{
				Type:     byte(monitorAPI.MessageTypeTrace),
				Source:   localEP,
				ObsPoint: monitorAPI.TraceToStack,
				Reason:   monitor.TraceReasonSRv6Encap,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				EventType: &flowpb.CiliumEventType{
					SubType: 3,
				},
				Source:                &flowpb.Endpoint{ID: 1234},
				TraceReason:           flowpb.TraceReason_SRV6_ENCAP,
				TrafficDirection:      flowpb.TrafficDirection_EGRESS,
				TraceObservationPoint: flowpb.TraceObservationPoint_TO_STACK,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isL3Device := false
			if ev, ok := tc.event.(monitor.TraceNotify); ok {
				isL3Device = ev.IsL3Device()
			}

			var l []gopacket.SerializableLayer
			if !isL3Device {
				l = append(l, &layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				})
			}
			l = append(l, &layers.IPv4{SrcIP: tc.ipTuple.src.AsSlice(), DstIP: tc.ipTuple.dst.AsSlice()})

			want := proto.Clone(getTemplate(isL3Device))
			proto.Merge(want, tc.want)

			data, err := testutils.CreateL3L4Payload(tc.event, l...)
			if err != nil {
				t.Fatalf("Unexpected error from CreateL3L4Payload(%T, ...): %v", tc.event, err)
			}

			got := &flowpb.Flow{}
			if err := parser.Decode(data, got); err != nil {
				t.Fatalf("Unexpected error from Decode(data, %T): %v", got, err)
			}

			opts := []cmp.Option{
				protocmp.Transform(),
				protocmp.IgnoreFields(&flowpb.Flow{}, "reply"),
			}
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("Unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecode_PolicyVerdictNotify(t *testing.T) {
	parser, err := New(hivetest.Logger(t), defaultEndpointGetter, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	template := &flowpb.Flow{
		EventType:   &flowpb.CiliumEventType{Type: 5},
		Summary:     flowpb.IPVersion_IPv4.String(),
		Type:        flowpb.FlowType_L3_L4,
		Verdict:     flowpb.Verdict_FORWARDED,
		Source:      &flowpb.Endpoint{},
		Destination: &flowpb.Endpoint{},
		Ethernet: &flowpb.Ethernet{
			Source:      srcMAC.String(),
			Destination: dstMAC.String(),
		},
		IP: &flowpb.IP{
			IpVersion:   flowpb.IPVersion_IPv4,
			Source:      localIP.String(),
			Destination: remoteIP.String(),
		},
		IsReply: wrapperspb.Bool(false),
	}

	testCases := []struct {
		name    string
		event   any
		ipTuple ipTuple
		want    *flowpb.Flow
	}{
		{
			name: "egress",
			event: monitor.PolicyVerdictNotify{
				Type:        byte(monitorAPI.MessageTypePolicyVerdict),
				Source:      localEP,
				Flags:       monitorAPI.PolicyEgress,
				RemoteLabel: identity.NumericIdentity(remoteID),
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				Source:           &flowpb.Endpoint{ID: 1234},
				Destination:      &flowpb.Endpoint{Identity: 5678},
				TrafficDirection: flowpb.TrafficDirection_EGRESS,
			},
		},
		{
			name: "ingresss",
			event: monitor.PolicyVerdictNotify{
				Type:   byte(monitorAPI.MessageTypePolicyVerdict),
				Source: localEP,
				Flags:  monitorAPI.PolicyIngress,
			},
			ipTuple: egressTuple,
			want: &flowpb.Flow{
				Source:           &flowpb.Endpoint{ID: 1234},
				TrafficDirection: flowpb.TrafficDirection_INGRESS,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			want := proto.Clone(template)
			proto.Merge(want, tc.want)

			data, err := testutils.CreateL3L4Payload(tc.event,
				&layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{SrcIP: tc.ipTuple.src.AsSlice(), DstIP: tc.ipTuple.dst.AsSlice()},
			)
			if err != nil {
				t.Fatalf("Unexpected error from CreateL3L4Payload(%T, ...): %v", tc.event, err)
			}

			got := &flowpb.Flow{}
			if err := parser.Decode(data, got); err != nil {
				t.Fatalf("Unexpected error from Decode(data, %T): %v", got, err)
			}

			opts := []cmp.Option{
				protocmp.Transform(),
				protocmp.IgnoreFields(&flowpb.Flow{}, "reply"),
			}
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("Unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
