// Copyright 2019 Authors of Hubble
// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package threefour

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/byteorder"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/source"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(ioutil.Discard)
}

func TestL34Decode(t *testing.T) {
	//SOURCE          					DESTINATION           TYPE   SUMMARY
	//192.168.33.11:6443(sun-sr-https)  10.16.236.178:54222   L3/4   TCP Flags: ACK
	d := []byte{
		4, 7, 0, 0, 7, 124, 26, 57, 66, 0, 0, 0, 66, 0, 0, 0, 1, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 246, 141, 178, 45, 33, 217, 246, 141, 178,
		45, 33, 217, 8, 0, 69, 0, 0, 52, 234, 28, 64, 0, 64, 6, 120, 49, 192,
		168, 33, 11, 10, 16, 236, 178, 25, 43, 211, 206, 42, 239, 210, 28, 180,
		152, 129, 103, 128, 16, 1, 152, 216, 156, 0, 0, 1, 1, 8, 10, 0, 90, 176,
		98, 0, 90, 176, 97, 0, 0}

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip net.IP) (endpoint v1.EndpointInfo, ok bool) {
			if ip.Equal(net.ParseIP("10.16.236.178")) {
				return &testutils.FakeEndpointInfo{
					ID:           1234,
					Identity:     5678,
					PodName:      "pod-10.16.236.178",
					PodNamespace: "default",
				}, true
			}
			return nil, false
		},
	}
	dnsGetter := &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip net.IP) (names []string) {
			if epID == 1234 {
				switch {
				case ip.Equal(net.ParseIP("192.168.33.11")):
					return []string{"host-192.168.33.11"}
				}
			}
			return nil
		},
	}
	ipGetter := &testutils.FakeIPGetter{
		OnGetK8sMetadata: func(ip net.IP) *ipcache.K8sMetadata {
			if ip.String() == "192.168.33.11" {
				return &ipcache.K8sMetadata{
					Namespace: "remote",
					PodName:   "pod-192.168.33.11",
				}
			}
			return nil
		},
		OnLookupSecIDByIP: func(ip net.IP) (ipcache.Identity, bool) {
			// pretend IP belongs to a pod on a remote node
			if ip.String() == "192.168.33.11" {
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
		OnGetServiceByAddr: func(ip net.IP, port uint16) (service flowpb.Service, ok bool) {
			if ip.Equal(net.ParseIP("192.168.33.11")) && (port == 6443) {
				return flowpb.Service{
					Name:      "service-1234",
					Namespace: "remote",
				}, true
			}
			if ip.Equal(net.ParseIP("10.16.236.178")) && (port == 54222) {
				return flowpb.Service{
					Name:      "service-4321",
					Namespace: "default",
				}, true
			}
			return
		},
	}
	identityCache := &testutils.NoopIdentityGetter
	parser, err := New(log, endpointGetter, identityCache, dnsGetter, ipGetter, serviceGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(d, f)
	require.NoError(t, err)

	assert.Equal(t, []string{"host-192.168.33.11"}, f.GetSourceNames())
	assert.Equal(t, "192.168.33.11", f.GetIP().GetSource())
	assert.Equal(t, uint32(6443), f.L4.GetTCP().GetSourcePort())
	assert.Equal(t, "pod-192.168.33.11", f.GetSource().GetPodName())
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

	assert.Equal(t, int32(api.MessageTypeTrace), f.GetEventType().GetType())
	assert.Equal(t, int32(api.TraceFromHost), f.GetEventType().GetSubType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, &flowpb.TCPFlags{ACK: true}, f.L4.GetTCP().GetFlags())

	assert.Equal(t, flowpb.TraceObservationPoint_FROM_HOST, f.GetTraceObservationPoint())

	// ICMP packet so no ports until that support is merged into master
	//
	//SOURCE              DESTINATION          TYPE   SUMMARY
	//ff02::1:ff00:b3e5   f00d::a10:0:0:9195   L3/4
	d2 := []byte{
		4, 5, 168, 11, 95, 22, 242, 184, 86, 0, 0, 0, 86, 0, 0, 0, 104, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 51, 255, 0, 179, 229, 18, 145,
		6, 226, 34, 26, 134, 221, 96, 0, 0, 0, 0, 32, 58, 255, 255, 2, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 1, 255, 0, 179, 229, 240, 13, 0, 0, 0, 0, 0, 0, 10,
		16, 0, 0, 0, 0, 145, 149, 135, 0, 80, 117, 0, 0, 0, 0, 240, 13, 0, 0, 0,
		0, 0, 0, 10, 16, 0, 0, 0, 0, 179, 229, 1, 1, 18, 145, 6, 226, 34, 26, 0,
		0, 0, 0, 0, 0}

	endpointGetter = &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip net.IP) (endpoint v1.EndpointInfo, ok bool) {
			if ip.Equal(net.ParseIP("ff02::1:ff00:b3e5")) {
				return &testutils.FakeEndpointInfo{
					ID: 1234,
				}, true
			}
			return nil, false
		},
	}
	dnsGetter = &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip net.IP) (names []string) {
			if epID == 1234 {
				switch {
				case ip.Equal(net.ParseIP("f00d::a10:0:0:9195")):
					return []string{"host-f00d::a10:0:0:9195"}
				}
			}
			return nil
		},
	}
	ipGetter = &testutils.NoopIPGetter
	serviceGetter = &testutils.NoopServiceGetter
	parser, err = New(log, endpointGetter, identityCache, dnsGetter, ipGetter, serviceGetter)
	require.NoError(t, err)

	err = parser.Decode(d2, f)
	require.NoError(t, err)

	// second packet is ICMPv6 and the flags should be totally wiped out
	assert.Equal(t, []string(nil), f.GetSourceNames())
	assert.Equal(t, "ff02::1:ff00:b3e5", f.GetIP().GetSource())
	assert.Equal(t, &flowpb.ICMPv6{Type: 135}, f.L4.GetICMPv6())
	assert.Equal(t, "", f.GetSource().GetPodName())
	assert.Equal(t, "", f.GetSource().GetNamespace())

	assert.Equal(t, []string{"host-f00d::a10:0:0:9195"}, f.GetDestinationNames())
	assert.Equal(t, "f00d::a10:0:0:9195", f.GetIP().GetDestination())
	assert.Equal(t, "", f.GetDestination().GetPodName())
	assert.Equal(t, "", f.GetDestination().GetNamespace())

	assert.Equal(t, int32(api.MessageTypeTrace), f.GetEventType().GetType())
	assert.Equal(t, int32(api.TraceFromLxc), f.GetEventType().GetSubType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, (*flowpb.TCPFlags)(nil), f.L4.GetTCP().GetFlags())

	assert.Equal(t, flowpb.TraceObservationPoint_FROM_ENDPOINT, f.GetTraceObservationPoint())
}

func BenchmarkL34Decode(b *testing.B) {
	d := []byte{4, 7, 0, 0, 7, 124, 26, 57, 66, 0, 0, 0, 66, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 246, 141, 178, 45, 33, 217, 246, 141,
		178, 45, 33, 217, 8, 0, 69, 0, 0, 52, 234, 28, 64, 0, 64, 6, 120, 49, 192,
		168, 33, 11, 10, 16, 236, 178, 25, 43, 211, 206, 42, 239, 210, 28, 180, 152,
		129, 103, 128, 16, 1, 152, 216, 156, 0, 0, 1, 1, 8, 10, 0, 90, 176, 98, 0,
		90, 176, 97, 0, 0}

	endpointGetter := &testutils.NoopEndpointGetter
	dnsGetter := &testutils.NoopDNSGetter
	ipGetter := &testutils.NoopIPGetter
	serviceGetter := &testutils.NoopServiceGetter
	identityCache := &testutils.NoopIdentityGetter
	parser, err := New(log, endpointGetter, identityCache, dnsGetter, ipGetter, serviceGetter)
	require.NoError(b, err)

	f := &flowpb.Flow{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.Decode(d, f)
	}
}

func TestDecodeTraceNotify(t *testing.T) {
	buf := &bytes.Buffer{}
	tn := monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		SrcLabel: 123,
		DstLabel: 456,
	}
	err := binary.Write(buf, byteorder.Native, &tn)
	require.NoError(t, err)
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6},
			DstMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6},
		},
		&layers.IPv4{
			SrcIP: net.IPv4(1, 2, 3, 4),
			DstIP: net.IPv4(1, 2, 3, 4),
		},
	)
	require.NoError(t, err)
	buf.Write(buffer.Bytes())
	require.NoError(t, err)
	identityGetter := &testutils.FakeIdentityGetter{OnGetIdentity: func(securityIdentity uint32) (*models.Identity, error) {
		if securityIdentity == uint32(tn.SrcLabel) {
			return &models.Identity{Labels: []string{"src=label"}}, nil
		} else if securityIdentity == uint32(tn.DstLabel) {
			return &models.Identity{Labels: []string{"dst=label"}}, nil
		}
		return nil, fmt.Errorf("identity not found for %d", securityIdentity)
	}}

	parser, err := New(log, &testutils.NoopEndpointGetter, identityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(buf.Bytes(), f)
	require.NoError(t, err)
	assert.Equal(t, []string{"src=label"}, f.GetSource().GetLabels())
	assert.Equal(t, []string{"dst=label"}, f.GetDestination().GetLabels())
}

func TestDecodeDropNotify(t *testing.T) {
	buf := &bytes.Buffer{}
	dn := monitor.DropNotify{
		Type:     byte(api.MessageTypeDrop),
		SrcLabel: 123,
		DstLabel: 456,
	}
	err := binary.Write(buf, byteorder.Native, &dn)
	require.NoError(t, err)
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer,
		gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6},
			DstMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6},
		},
		&layers.IPv4{
			SrcIP: net.IPv4(1, 2, 3, 4),
			DstIP: net.IPv4(1, 2, 3, 4),
		},
	)
	require.NoError(t, err)
	buf.Write(buffer.Bytes())
	require.NoError(t, err)
	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*models.Identity, error) {
			if securityIdentity == uint32(dn.SrcLabel) {
				return &models.Identity{Labels: []string{"src=label"}}, nil
			} else if securityIdentity == uint32(dn.DstLabel) {
				return &models.Identity{Labels: []string{"dst=label"}}, nil
			}
			return nil, fmt.Errorf("identity not found for %d", securityIdentity)
		},
	}

	parser, err := New(log, &testutils.NoopEndpointGetter, identityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(buf.Bytes(), f)
	require.NoError(t, err)
	assert.Equal(t, []string{"src=label"}, f.GetSource().GetLabels())
	assert.Equal(t, []string{"dst=label"}, f.GetDestination().GetLabels())
}

func TestDecodePolicyVerdictNotify(t *testing.T) {
	var remoteLabel identity.NumericIdentity = 123
	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*models.Identity, error) {
			if securityIdentity == uint32(remoteLabel) {
				return &models.Identity{Labels: []string{"dst=label"}}, nil
			}
			return nil, fmt.Errorf("identity not found for %d", securityIdentity)
		},
	}

	parser, err := New(log, &testutils.NoopEndpointGetter, identityGetter, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter)
	require.NoError(t, err)

	// PolicyVerdictNotify for forwarded flow
	var flags uint8
	flags |= api.PolicyEgress
	flags |= api.PolicyMatchL3L4 << monitor.PolicyVerdictNotifyFlagMatchTypeBitOffset
	pvn := monitor.PolicyVerdictNotify{
		Type:        byte(api.MessageTypePolicyVerdict),
		SubType:     0,
		Flags:       flags,
		RemoteLabel: remoteLabel,
		Verdict:     0, // CTX_ACT_OK
	}
	data, err := testutils.CreateL3L4Payload(pvn)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(api.MessageTypePolicyVerdict), f.GetEventType().GetType())
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(api.PolicyMatchL3L4), f.GetPolicyMatchType())
	assert.Equal(t, flowpb.Verdict_FORWARDED, f.GetVerdict())
	assert.Equal(t, []string{"dst=label"}, f.GetDestination().GetLabels())

	// PolicyVerdictNotify for dropped flow
	flags = api.PolicyIngress
	pvn = monitor.PolicyVerdictNotify{
		Type:        byte(api.MessageTypePolicyVerdict),
		SubType:     0,
		Flags:       flags,
		RemoteLabel: remoteLabel,
		Verdict:     -151, // drop reason: Stale or unroutable IP
	}
	data, err = testutils.CreateL3L4Payload(pvn)
	require.NoError(t, err)

	f.Reset()
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, int32(api.MessageTypePolicyVerdict), f.GetEventType().GetType())
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(151), f.GetDropReason())
	assert.Equal(t, flowpb.DropReason(151), f.GetDropReasonDesc())
	assert.Equal(t, flowpb.Verdict_DROPPED, f.GetVerdict())
	assert.Equal(t, []string{"dst=label"}, f.GetSource().GetLabels())
}

func TestDecodeDropReason(t *testing.T) {
	reason := uint8(130)
	dn := monitor.DropNotify{
		Type:    byte(api.MessageTypeDrop),
		SubType: reason,
	}
	data, err := testutils.CreateL3L4Payload(dn)
	require.NoError(t, err)

	parser, err := New(log, nil, nil, nil, nil, nil)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, uint32(reason), f.GetDropReason())
	assert.Equal(t, flowpb.DropReason(reason), f.GetDropReasonDesc())
}

func TestDecodeLocalIdentity(t *testing.T) {
	tn := monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		SrcLabel: 123 | identity.LocalIdentityFlag,
		DstLabel: 456 | identity.LocalIdentityFlag,
	}
	data, err := testutils.CreateL3L4Payload(tn)
	require.NoError(t, err)
	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*models.Identity, error) {
			return &models.Identity{Labels: []string{"some=label", "cidr:1.2.3.4/12", "cidr:1.2.3.4/11"}}, nil
		},
	}

	parser, err := New(log, nil, identityGetter, nil, nil, nil)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, []string{"cidr:1.2.3.4/12", "some=label"}, f.GetSource().GetLabels())
	assert.Equal(t, []string{"cidr:1.2.3.4/12", "some=label"}, f.GetDestination().GetLabels())
}

func TestDecodeTrafficDirection(t *testing.T) {
	localIP := net.ParseIP("1.2.3.4")
	localEP := uint16(1234)
	remoteIP := net.ParseIP("5.6.7.8")
	remoteID := uint32(5678)

	directionFromProto := func(direction flowpb.TrafficDirection) trafficdirection.TrafficDirection {
		switch direction {
		case flowpb.TrafficDirection_INGRESS:
			return trafficdirection.Ingress
		case flowpb.TrafficDirection_EGRESS:
			return trafficdirection.Egress
		}
		return trafficdirection.Invalid
	}

	type policyGetter interface {
		GetRealizedPolicyRuleLabelsForKey(key policy.Key) (
			derivedFrom labels.LabelArrayList,
			revision uint64,
			ok bool,
		)
	}
	policyLabel := labels.LabelArrayList{labels.ParseLabelArray("foo=bar")}
	policyKey := policy.Key{
		Identity:         remoteID,
		DestPort:         0,
		Nexthdr:          0,
		TrafficDirection: trafficdirection.Egress.Uint8(),
	}

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip net.IP) (endpoint v1.EndpointInfo, ok bool) {
			if ip.Equal(localIP) {
				return &testutils.FakeEndpointInfo{
					ID: uint64(localEP),
					PolicyMap: map[policy.Key]labels.LabelArrayList{
						policyKey: policyLabel,
					},
					PolicyRevision: 1,
				}, true
			}
			return nil, false
		},
	}

	parser, err := New(log, endpointGetter, nil, nil, nil, nil)
	require.NoError(t, err)
	parseFlow := func(event interface{}, srcIPv4, dstIPv4 net.IP) *flowpb.Flow {
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

	// DROP at unknown endpoint
	dn := monitor.DropNotify{
		Type: byte(api.MessageTypeDrop),
	}
	f := parseFlow(dn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// DROP Egress
	dn = monitor.DropNotify{
		Type:   byte(api.MessageTypeDrop),
		Source: localEP,
	}
	f = parseFlow(dn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// DROP Ingress
	dn = monitor.DropNotify{
		Type:   byte(api.MessageTypeDrop),
		Source: localEP,
	}
	f = parseFlow(dn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())

	// TRACE_TO_LXC at unknown endpoint
	tn := monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		ObsPoint: api.TraceToLxc,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_LXC Egress
	tn = monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: api.TraceToLxc,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_LXC Egress, reversed by CT_REPLY
	tn = monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: api.TraceToLxc,
		Reason:   monitor.TraceReasonCtReply,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// TRACE_TO_HOST Ingress
	tn = monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: api.TraceToHost,
	}
	f = parseFlow(tn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())

	// TRACE_TO_HOST Ingress, reversed by CT_REPLY
	tn = monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: api.TraceToHost,
		Reason:   monitor.TraceReasonCtReply,
	}
	f = parseFlow(tn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())

	// TRACE_FROM_LXC (traffic direction not supported)
	tn = monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		Source:   localEP,
		ObsPoint: api.TraceFromLxc,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	// PolicyVerdictNotify Egress
	pvn := monitor.PolicyVerdictNotify{
		Type:        byte(api.MessageTypePolicyVerdict),
		Source:      localEP,
		Flags:       api.PolicyEgress,
		RemoteLabel: identity.NumericIdentity(remoteID),
	}
	f = parseFlow(pvn, localIP, remoteIP)
	assert.Equal(t, flowpb.TrafficDirection_EGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetSource().GetID())

	ep, ok := endpointGetter.GetEndpointInfo(localIP)
	assert.Equal(t, true, ok)
	lbls, rev, ok := ep.(policyGetter).GetRealizedPolicyRuleLabelsForKey(policy.Key{
		Identity:         f.GetDestination().GetIdentity(),
		TrafficDirection: directionFromProto(f.GetTrafficDirection()).Uint8(),
	})
	assert.Equal(t, true, ok)
	assert.Equal(t, lbls, policyLabel)
	assert.Equal(t, uint64(1), rev)

	// PolicyVerdictNotify Ingress
	pvn = monitor.PolicyVerdictNotify{
		Type:   byte(api.MessageTypePolicyVerdict),
		Source: localEP,
		Flags:  api.PolicyIngress,
	}
	f = parseFlow(pvn, remoteIP, localIP)
	assert.Equal(t, flowpb.TrafficDirection_INGRESS, f.GetTrafficDirection())
	assert.Equal(t, uint32(localEP), f.GetDestination().GetID())
}

func TestDecodeIsReply(t *testing.T) {
	localIP := net.ParseIP("1.2.3.4")
	remoteIP := net.ParseIP("5.6.7.8")

	parser, err := New(log, nil, nil, nil, nil, nil)
	require.NoError(t, err)
	parseFlow := func(event interface{}, srcIPv4, dstIPv4 net.IP) *flowpb.Flow {
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
	tn := monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		ObsPoint: api.TraceToLxc,
		Reason:   monitor.TraceReasonCtReply,
	}
	f := parseFlow(tn, localIP, remoteIP)
	assert.NotNil(t, f.GetIsReply())
	assert.Equal(t, true, f.GetIsReply().GetValue())
	assert.Equal(t, true, f.GetReply())

	// TRACE_FROM_LXC (connection tracking not supported)
	tn = monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		ObsPoint: api.TraceFromLxc,
		Reason:   monitor.TraceReasonCtReply,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.Equal(t, false, f.GetReply())

	tn = monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		ObsPoint: api.TraceFromLxc,
		Reason:   0,
	}
	f = parseFlow(tn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.Equal(t, false, f.GetReply())

	// PolicyVerdictNotify forward statically assumes is_reply=false
	pvn := monitor.PolicyVerdictNotify{
		Type:    byte(api.MessageTypePolicyVerdict),
		Verdict: 0,
	}
	f = parseFlow(pvn, localIP, remoteIP)
	assert.NotNil(t, f.GetIsReply())
	assert.Equal(t, false, f.GetIsReply().GetValue())
	assert.Equal(t, false, f.GetReply())

	// PolicyVerdictNotify drop statically assumes is_reply=unknown
	pvn = monitor.PolicyVerdictNotify{
		Type:    byte(api.MessageTypePolicyVerdict),
		Verdict: -151, // drop reason: Stale or unroutable IP
	}
	f = parseFlow(pvn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.Equal(t, false, f.GetReply())

	// DropNotify statically assumes is_reply=unknown
	dn := monitor.DropNotify{
		Type: byte(api.MessageTypeDrop),
	}
	f = parseFlow(dn, localIP, remoteIP)
	assert.Nil(t, f.GetIsReply())
	assert.Equal(t, false, f.GetReply())
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
			got := filterCIDRLabels(log, tt.args.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTraceNotifyOriginalIP(t *testing.T) {
	f := &flowpb.Flow{}
	parser, err := New(log, &testutils.NoopEndpointGetter, nil, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter)
	require.NoError(t, err)

	v0 := monitor.TraceNotifyV0{
		Type:    byte(api.MessageTypeTrace),
		Version: monitor.TraceNotifyVersion0,
	}
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP: net.ParseIP("2.2.2.2"),
		DstIP: net.ParseIP("3.3.3.3"),
	}
	data, err := testutils.CreateL3L4Payload(v0, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)

	err = parser.Decode(data, f)
	require.NoError(t, err)
	assert.Equal(t, f.IP.Source, "2.2.2.2")

	v1 := monitor.TraceNotifyV1{
		TraceNotifyV0: monitor.TraceNotifyV0{
			Type:    byte(api.MessageTypeTrace),
			Version: monitor.TraceNotifyVersion1,
		},
		OrigIP: [16]byte{1, 1, 1, 1},
	}
	data, err = testutils.CreateL3L4Payload(v1, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)
	err = parser.Decode(data, f)
	require.NoError(t, err)
	assert.Equal(t, f.IP.Source, "1.1.1.1")
}

func TestICMP(t *testing.T) {
	parser, err := New(log, &testutils.NoopEndpointGetter, nil, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter)
	require.NoError(t, err)
	message := monitor.TraceNotifyV1{
		TraceNotifyV0: monitor.TraceNotifyV0{
			Type:    byte(api.MessageTypeTrace),
			Version: monitor.TraceNotifyVersion1,
		},
	}

	// icmpv4
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP:    net.ParseIP("2.2.2.2"),
		DstIP:    net.ParseIP("3.3.3.3"),
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
		PodNamespace: "default",
		Labels:       []string{"a", "b", "c"},
	}
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip net.IP) (endpoint v1.EndpointInfo, ok bool) {
			return ep, true
		},
	}

	parser, err := New(log, endpointGetter, nil, &testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter)
	require.NoError(t, err)

	v0 := monitor.TraceNotifyV0{
		Type:     byte(api.MessageTypeTrace),
		SrcLabel: 456, // takes precedence over ep.Identity
		Version:  monitor.TraceNotifyVersion0,
	}

	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP:    net.ParseIP("2.2.2.2"),
		DstIP:    net.ParseIP("3.3.3.3"),
		Protocol: layers.IPProtocolTCP,
	}
	data, err := testutils.CreateL3L4Payload(v0, &eth, &ip, &layers.TCP{})
	require.NoError(t, err)

	err = parser.Decode(data, f)
	require.NoError(t, err)

	assert.Equal(t, uint32(ep.ID), f.Source.ID)
	assert.Equal(t, uint32(v0.SrcLabel), f.Source.Identity)
	assert.Equal(t, ep.PodNamespace, f.Source.Namespace)
	assert.Equal(t, ep.Labels, f.Source.Labels)
	assert.Equal(t, ep.PodName, f.Source.PodName)
}
