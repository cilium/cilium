// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cgroupManager "github.com/cilium/cilium/pkg/cgroups/manager"
	parserErrors "github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/types"
)

func mustParseIP(s string) (res types.IPv6) {
	ip := net.ParseIP(s)
	if ip == nil {
		panic(fmt.Sprintf("failed to parse ip %q", s))
	}
	if v4 := ip.To4(); v4 != nil {
		copy(res[:4], v4)
	} else {
		copy(res[:], ip)
	}
	return res
}

type nodeLabelsCall struct {
	ip   netip.Addr
	hint getters.NodeClusterHint
}

type recordingNodeLabelsGetter struct {
	calls   []nodeLabelsCall
	results [][]string
}

func (g *recordingNodeLabelsGetter) GetNodeLabels(ip netip.Addr, hint getters.NodeClusterHint) []string {
	callIndex := len(g.calls)
	g.calls = append(g.calls, nodeLabelsCall{ip: ip, hint: hint})
	if callIndex < len(g.results) {
		return g.results[callIndex]
	}
	return nil
}

func TestDecodeSockEvent(t *testing.T) {
	const (
		xwingIPv4                 = "192.168.10.10"
		xwingIPv6                 = "f00d::a10:0:0:10"
		xwingCgroupId             = 101010
		xwingIdentity             = 1234
		xwingEndpoint             = 110
		xwingPodName              = "xwing"
		xwingPodNamespace         = "default"
		deathstarIPv4             = "192.168.20.20"
		deathstarIPv6             = "f00d::20:20"
		deathstarServiceV4        = "10.10.20.20"
		deathstarServiceV6        = "f00c::20:20"
		deathstarIdentity         = 5678
		deathstarEndpoint         = 220
		deathstarServicePort      = 8080
		deathstarTargetPort       = 80
		deathstarPodName          = "deathstar-1"
		deathstarPodNamespace     = "default"
		deathstarServiceName      = "deathstar"
		deathstarServiceNamespace = "default"
		deathstarServiceDomain    = "deathstar.default.svc.cluster.local"
		deathstarAltIPv4          = "192.168.20.21"
		deathstarAltIPv6          = "f00d::20:21"
		deathstarAltPodName       = "deathstar-2"
		deathstarAltPodNamespace  = "default"
	)
	var (
		xwingLabels     = []string{"k8s:org=alliance"}
		deathstarLabels = []string{"k8s:org=empire"}
	)

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (endpoint getters.EndpointInfo, ok bool) {
			switch ip.String() {
			case xwingIPv4, xwingIPv6:
				return &testutils.FakeEndpointInfo{
					ID:           xwingEndpoint,
					Identity:     xwingIdentity,
					IPv4:         net.ParseIP(xwingIPv4),
					IPv6:         net.ParseIP(xwingIPv6),
					Labels:       xwingLabels,
					PodName:      xwingPodName,
					PodNamespace: xwingPodNamespace,
				}, true
			case deathstarIPv4, deathstarIPv6:
				return &testutils.FakeEndpointInfo{
					ID:           deathstarEndpoint,
					Identity:     deathstarIdentity,
					IPv4:         net.ParseIP(deathstarIPv4),
					IPv6:         net.ParseIP(deathstarIPv6),
					Labels:       deathstarLabels,
					PodName:      deathstarPodName,
					PodNamespace: deathstarPodNamespace,
				}, true
			}
			return nil, false
		},
	}
	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(securityIdentity uint32) (*identity.Identity, error) {
			switch securityIdentity {
			case xwingIdentity:
				return &identity.Identity{
					ID:     xwingIdentity,
					Labels: labels.NewLabelsFromModel(xwingLabels),
				}, nil
			case deathstarIdentity:
				return &identity.Identity{
					ID:     deathstarIdentity,
					Labels: labels.NewLabelsFromModel(deathstarLabels),
				}, nil
			}
			return nil, errors.New("identity not found")
		},
	}
	dnsGetter := &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip netip.Addr) (names []string) {
			switch epID {
			case xwingEndpoint:
				switch ip.String() {
				case deathstarServiceV4, deathstarServiceV6:
					return []string{deathstarServiceDomain}
				}
			}
			return nil
		},
	}
	ipGetter := &testutils.FakeIPGetter{
		OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
			switch ip.String() {
			case xwingIPv4, xwingIPv6:
				return &ipcache.K8sMetadata{
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
				}
			case deathstarIPv4, deathstarIPv6:
				return &ipcache.K8sMetadata{
					PodName:   deathstarPodName,
					Namespace: deathstarPodNamespace,
				}
			case deathstarAltIPv4, deathstarAltIPv6:
				return &ipcache.K8sMetadata{
					PodName:   deathstarAltPodName,
					Namespace: deathstarAltPodNamespace,
				}
			}
			return nil
		},
		OnLookupSecIDByIP: func(ip netip.Addr) (ipcache.Identity, bool) {
			switch ip.String() {
			case xwingIPv4, xwingIPv6:
				return ipcache.Identity{
					ID: xwingIdentity,
				}, true
			case deathstarIPv4, deathstarIPv6, deathstarAltIPv4, deathstarAltIPv6:
				return ipcache.Identity{
					ID: deathstarIdentity,
				}, true
			}
			return ipcache.Identity{}, false
		},
	}
	serviceGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
			switch ip.String() {
			case deathstarServiceV4, deathstarServiceV6:
				if port == deathstarServicePort {
					return &flowpb.Service{
						Name:      deathstarServiceName,
						Namespace: deathstarServiceNamespace,
					}
				}
			}
			return nil
		},
	}
	cgroupGetter := &testutils.FakePodMetadataGetter{
		OnGetPodMetadataForContainer: func(cgroupId uint64) *cgroupManager.PodMetadata {
			switch cgroupId {
			case xwingCgroupId:
				return &cgroupManager.PodMetadata{
					Name:      xwingPodName,
					Namespace: xwingPodNamespace,
					IPs:       []string{xwingIPv4, xwingIPv6},
				}
			}
			return nil
		},
	}
	tt := []struct {
		name string
		msg  monitor.TraceSockNotify

		opts []options.Option

		rawMsg []byte
		flow   *flowpb.Flow
		errMsg string
	}{
		{
			name:   "empty buffer",
			rawMsg: []byte{},
			errMsg: parserErrors.ErrEmptyData.Error(),
		},
		{
			name:   "invalid buffer",
			rawMsg: []byte{monitorAPI.MessageTypeTraceSock},
			errMsg: "failed to parse sock trace event",
		},
		{
			name:   "empty event",
			msg:    monitor.TraceSockNotify{},
			errMsg: parserErrors.NewErrInvalidType(0).Error(),
		},
		{
			name: "invalid cgroup id",
			msg: monitor.TraceSockNotify{
				Type:       monitorAPI.MessageTypeTraceSock,
				XlatePoint: monitor.XlatePointPreDirectionFwd,
				DstIP:      mustParseIP("10.10.10.10"),
				DstPort:    8080,
				L4Proto:    monitor.L4ProtocolUDP,
				SockCookie: 0xc0ffee,
				CgroupId:   1234,
			},
			errMsg: parserErrors.ErrEventSkipped.Error(),
		},
		{
			name: "minimal",
			msg: monitor.TraceSockNotify{
				Type:       monitorAPI.MessageTypeTraceSock,
				XlatePoint: monitor.XlatePointPreDirectionFwd,
				DstIP:      mustParseIP("10.10.10.10"),
				DstPort:    8080,
				L4Proto:    monitor.L4ProtocolUDP,
				SockCookie: 0xc0ffee,
			},
			opts: []options.Option{options.WithSkipUnknownCGroupIDs(false)},
			flow: &flowpb.Flow{
				Type:    flowpb.FlowType_SOCK,
				Verdict: flowpb.Verdict_TRACED,
				IP: &flowpb.IP{
					Destination: "10.10.10.10",
					IpVersion:   flowpb.IPVersion_IPv4,
				},
				L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{
					DestinationPort: 8080,
				}}},
				Source:      &flowpb.Endpoint{},
				Destination: &flowpb.Endpoint{},
				EventType: &flowpb.CiliumEventType{
					Type:    monitorAPI.MessageTypeTraceSock,
					SubType: monitor.XlatePointPreDirectionFwd,
				},
				SockXlatePoint: monitor.XlatePointPreDirectionFwd,
				SocketCookie:   0xc0ffee,
				Summary:        "UDP",
			},
		},
		{
			name: "pre-translate v4 xwing to service ip",
			msg: monitor.TraceSockNotify{
				Type:       monitorAPI.MessageTypeTraceSock,
				XlatePoint: monitor.XlatePointPreDirectionFwd,
				DstIP:      mustParseIP(deathstarServiceV4),
				DstPort:    deathstarServicePort,
				CgroupId:   xwingCgroupId,
				L4Proto:    monitor.L4ProtocolTCP,
			},
			flow: &flowpb.Flow{
				Type:     flowpb.FlowType_SOCK,
				Verdict:  flowpb.Verdict_TRACED,
				CgroupId: xwingCgroupId,
				IP: &flowpb.IP{
					Source:      xwingIPv4,
					Destination: deathstarServiceV4,
					IpVersion:   flowpb.IPVersion_IPv4,
				},
				L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
					DestinationPort: deathstarServicePort,
				}}},
				Source: &flowpb.Endpoint{
					ID:        xwingEndpoint,
					Identity:  xwingIdentity,
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
					Labels:    xwingLabels,
				},
				Destination:      &flowpb.Endpoint{},
				DestinationNames: []string{deathstarServiceDomain},
				DestinationService: &flowpb.Service{
					Name:      deathstarServiceName,
					Namespace: deathstarServiceNamespace,
				},
				EventType: &flowpb.CiliumEventType{
					Type:    monitorAPI.MessageTypeTraceSock,
					SubType: monitor.XlatePointPreDirectionFwd,
				},
				SockXlatePoint: monitor.XlatePointPreDirectionFwd,
				Summary:        "TCP",
			},
		},
		{
			name: "post-translate v4 xwing to remote pod ip",
			msg: monitor.TraceSockNotify{
				Type:       monitorAPI.MessageTypeTraceSock,
				XlatePoint: monitor.XlatePointPostDirectionFwd,
				DstIP:      mustParseIP(deathstarAltIPv4),
				DstPort:    deathstarTargetPort,
				CgroupId:   xwingCgroupId,
				L4Proto:    monitor.L4ProtocolTCP,
			},
			flow: &flowpb.Flow{
				Type:     flowpb.FlowType_SOCK,
				Verdict:  flowpb.Verdict_TRANSLATED,
				CgroupId: xwingCgroupId,
				IP: &flowpb.IP{
					Source:      xwingIPv4,
					Destination: deathstarAltIPv4,
					IpVersion:   flowpb.IPVersion_IPv4,
				},
				L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
					DestinationPort: deathstarTargetPort,
				}}},
				Source: &flowpb.Endpoint{
					ID:        xwingEndpoint,
					Identity:  xwingIdentity,
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
					Labels:    xwingLabels,
				},
				Destination: &flowpb.Endpoint{
					Identity:  deathstarIdentity,
					PodName:   deathstarAltPodName,
					Namespace: deathstarAltPodNamespace,
					Labels:    deathstarLabels,
				},
				EventType: &flowpb.CiliumEventType{
					Type:    monitorAPI.MessageTypeTraceSock,
					SubType: monitor.XlatePointPostDirectionFwd,
				},
				SockXlatePoint: monitor.XlatePointPostDirectionFwd,
				Summary:        "TCP",
			},
		},
		{
			name: "post-translate rev v6 xwing from service ip",
			msg: monitor.TraceSockNotify{
				Type:       monitorAPI.MessageTypeTraceSock,
				XlatePoint: monitor.XlatePointPostDirectionRev,
				DstIP:      mustParseIP(deathstarServiceV6),
				DstPort:    deathstarServicePort,
				CgroupId:   xwingCgroupId,
				L4Proto:    monitor.L4ProtocolTCP,
				Flags:      monitor.TraceSockNotifyFlagIPv6,
			},
			flow: &flowpb.Flow{
				Type:     flowpb.FlowType_SOCK,
				Verdict:  flowpb.Verdict_TRANSLATED,
				CgroupId: xwingCgroupId,
				IP: &flowpb.IP{
					Source:      deathstarServiceV6,
					Destination: xwingIPv6,
					IpVersion:   flowpb.IPVersion_IPv6,
				},
				L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
					SourcePort: deathstarServicePort,
				}}},
				Source:      &flowpb.Endpoint{},
				SourceNames: []string{deathstarServiceDomain},
				SourceService: &flowpb.Service{
					Name:      deathstarServiceName,
					Namespace: deathstarServiceNamespace,
				},
				Destination: &flowpb.Endpoint{
					ID:        xwingEndpoint,
					Identity:  xwingIdentity,
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
					Labels:    xwingLabels,
				},
				EventType: &flowpb.CiliumEventType{
					Type:    monitorAPI.MessageTypeTraceSock,
					SubType: monitor.XlatePointPostDirectionRev,
				},
				SockXlatePoint: monitor.XlatePointPostDirectionRev,
				Summary:        "TCP",
			},
		},
		{
			name: "custom decoder",
			msg: monitor.TraceSockNotify{
				Type:       monitorAPI.MessageTypeTraceSock,
				XlatePoint: monitor.XlatePointPreDirectionFwd,
				DstIP:      mustParseIP("10.10.10.10"),
				DstPort:    8080,
				L4Proto:    monitor.L4ProtocolUDP,
				SockCookie: 0xc0ffee,
			},
			opts: []options.Option{
				options.WithSkipUnknownCGroupIDs(false),
				options.WithTraceSockNotifyDecoder(func(data []byte, flow *flowpb.Flow) (*monitor.TraceSockNotify, error) {
					flow.Uuid = "coffee"
					return &monitor.TraceSockNotify{
						Type:       monitorAPI.MessageTypeTraceSock,
						XlatePoint: monitor.XlatePointPostDirectionFwd,
						DstIP:      mustParseIP("192.10.21.20"),
						DstPort:    8081,
						L4Proto:    monitor.L4ProtocolUDP,
						SockCookie: 0xdecafbad,
					}, nil
				}),
			},
			flow: &flowpb.Flow{
				Uuid:    "coffee",
				Type:    flowpb.FlowType_SOCK,
				Verdict: flowpb.Verdict_TRANSLATED,
				IP: &flowpb.IP{
					Destination: "192.10.21.20",
					IpVersion:   flowpb.IPVersion_IPv4,
				},
				L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{
					DestinationPort: 8081,
				}}},
				Source:      &flowpb.Endpoint{},
				Destination: &flowpb.Endpoint{},
				EventType: &flowpb.CiliumEventType{
					Type:    monitorAPI.MessageTypeTraceSock,
					SubType: monitor.XlatePointPostDirectionFwd,
				},
				SockXlatePoint: monitor.XlatePointPostDirectionFwd,
				SocketCookie:   0xdecafbad,
				Summary:        "UDP",
			},
		},
	}

	logger := hivetest.Logger(t)

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(logger, endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter, cgroupGetter, tc.opts...)
			assert.NoError(t, err)
			data := tc.rawMsg
			if data == nil {
				buf := &bytes.Buffer{}
				err := binary.Write(buf, binary.NativeEndian, &tc.msg)
				assert.NoError(t, err)
				data = buf.Bytes()
			}
			flow := &flowpb.Flow{}
			err = p.Decode(data, flow)
			if tc.errMsg != "" {
				assert.ErrorContains(t, err, tc.errMsg)
			} else {
				assert.NoError(t, err)
				require.Equal(t, tc.flow, flow)
			}
		})
	}
}

func TestDecodeNodeLabelsUsesLocalSourceProvenance(t *testing.T) {
	const (
		sourceIP = "192.0.2.10"
		destIP   = "198.51.100.20"
		cgroupID = 1010
	)
	localLabels := []string{"topology.kubernetes.io/zone=local-a"}
	getter := &recordingNodeLabelsGetter{results: [][]string{localLabels, nil}}
	cgroupGetter := &testutils.FakePodMetadataGetter{
		OnGetPodMetadataForContainer: func(id uint64) *cgroupManager.PodMetadata {
			require.Equal(t, uint64(cgroupID), id)
			return &cgroupManager.PodMetadata{IPs: []string{sourceIP}}
		},
	}
	parser, err := New(
		hivetest.Logger(t), nil, nil, nil, nil, nil, cgroupGetter,
		options.WithNodeLabelsGetter(getter),
	)
	require.NoError(t, err)

	msg := monitor.TraceSockNotify{
		Type:       monitorAPI.MessageTypeTraceSock,
		XlatePoint: monitor.XlatePointPreDirectionFwd,
		DstIP:      mustParseIP(destIP),
		DstPort:    8080,
		CgroupId:   cgroupID,
		L4Proto:    monitor.L4ProtocolTCP,
	}
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, binary.NativeEndian, &msg))
	decoded := &flowpb.Flow{}
	require.NoError(t, parser.Decode(buf.Bytes(), decoded))

	require.Equal(t, []nodeLabelsCall{
		{
			ip: netip.MustParseAddr(sourceIP),
			hint: getters.NodeClusterHint{
				Identity:      identity.IdentityUnknown,
				IdentityKnown: false,
				LocalEndpoint: true,
			},
		},
		{
			ip: netip.MustParseAddr(destIP),
			hint: getters.NodeClusterHint{
				Identity:      identity.IdentityUnknown,
				IdentityKnown: false,
				LocalEndpoint: false,
			},
		},
	}, getter.calls)
	require.Equal(t, localLabels, decoded.GetSourceNodeLabels())
	require.Empty(t, decoded.GetDestinationNodeLabels())
	require.Same(t, &localLabels[0], &decoded.SourceNodeLabels[0], "getter results must be assigned without copying")
}

func TestDecodeReverseNATSwapsLabelsWithFlowOrientation(t *testing.T) {
	const (
		initialSourceIP = "192.0.2.10"
		initialDestIP   = "198.51.100.20"
		cgroupID        = 1010
		initialSourceEP = 110
		initialDestEP   = 220
	)
	localLabels := []string{"topology.kubernetes.io/zone=local-a"}
	getter := &recordingNodeLabelsGetter{results: [][]string{localLabels, nil}}
	cgroupGetter := &testutils.FakePodMetadataGetter{
		OnGetPodMetadataForContainer: func(id uint64) *cgroupManager.PodMetadata {
			require.Equal(t, uint64(cgroupID), id)
			return &cgroupManager.PodMetadata{IPs: []string{initialSourceIP}}
		},
	}
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(ip netip.Addr) (getters.EndpointInfo, bool) {
			switch ip.String() {
			case initialSourceIP:
				return &testutils.FakeEndpointInfo{ID: initialSourceEP, PodName: "initial-source"}, true
			case initialDestIP:
				return &testutils.FakeEndpointInfo{ID: initialDestEP, PodName: "initial-destination"}, true
			default:
				t.Fatalf("unexpected endpoint lookup for %s", ip)
				return nil, false
			}
		},
	}
	dnsGetter := &testutils.FakeFQDNCache{
		OnGetNamesOf: func(epID uint32, ip netip.Addr) []string {
			switch {
			case epID == initialSourceEP && ip.String() == initialDestIP:
				return []string{"initial-destination.example"}
			case epID == initialDestEP && ip.String() == initialSourceIP:
				return []string{"initial-source.example"}
			default:
				t.Fatalf("unexpected DNS lookup from endpoint %d for %s", epID, ip)
				return nil
			}
		},
	}
	serviceGetter := &testutils.FakeServiceGetter{
		OnGetServiceByAddr: func(ip netip.Addr, port uint16) *flowpb.Service {
			switch {
			case ip.String() == initialDestIP && port == 8080:
				return &flowpb.Service{Name: "initial-destination"}
			case ip.String() == initialSourceIP && port == 0:
				return &flowpb.Service{Name: "initial-source"}
			default:
				t.Fatalf("unexpected service lookup for %s:%d", ip, port)
				return nil
			}
		},
	}
	parser, err := New(
		hivetest.Logger(t), endpointGetter, nil, dnsGetter, nil, serviceGetter, cgroupGetter,
		options.WithNodeLabelsGetter(getter),
	)
	require.NoError(t, err)

	msg := monitor.TraceSockNotify{
		Type:       monitorAPI.MessageTypeTraceSock,
		XlatePoint: monitor.XlatePointPostDirectionRev,
		DstIP:      mustParseIP(initialDestIP),
		DstPort:    8080,
		CgroupId:   cgroupID,
		L4Proto:    monitor.L4ProtocolTCP,
	}
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, binary.NativeEndian, &msg))
	decoded := &flowpb.Flow{}
	require.NoError(t, parser.Decode(buf.Bytes(), decoded))

	require.Equal(t, initialDestIP, decoded.GetIP().GetSource())
	require.Equal(t, initialSourceIP, decoded.GetIP().GetDestination())
	require.Equal(t, uint32(initialDestEP), decoded.GetSource().GetID())
	require.Equal(t, "initial-destination", decoded.GetSource().GetPodName())
	require.Equal(t, uint32(initialSourceEP), decoded.GetDestination().GetID())
	require.Equal(t, "initial-source", decoded.GetDestination().GetPodName())
	require.Equal(t, "initial-destination", decoded.GetSourceService().GetName())
	require.Equal(t, "initial-source", decoded.GetDestinationService().GetName())
	require.Equal(t, []string{"initial-destination.example"}, decoded.GetSourceNames())
	require.Equal(t, []string{"initial-source.example"}, decoded.GetDestinationNames())
	require.Equal(t, []nodeLabelsCall{
		{
			ip: netip.MustParseAddr(initialSourceIP),
			hint: getters.NodeClusterHint{
				Identity:      identity.IdentityUnknown,
				IdentityKnown: false,
				LocalEndpoint: true,
			},
		},
		{
			ip: netip.MustParseAddr(initialDestIP),
			hint: getters.NodeClusterHint{
				Identity:      identity.IdentityUnknown,
				IdentityKnown: false,
				LocalEndpoint: false,
			},
		},
	}, getter.calls)
	require.Empty(t, decoded.GetSourceNodeLabels())
	require.Equal(t, localLabels, decoded.GetDestinationNodeLabels())
	require.Same(t, &localLabels[0], &decoded.DestinationNodeLabels[0], "swapped getter results must be assigned without copying")
}

func TestDecodeNodeLabelsNilGetterPreservesOutputAndClearsReuse(t *testing.T) {
	const (
		sourceIP = "192.0.2.10"
		destIP   = "198.51.100.20"
		cgroupID = 1010
	)
	cgroupGetter := &testutils.FakePodMetadataGetter{
		OnGetPodMetadataForContainer: func(uint64) *cgroupManager.PodMetadata {
			return &cgroupManager.PodMetadata{IPs: []string{sourceIP}}
		},
	}
	msg := monitor.TraceSockNotify{
		Type:       monitorAPI.MessageTypeTraceSock,
		XlatePoint: monitor.XlatePointPreDirectionFwd,
		DstIP:      mustParseIP(destIP),
		DstPort:    8080,
		CgroupId:   cgroupID,
		L4Proto:    monitor.L4ProtocolTCP,
	}
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, binary.NativeEndian, &msg))

	baselineParser, err := New(hivetest.Logger(t), nil, nil, nil, nil, nil, cgroupGetter)
	require.NoError(t, err)
	baseline := &flowpb.Flow{}
	require.NoError(t, baselineParser.Decode(buf.Bytes(), baseline))

	recorder := &recordingNodeLabelsGetter{results: [][]string{{"must-not-be-called"}}}
	nilGetterParser, err := New(
		hivetest.Logger(t), nil, nil, nil, nil, nil, cgroupGetter,
		options.WithNodeLabelsGetter(recorder),
		options.WithNodeLabelsGetter(nil),
	)
	require.NoError(t, err)
	reused := &flowpb.Flow{
		SourceNodeLabels:      []string{"stale-source-label"},
		DestinationNodeLabels: []string{"stale-destination-label"},
	}
	require.NoError(t, nilGetterParser.Decode(buf.Bytes(), reused))

	require.Empty(t, recorder.calls, "a final nil option must disable the getter")
	require.Empty(t, reused.GetSourceNodeLabels())
	require.Empty(t, reused.GetDestinationNodeLabels())
	require.Equal(t, baseline, reused, "nil getter output must match existing socket parser behavior")
}
