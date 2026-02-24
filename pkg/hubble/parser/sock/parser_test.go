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
	"github.com/cilium/cilium/pkg/hubble/ir"
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
		flow   ir.Flow
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
			flow: ir.Flow{
				Type:    flowpb.FlowType_SOCK,
				Verdict: flowpb.Verdict_TRACED,
				IP: ir.IP{
					Destination: net.ParseIP("10.10.10.10"),
					IPVersion:   flowpb.IPVersion_IPv4,
				},
				L4: ir.Layer4{UDP: ir.UDP{
					DestinationPort: 8080,
				}},
				EventType: ir.EventType{
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
			flow: ir.Flow{
				Type:     flowpb.FlowType_SOCK,
				Verdict:  flowpb.Verdict_TRACED,
				CgroupID: xwingCgroupId,
				IP: ir.IP{
					Source:      net.ParseIP(xwingIPv4),
					Destination: net.ParseIP(deathstarServiceV4),
					IPVersion:   flowpb.IPVersion_IPv4,
				},
				L4: ir.Layer4{TCP: ir.TCP{
					DestinationPort: deathstarServicePort,
				}},
				Source: ir.Endpoint{
					ID:        xwingEndpoint,
					Identity:  xwingIdentity,
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
					Labels:    xwingLabels,
				},
				DestinationNames: []string{deathstarServiceDomain},
				DestinationService: ir.Service{
					Name:      deathstarServiceName,
					Namespace: deathstarServiceNamespace,
				},
				EventType: ir.EventType{
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
			flow: ir.Flow{
				Type:     flowpb.FlowType_SOCK,
				Verdict:  flowpb.Verdict_TRANSLATED,
				CgroupID: xwingCgroupId,
				IP: ir.IP{
					Source:      net.ParseIP(xwingIPv4),
					Destination: net.ParseIP(deathstarAltIPv4),
					IPVersion:   flowpb.IPVersion_IPv4,
				},
				L4: ir.Layer4{TCP: ir.TCP{
					DestinationPort: deathstarTargetPort,
				}},
				Source: ir.Endpoint{
					ID:        xwingEndpoint,
					Identity:  xwingIdentity,
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
					Labels:    xwingLabels,
				},
				Destination: ir.Endpoint{
					Identity:  deathstarIdentity,
					PodName:   deathstarAltPodName,
					Namespace: deathstarAltPodNamespace,
					Labels:    deathstarLabels,
				},
				EventType: ir.EventType{
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
			flow: ir.Flow{
				Type:     flowpb.FlowType_SOCK,
				Verdict:  flowpb.Verdict_TRANSLATED,
				CgroupID: xwingCgroupId,
				IP: ir.IP{
					Source:      net.ParseIP(deathstarServiceV6),
					Destination: net.ParseIP(xwingIPv6),
					IPVersion:   flowpb.IPVersion_IPv6,
				},
				L4: ir.Layer4{TCP: ir.TCP{
					SourcePort: deathstarServicePort,
				}},
				SourceNames: []string{deathstarServiceDomain},
				SourceService: ir.Service{
					Name:      deathstarServiceName,
					Namespace: deathstarServiceNamespace,
				},
				Destination: ir.Endpoint{
					ID:        xwingEndpoint,
					Identity:  xwingIdentity,
					PodName:   xwingPodName,
					Namespace: xwingPodNamespace,
					Labels:    xwingLabels,
				},
				EventType: ir.EventType{
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
				options.WithTraceSockNotifyDecoder(func(data []byte, flow *ir.Flow) (*monitor.TraceSockNotify, error) {
					flow.UUID = "coffee"
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
			flow: ir.Flow{
				UUID:    "coffee",
				Type:    flowpb.FlowType_SOCK,
				Verdict: flowpb.Verdict_TRANSLATED,
				IP: ir.IP{
					Destination: net.ParseIP("192.10.21.20"),
					IPVersion:   flowpb.IPVersion_IPv4,
				},
				L4: ir.Layer4{UDP: ir.UDP{
					DestinationPort: 8081,
				}},
				EventType: ir.EventType{
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
			var flow ir.Flow
			err = p.Decode(data, &flow)
			if tc.errMsg != "" {
				assert.ErrorContains(t, err, tc.errMsg)
			} else {
				assert.NoError(t, err)
				require.Equal(t, tc.flow, flow)
			}
		})
	}
}
