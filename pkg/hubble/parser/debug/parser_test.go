// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package debug

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(io.Discard)
}

func encodeDebugEvent(msg *monitor.DebugMsg) []byte {
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, byteorder.Native, msg); err != nil {
		panic(fmt.Sprintf("failed to encode debug event: %s", err))
	}
	return buf.Bytes()
}

func TestDecodeDebugEvent(t *testing.T) {
	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfoByID: func(id uint16) (endpoint v1.EndpointInfo, ok bool) {
			if id == 1234 {
				return &testutils.FakeEndpointInfo{
					ID:           1234,
					Identity:     5678,
					PodName:      "somepod",
					PodNamespace: "default",
				}, true
			}
			return nil, false
		},
	}

	p, err := New(log, endpointGetter)
	assert.NoError(t, err)

	tt := []struct {
		name    string
		data    []byte
		cpu     int
		ev      *flowpb.DebugEvent
		wantErr bool
	}{
		{
			name: "Generic event",
			data: encodeDebugEvent(&monitor.DebugMsg{
				Type:    monitorAPI.MessageTypeDebug,
				SubType: monitor.DbgGeneric,
				Source:  0,
				Arg1:    1,
				Arg2:    2,
			}),
			cpu: 0,
			ev: &flowpb.DebugEvent{
				Type:    flowpb.DebugEventType_DBG_GENERIC,
				Hash:    wrapperspb.UInt32(0),
				Arg1:    wrapperspb.UInt32(1),
				Arg2:    wrapperspb.UInt32(2),
				Arg3:    wrapperspb.UInt32(0),
				Message: "No message, arg1=1 (0x1) arg2=2 (0x2)",
				Cpu:     wrapperspb.Int32(0),
			},
		},
		{
			name: "IPv4 Mapping",
			data: encodeDebugEvent(&monitor.DebugMsg{
				Type:    monitorAPI.MessageTypeDebug,
				SubType: monitor.DbgIPIDMapSucceed4,
				Source:  1234,
				Hash:    705182630,
				Arg1:    3909094154,
				Arg2:    2,
			}),
			cpu: 2,
			ev: &flowpb.DebugEvent{
				Type: flowpb.DebugEventType_DBG_IP_ID_MAP_SUCCEED4,
				Source: &flowpb.Endpoint{
					ID:        1234,
					Identity:  5678,
					PodName:   "somepod",
					Namespace: "default",
				},
				Hash:    wrapperspb.UInt32(705182630),
				Arg1:    wrapperspb.UInt32(3909094154),
				Arg2:    wrapperspb.UInt32(2),
				Arg3:    wrapperspb.UInt32(0),
				Message: "Successfully mapped addr=10.11.0.233 to identity=2",
				Cpu:     wrapperspb.Int32(2),
			},
		},
		{
			name: "ICMP6 Handle",
			data: encodeDebugEvent(&monitor.DebugMsg{
				Type:    monitorAPI.MessageTypeDebug,
				SubType: monitor.DbgIcmp6Handle,
				Source:  1234,
				Hash:    0x9dd55684,
				Arg1:    129,
			}),
			cpu: 3,
			ev: &flowpb.DebugEvent{
				Type: flowpb.DebugEventType_DBG_ICMP6_HANDLE,
				Source: &flowpb.Endpoint{
					ID:        1234,
					Identity:  5678,
					PodName:   "somepod",
					Namespace: "default",
				},
				Hash:    wrapperspb.UInt32(0x9dd55684),
				Arg1:    wrapperspb.UInt32(129),
				Arg2:    wrapperspb.UInt32(0),
				Arg3:    wrapperspb.UInt32(0),
				Message: "Handling ICMPv6 type=129",
				Cpu:     wrapperspb.Int32(3),
			},
		},
		{
			name: "Unknown event",
			data: encodeDebugEvent(&monitor.DebugMsg{
				Type:    monitorAPI.MessageTypeDebug,
				SubType: monitor.DbgUnspec,
				Source:  10000,
				Hash:    0x12345678,
				Arg1:    10,
				Arg2:    20,
				Arg3:    30,
			}),
			cpu: 1,
			ev: &flowpb.DebugEvent{
				Type: flowpb.DebugEventType_DBG_EVENT_UNKNOWN,
				Source: &flowpb.Endpoint{
					ID: 10000,
				},
				Hash:    wrapperspb.UInt32(0x12345678),
				Arg1:    wrapperspb.UInt32(10),
				Arg2:    wrapperspb.UInt32(20),
				Arg3:    wrapperspb.UInt32(30),
				Message: "Unknown message type=0 arg1=10 arg2=20",
				Cpu:     wrapperspb.Int32(1),
			},
		},
		{
			name:    "No data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid data",
			data:    []byte{0, 1, 2},
			wantErr: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := p.Decode(tc.data, tc.cpu)
			if tc.wantErr {
				assert.NotNil(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.ev, ev)
			}
		})
	}
}
