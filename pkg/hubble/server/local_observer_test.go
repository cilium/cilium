// Copyright 2020 Authors of Hubble
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

package server

import (
	"context"
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/logger"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noopParser(t *testing.T) *parser.Parser {
	pp, err := parser.New(
		&testutils.NoopEndpointGetter,
		&testutils.NoopIdentityGetter,
		&testutils.NoopDNSGetter,
		&testutils.NoopIPGetter,
		&testutils.NoopServiceGetter,
	)
	require.NoError(t, err)
	return pp
}

func TestNewLocalServer(t *testing.T) {
	pp := noopParser(t)
	s, err := NewLocalServer(pp, logger.GetLogger())
	require.NoError(t, err)
	assert.NotNil(t, s.GetStopped())
	assert.NotNil(t, s.GetPayloadParser())
	assert.NotNil(t, s.GetRingBuffer())
	assert.NotNil(t, s.GetLogger())
	assert.NotNil(t, s.GetEventsChannel())
}

func TestLocalObserverServer_ServerStatus(t *testing.T) {
	// (glibsm): This test is really confusing. `serveroption.WithMaxFlows(1)`
	// results in the actual flow capacity of 2.

	pp := noopParser(t)
	s, err := NewLocalServer(pp, logger.GetLogger(), serveroption.WithMaxFlows(1))
	require.NoError(t, err)
	res, err := s.ServerStatus(context.Background(), &observer.ServerStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, &observer.ServerStatusResponse{NumFlows: 0, MaxFlows: 2}, res)
}

func TestLocalObserverServer_GetFlows(t *testing.T) {
	numFlows := 100
	queueSize := 0
	req := &observer.GetFlowsRequest{Number: uint64(10)}
	i := 0
	fakeServer := &FakeGetFlowsServer{
		OnSend: func(response *observer.GetFlowsResponse) error {
			i++
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, logger.GetLogger(),
		serveroption.WithMaxFlows(numFlows),
		serveroption.WithMonitorBuffer(queueSize),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		data := testutils.MustCreateL3L4Payload(tn)
		pl := &pb.Payload{
			Time: &timestamp.Timestamp{Seconds: int64(i)},
			Type: pb.EventType_EventSample,
			Data: data,
		}
		m <- pl
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, req.Number, uint64(i))
}

type fakeCiliumDaemon struct{}

func (f *fakeCiliumDaemon) DebugEnabled() bool {
	return true
}

func TestHooks(t *testing.T) {
	numFlows := 10
	queueSize := 0

	ciliumDaemon := &fakeCiliumDaemon{}
	onServerInit := func(srv serveroption.Server) error {
		assert.Equal(t, srv.GetOptions().CiliumDaemon, ciliumDaemon)
		return nil
	}

	seenFlows := int64(0)
	skipEveryNFlows := int64(2)
	onMonitorEventFirst := func(ctx context.Context, payload *pb.Payload) (bool, error) {
		seenFlows++

		assert.Equal(t, payload.Time.Seconds, seenFlows-1)
		if seenFlows%skipEveryNFlows == 0 {
			return true, nil
		}
		return false, nil
	}
	onMonitorEventSecond := func(ctx context.Context, payload *pb.Payload) (bool, error) {
		if seenFlows%skipEveryNFlows == 0 {
			assert.Fail(t, "server did not break loop after onMonitorEventFirst")
		}
		return false, nil
	}
	onDecodedFlow := func(ctx context.Context, f *pb.Flow) (bool, error) {
		if seenFlows%skipEveryNFlows == 0 {
			assert.Fail(t, "server did not stop decoding after onMonitorEventFirst")
		}
		return false, nil
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, logger.GetLogger(),
		serveroption.WithMaxFlows(numFlows),
		serveroption.WithMonitorBuffer(queueSize),
		serveroption.WithCiliumDaemon(ciliumDaemon),
		serveroption.WithOnServerInitFunc(onServerInit),
		serveroption.WithOnMonitorEventFunc(onMonitorEventFirst),
		serveroption.WithOnMonitorEventFunc(onMonitorEventSecond),
		serveroption.WithOnDecodedFlowFunc(onDecodedFlow),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		data := testutils.MustCreateL3L4Payload(tn)
		pl := &pb.Payload{
			Time: &timestamp.Timestamp{Seconds: int64(i)},
			Type: pb.EventType_EventSample,
			Data: data,
		}
		m <- pl
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()
	assert.Equal(t, int64(numFlows), seenFlows)
}
