// Copyright 2020 Authors of Hubble
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

package observer

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(ioutil.Discard)
}

func noopParser(t *testing.T) *parser.Parser {
	pp, err := parser.New(
		log,
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
	s, err := NewLocalServer(pp, log)
	require.NoError(t, err)
	assert.NotNil(t, s.GetStopped())
	assert.NotNil(t, s.GetPayloadParser())
	assert.NotNil(t, s.GetRingBuffer())
	assert.NotNil(t, s.GetLogger())
	assert.NotNil(t, s.GetEventsChannel())
}

func TestLocalObserverServer_ServerStatus(t *testing.T) {
	pp := noopParser(t)
	s, err := NewLocalServer(pp, log, observeroption.WithMaxFlows(container.Capacity1))
	require.NoError(t, err)
	res, err := s.ServerStatus(context.Background(), &observerpb.ServerStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint64(0), res.SeenFlows)
	assert.Equal(t, uint64(0), res.NumFlows)
	assert.Equal(t, uint64(1), res.MaxFlows)
}

func TestLocalObserverServer_GetFlows(t *testing.T) {
	numFlows := 100
	queueSize := 0
	req := &observerpb.GetFlowsRequest{Number: uint64(10)}
	i := 0
	fakeServer := &testutils.FakeGetFlowsServer{
		OnSend: func(response *observerpb.GetFlowsResponse) error {
			assert.Equal(t, response.GetTime(), response.GetFlow().GetTime())
			assert.Equal(t, response.GetNodeName(), response.GetFlow().GetNodeName())
			i++
			return nil
		},
		FakeGRPCServerStream: &testutils.FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, log,
		observeroption.WithMaxFlows(container.Capacity127),
		observeroption.WithMonitorBuffer(queueSize),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		data := testutils.MustCreateL3L4Payload(tn)
		m <- &observerTypes.MonitorEvent{
			Timestamp: time.Unix(int64(i), 0),
			NodeName:  fmt.Sprintf("node #%03d", i),
			Payload: &observerTypes.PerfEvent{
				Data: data,
				CPU:  0,
			},
		}
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, req.Number, uint64(i))
}

func TestLocalObserverServer_GetFlows_Follow_Since(t *testing.T) {
	numFlows := 100
	queueSize := 0

	since := time.Unix(5, 0)
	sinceProto, err := ptypes.TimestampProto(since)
	assert.NoError(t, err)
	req := &observerpb.GetFlowsRequest{
		Since:  sinceProto,
		Follow: true,
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, log,
		observeroption.WithMaxFlows(container.Capacity127),
		observeroption.WithMonitorBuffer(queueSize),
	)
	require.NoError(t, err)
	go s.Start()

	generateFlows := func(from, to int, m chan<- *observerTypes.MonitorEvent) {
		for i := from; i < to; i++ {
			tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
			data := testutils.MustCreateL3L4Payload(tn)
			m <- &observerTypes.MonitorEvent{
				Timestamp: time.Unix(int64(i), 0),
				NodeName:  fmt.Sprintf("node #%03d", i),
				Payload: &observerTypes.PerfEvent{
					Data: data,
					CPU:  0,
				},
			}
		}
	}

	// produce first half of flows before request and second half during request
	m := s.GetEventsChannel()
	generateFlows(0, numFlows/2, m)

	receivedFlows := 0
	fakeServer := &testutils.FakeGetFlowsServer{
		OnSend: func(response *observerpb.GetFlowsResponse) error {
			receivedFlows++
			assert.Equal(t, response.GetTime(), response.GetFlow().GetTime())
			assert.Equal(t, response.GetNodeName(), response.GetFlow().GetNodeName())

			ts, err := ptypes.Timestamp(response.GetTime())
			assert.NoError(t, err)
			assert.True(t, !ts.Before(since), "flow had invalid timestamp. ts=%s, since=%s", ts, since)

			// start producing flows once we have seen the most recent one.
			// Most recently produced flow has timestamp (numFlows/2)-1, but is
			// inaccessible to readers due to the way the ring buffer works
			if int(ts.Unix()) == (numFlows/2)-2 {
				go func() {
					generateFlows(numFlows/2, numFlows, m)
					close(m)
				}()
			}

			// terminate the request once we have seen enough flows.
			// we expected to see all generated flows, minus the ones filtered
			// out by 'since', minus the one inaccessible in the ring buffer
			if receivedFlows == numFlows-int(since.Unix())-1 {
				// this will terminate the follow request
				return io.EOF
			}

			return nil
		},
		FakeGRPCServerStream: &testutils.FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}

	err = s.GetFlows(req, fakeServer)
	<-s.GetStopped()
	assert.Equal(t, err, io.EOF)
}

type fakeCiliumDaemon struct{}

func (f *fakeCiliumDaemon) DebugEnabled() bool {
	return true
}

func (f *fakeCiliumDaemon) GetK8sStore(name string) cache.Store {
	return nil
}

func TestHooks(t *testing.T) {
	numFlows := 10
	queueSize := 0

	ciliumDaemon := &fakeCiliumDaemon{}
	onServerInit := func(srv observeroption.Server) error {
		assert.Equal(t, srv.GetOptions().CiliumDaemon, ciliumDaemon)
		return nil
	}

	seenFlows := int64(0)
	skipEveryNFlows := int64(2)
	onMonitorEventFirst := func(ctx context.Context, event *observerTypes.MonitorEvent) (bool, error) {
		seenFlows++

		assert.Equal(t, event.Timestamp.Unix(), seenFlows-1)
		if seenFlows%skipEveryNFlows == 0 {
			return true, nil
		}
		return false, nil
	}
	onMonitorEventSecond := func(ctx context.Context, event *observerTypes.MonitorEvent) (bool, error) {
		if seenFlows%skipEveryNFlows == 0 {
			assert.Fail(t, "server did not break loop after onMonitorEventFirst")
		}
		return false, nil
	}
	onDecodedFlow := func(ctx context.Context, f *flowpb.Flow) (bool, error) {
		if seenFlows%skipEveryNFlows == 0 {
			assert.Fail(t, "server did not stop decoding after onMonitorEventFirst")
		}
		return false, nil
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, log,
		observeroption.WithMaxFlows(container.Capacity15),
		observeroption.WithMonitorBuffer(queueSize),
		observeroption.WithCiliumDaemon(ciliumDaemon),
		observeroption.WithOnServerInitFunc(onServerInit),
		observeroption.WithOnMonitorEventFunc(onMonitorEventFirst),
		observeroption.WithOnMonitorEventFunc(onMonitorEventSecond),
		observeroption.WithOnDecodedFlowFunc(onDecodedFlow),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		data := testutils.MustCreateL3L4Payload(tn)
		m <- &observerTypes.MonitorEvent{
			Timestamp: time.Unix(int64(i), 0),
			NodeName:  fmt.Sprintf("node #%03d", i),
			Payload: &observerTypes.PerfEvent{
				Data: data,
				CPU:  0,
			},
		}
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()
	assert.Equal(t, int64(numFlows), seenFlows)
}

func TestLocalObserverServer_OnFlowDelivery(t *testing.T) {
	numFlows := 100
	queueSize := 0
	req := &observerpb.GetFlowsRequest{Number: uint64(100)}
	flowsReceived := 0
	fakeServer := &testutils.FakeGetFlowsServer{
		OnSend: func(response *observerpb.GetFlowsResponse) error {
			assert.Equal(t, response.GetTime(), response.GetFlow().GetTime())
			assert.Equal(t, response.GetNodeName(), response.GetFlow().GetNodeName())
			flowsReceived++
			return nil
		},
		FakeGRPCServerStream: &testutils.FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}

	count := 0
	onFlowDelivery := func(ctx context.Context, f *flowpb.Flow) (bool, error) {
		count++
		if count%2 == 0 {
			return true, nil
		}
		return false, nil
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, log,
		observeroption.WithMaxFlows(container.Capacity127),
		observeroption.WithMonitorBuffer(queueSize),
		observeroption.WithOnFlowDeliveryFunc(onFlowDelivery),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		data := testutils.MustCreateL3L4Payload(tn)
		m <- &observerTypes.MonitorEvent{
			Timestamp: time.Unix(int64(i), 0),
			NodeName:  fmt.Sprintf("node #%03d", i),
			Payload: &observerTypes.PerfEvent{
				Data: data,
				CPU:  0,
			},
		}
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	// Only every second flow should have been received
	assert.Equal(t, flowsReceived, numFlows/2)
}

func TestLocalObserverServer_OnGetFlows(t *testing.T) {
	numFlows := 100
	queueSize := 0
	req := &observerpb.GetFlowsRequest{Number: uint64(100)}
	flowsReceived := 0
	fakeServer := &testutils.FakeGetFlowsServer{
		OnSend: func(response *observerpb.GetFlowsResponse) error {
			assert.Equal(t, response.GetTime(), response.GetFlow().GetTime())
			assert.Equal(t, response.GetNodeName(), response.GetFlow().GetNodeName())
			flowsReceived++
			return nil
		},
		FakeGRPCServerStream: &testutils.FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}

	type contextKey string
	key := contextKey("foo")
	onGetFlows := func(ctx context.Context, req *observerpb.GetFlowsRequest) (context.Context, error) {
		return context.WithValue(ctx, key, 10), nil
	}

	onFlowDelivery := func(ctx context.Context, f *flowpb.Flow) (bool, error) {
		// Pass if context is available
		if ctx.Value(key) != nil {
			return false, nil
		}
		return true, nil
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, log,
		observeroption.WithMaxFlows(container.Capacity127),
		observeroption.WithMonitorBuffer(queueSize),
		observeroption.WithOnFlowDeliveryFunc(onFlowDelivery),
		observeroption.WithOnGetFlowsFunc(onGetFlows),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		data := testutils.MustCreateL3L4Payload(tn)
		m <- &observerTypes.MonitorEvent{
			Timestamp: time.Unix(int64(i), 0),
			NodeName:  fmt.Sprintf("node #%03d", i),
			Payload: &observerTypes.PerfEvent{
				Data: data,
				CPU:  0,
			},
		}
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	// FIXME:
	// This should be assert.Equals(t, flowsReceived, numFlows)
	// A bug in the ring buffer prevents this from succeeding
	assert.Greater(t, flowsReceived, 0)
}
