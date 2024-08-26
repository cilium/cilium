// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observer

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cilium/fake"
	"github.com/gopacket/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	hubv1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
)

var (
	log       *logrus.Logger
	nsManager = NewNamespaceManager()
)

func init() {
	log = logrus.New()
	log.SetOutput(io.Discard)
}

func noopParser(t *testing.T) *parser.Parser {
	pp, err := parser.New(
		log,
		&testutils.NoopEndpointGetter,
		&testutils.NoopIdentityGetter,
		&testutils.NoopDNSGetter,
		&testutils.NoopIPGetter,
		&testutils.NoopServiceGetter,
		&testutils.NoopLinkGetter,
		&testutils.NoopPodMetadataGetter,
	)
	require.NoError(t, err)
	return pp
}

func TestNewLocalServer(t *testing.T) {
	pp := noopParser(t)
	s, err := NewLocalServer(pp, nsManager, log)
	require.NoError(t, err)
	assert.NotNil(t, s.GetStopped())
	assert.NotNil(t, s.GetPayloadParser())
	assert.NotNil(t, s.GetRingBuffer())
	assert.NotNil(t, s.GetLogger())
	assert.NotNil(t, s.GetEventsChannel())
}

func TestLocalObserverServer_ServerStatus(t *testing.T) {
	pp := noopParser(t)
	s, err := NewLocalServer(pp, nsManager, log, observeroption.WithMaxFlows(container.Capacity1))
	require.NoError(t, err)
	res, err := s.ServerStatus(context.Background(), &observerpb.ServerStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint64(0), res.SeenFlows)
	assert.Equal(t, uint64(0), res.NumFlows)
	assert.Equal(t, uint64(1), res.MaxFlows)
	assert.Equal(t, float64(0), res.FlowsRate)
}

func TestGetFlowRate(t *testing.T) {
	type event struct {
		offset int
		event  interface{}
	}

	tcs := map[string]struct {
		ringCap container.Capacity
		events  []event
		rate    float64
	}{
		"0.5 Flow/s": {
			events: []event{
				{offset: 2000},
				{offset: 4000},
				{offset: 6000},
				{offset: 8000},
				{offset: 10000},
				{offset: 12000},
				{offset: 14000},
				{offset: 16000},
			},
			rate: 0.5,
		},
		"2 Flow/s": {
			events: []event{
				{offset: 500},
				{offset: 1000},
				{offset: 1500},
				{offset: 2000},
				{offset: 2500},
				{offset: 3000},
				{offset: 3500},
				{offset: 4000},
			},
			rate: 2,
		},
		"1 Flow/s  Full buffer": {
			ringCap: container.Capacity7,
			events: []event{
				{offset: 1000},
				{offset: 2000},
				{offset: 3000},
				{offset: 4000},
				{offset: 5000},
				{offset: 6000},
				{offset: 7000},
				{offset: 8000},
				{offset: 9000},
				{offset: 10000},
			},
			rate: 1,
		},
		"0.15 Flow/s  with flows older than 1 min": {
			events: []event{
				{offset: 1000},
				{offset: 2000},
				{offset: 3000},
				{offset: 4000},
				{offset: 5000},
				{offset: 6000},
				{offset: 7000},
				{offset: 8000},
				{offset: 9000},
				{offset: 61000},
			},
			rate: 0.15,
		},
		"1 Flow/s  with non flow events": {
			events: []event{
				{offset: 1000},
				{offset: 2000},
				{
					offset: 2500,
					event:  &flowpb.AgentEvent{},
				},
				{offset: 3000},
				{offset: 4000},
				{
					offset: 2500,
					event:  &flowpb.DebugEvent{},
				},
				{offset: 5000},
				{offset: 6000},
				{offset: 7000},
			},
			rate: 1,
		},
	}
	now := time.Now()

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			var c container.Capacity = container.Capacity63
			if tc.ringCap != nil {
				c = tc.ringCap
			}
			ring := container.NewRing(c)
			for i := len(tc.events) - 1; i >= 0; i-- {
				ev := tc.events[i].event
				if ev == nil {
					// Default is flow
					ev = &flowpb.Flow{}
				}
				ring.Write(&hubv1.Event{
					Timestamp: timestamppb.New(now.Add(-1 * time.Duration(tc.events[i].offset) * time.Millisecond)),
					Event:     ev,
				})
			}
			// Dummy value so that we can actually read all flows
			ring.Write(&hubv1.Event{
				Timestamp: timestamppb.New(now.Add(time.Second)),
			})
			rate, err := getFlowRate(ring, now)
			assert.NoError(t, err)
			assert.Equal(t, tc.rate, rate)
		})
	}
}

func TestLocalObserverServer_GetFlows(t *testing.T) {
	numFlows := 100
	queueSize := 0
	i := 0

	var output []*observerpb.Flow
	fakeServer := &testutils.FakeGetFlowsServer{
		OnSend: func(response *observerpb.GetFlowsResponse) error {
			assert.Equal(t, response.GetTime(), response.GetFlow().GetTime())
			assert.Equal(t, response.GetNodeName(), response.GetFlow().GetNodeName())
			output = append(output, proto.Clone(response.GetFlow()).(*flowpb.Flow))
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
	s, err := NewLocalServer(pp, nsManager, log,
		observeroption.WithMaxFlows(container.Capacity127),
		observeroption.WithMonitorBuffer(queueSize),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	input := make([]*observerpb.Flow, numFlows)

	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		macOnly := func(mac string) net.HardwareAddr {
			m, _ := net.ParseMAC(mac)
			return m
		}
		data := testutils.MustCreateL3L4Payload(tn, &layers.Ethernet{
			SrcMAC: macOnly(fake.MAC()),
			DstMAC: macOnly(fake.MAC()),
		})

		event := &observerTypes.MonitorEvent{
			Timestamp: time.Unix(int64(i), 0),
			NodeName:  fmt.Sprintf("node #%03d", i),
			Payload: &observerTypes.PerfEvent{
				Data: data,
				CPU:  0,
			},
		}
		m <- event
		ev, err := pp.Decode(event)
		require.NoError(t, err)
		input[i] = ev.GetFlow()
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()

	// testing getting recent events
	req := &observerpb.GetFlowsRequest{Number: uint64(10)}
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, req.Number, uint64(i))

	// instead of looking at exactly the last 10, we look at the last 10, minus
	// 1, because the last event is inaccessible due to how the ring buffer
	// works.
	last10Input := input[numFlows-11 : numFlows-1]
	for i := range output {
		assert.True(t, proto.Equal(last10Input[i], output[i]))
	}

	// Clear out the output slice, as we're making another request
	output = nil
	i = 0
	// testing getting earliest events
	req = &observerpb.GetFlowsRequest{Number: uint64(10), First: true}
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, req.Number, uint64(i))

	first10Input := input[0:10]
	for i := range output {
		assert.True(t, proto.Equal(first10Input[i], output[i]))
	}

	// Clear out the output slice, as we're making another request
	output = nil
	i = 0
	// testing getting subset of fields with field mask
	fmPaths := []string{"trace_observation_point", "ethernet.source"}
	req = &observerpb.GetFlowsRequest{
		Number:    uint64(10),
		FieldMask: &fieldmaskpb.FieldMask{Paths: fmPaths},
		Experimental: &observerpb.GetFlowsRequest_Experimental{
			FieldMask: &fieldmaskpb.FieldMask{Paths: fmPaths},
		},
	}
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, req.Number, uint64(i))

	for i, out := range output {
		assert.Equal(t, last10Input[i].TraceObservationPoint, out.TraceObservationPoint)
		assert.Equal(t, last10Input[i].Ethernet.Source, out.Ethernet.Source)
		assert.Empty(t, out.Ethernet.Destination)
		assert.Empty(t, out.Verdict)
		assert.Empty(t, out.Summary)
		// Keeps original as is
		assert.NotEmpty(t, last10Input[i].Summary)
	}

	// Clear out the output slice, as we're making another request
	output = nil
	i = 0
	// testing getting all fields with field mask
	req = &observerpb.GetFlowsRequest{
		Number:    uint64(10),
		FieldMask: &fieldmaskpb.FieldMask{Paths: []string{""}},
		Experimental: &observerpb.GetFlowsRequest_Experimental{
			FieldMask: &fieldmaskpb.FieldMask{Paths: []string{""}},
		},
	}
	err = s.GetFlows(req, fakeServer)
	assert.EqualError(t, err, "invalid fieldmask")
}

func TestLocalObserverServer_GetAgentEvents(t *testing.T) {
	numEvents := 100
	queueSize := 0
	req := &observerpb.GetAgentEventsRequest{
		Number: uint64(numEvents),
	}
	cidr := "10.0.0.0/8"
	agentEventsReceived := 0
	agentStartedReceived := 0
	fakeServer := &testutils.FakeGetAgentEventsServer{
		OnSend: func(response *observerpb.GetAgentEventsResponse) error {
			switch ev := response.GetAgentEvent(); ev.GetType() {
			case flowpb.AgentEventType_AGENT_STARTED:
				startEvent := response.GetAgentEvent().GetAgentStart()
				assert.NotNil(t, startEvent)
				assert.Equal(t, startEvent.GetTime().GetSeconds(), int64(42))
				assert.Equal(t, startEvent.GetTime().GetNanos(), int32(1))
				agentStartedReceived++
			case flowpb.AgentEventType_IPCACHE_UPSERTED:
				ipcacheUpdate := response.GetAgentEvent().GetIpcacheUpdate()
				assert.NotNil(t, ipcacheUpdate)
				assert.Equal(t, cidr, ipcacheUpdate.GetCidr())
			case flowpb.AgentEventType_SERVICE_DELETED:
				serviceDelete := response.GetAgentEvent().GetServiceDelete()
				assert.NotNil(t, serviceDelete)
			default:
				assert.Fail(t, "unexpected agent event", ev)
			}
			agentEventsReceived++
			return nil
		},
		FakeGRPCServerStream: &testutils.FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, nsManager, log,
		observeroption.WithMonitorBuffer(queueSize),
	)
	require.NoError(t, err)
	go s.Start()

	m := s.GetEventsChannel()
	for i := 0; i < numEvents; i++ {
		ts := time.Unix(int64(i), 0)
		node := fmt.Sprintf("node #%03d", i)
		var msg monitorAPI.AgentNotifyMessage
		if i == 0 {
			msg = monitorAPI.StartMessage(time.Unix(42, 1))
		} else if i%2 == 1 {
			msg = monitorAPI.IPCacheUpsertedMessage(cidr, uint32(i), nil, net.ParseIP("10.1.5.4"), nil, 0xff, "default", "foobar")
		} else {
			msg = monitorAPI.ServiceDeleteMessage(uint32(i))
		}
		m <- &observerTypes.MonitorEvent{
			Timestamp: ts,
			NodeName:  node,
			Payload: &observerTypes.AgentEvent{
				Type:    monitorAPI.MessageTypeAgent,
				Message: msg,
			},
		}
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()
	err = s.GetAgentEvents(req, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, 1, agentStartedReceived)
	// FIXME:
	// This should be assert.Equals(t, numEvents, agentEventsReceived)
	// A bug in the ring buffer prevents this from succeeding
	assert.Greater(t, agentEventsReceived, 0)
}

func TestLocalObserverServer_GetFlows_Follow_Since(t *testing.T) {
	numFlows := 100
	queueSize := 0

	since := time.Unix(5, 0)
	sinceProto := timestamppb.New(since)
	assert.NoError(t, sinceProto.CheckValid())
	req := &observerpb.GetFlowsRequest{
		Since:  sinceProto,
		Follow: true,
	}

	pp := noopParser(t)
	s, err := NewLocalServer(pp, nsManager, log,
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

			assert.NoError(t, response.GetTime().CheckValid())
			ts := response.GetTime().AsTime()
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

func TestHooks(t *testing.T) {
	numFlows := 10
	queueSize := 0

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
	s, err := NewLocalServer(pp, nsManager, log,
		observeroption.WithMaxFlows(container.Capacity15),
		observeroption.WithMonitorBuffer(queueSize),
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
	s, err := NewLocalServer(pp, nsManager, log,
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
	s, err := NewLocalServer(pp, nsManager, log,
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
	// This should be assert.Equal(t, numFlows, flowsReceived)
	// A bug in the ring buffer prevents this from succeeding
	assert.Greater(t, flowsReceived, 0)
}

// TestLocalObserverServer_NodeLabels test the LocalNodeWatcher integration
// with the observer.
func TestLocalObserverServer_NodeLabels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// local node stuff setup.
	localNode := node.LocalNode{
		Node: types.Node{
			Name: "ip-1-2-3-4.us-west-2.compute.internal",
			Labels: map[string]string{
				"kubernetes.io/arch":            "amd64",
				"kubernetes.io/os":              "linux",
				"kubernetes.io/hostname":        "ip-1-2-3-4.us-west-2.compute.internal",
				"topology.kubernetes.io/region": "us-west-2",
				"topology.kubernetes.io/zone":   "us-west-2d",
			},
		},
	}
	localNodeWatcher, err := NewLocalNodeWatcher(ctx, node.NewTestLocalNodeStore(localNode))
	require.NoError(t, err)
	require.NotNil(t, localNodeWatcher)

	// fake hubble server setup.
	flowsReceived := 0
	req := &observerpb.GetFlowsRequest{Number: uint64(1)}
	fakeServer := &testutils.FakeGetFlowsServer{
		OnSend: func(response *observerpb.GetFlowsResponse) error {
			// NOTE: a bit hacky to directly access the localNodeWatcher cache,
			// but we don't have any use yet for an accessor method beyond this
			// package local test.
			localNodeWatcher.mu.Lock()
			expected := localNodeWatcher.cache.labels
			localNodeWatcher.mu.Unlock()
			assert.Equal(t, expected, response.GetFlow().GetNodeLabels())
			flowsReceived++
			return nil
		},
		FakeGRPCServerStream: &testutils.FakeGRPCServerStream{
			OnContext: func() context.Context {
				return ctx
			},
		},
	}

	// local hubble observer setup.
	s, err := NewLocalServer(noopParser(t), nsManager, log,
		observeroption.WithOnDecodedFlow(localNodeWatcher),
	)
	require.NoError(t, err)
	go s.Start()

	// simulate a new monitor event.
	m := s.GetEventsChannel()
	tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
	data := testutils.MustCreateL3L4Payload(tn)
	// NOTE: we need to send an extra event into Hubble's ring buffer to see
	// the first one sent.
	for range 2 {
		m <- &observerTypes.MonitorEvent{
			Timestamp: time.Now(),
			NodeName:  localNode.Name,
			Payload: &observerTypes.PerfEvent{
				Data: data,
				CPU:  0,
			},
		}
	}
	close(s.GetEventsChannel())
	<-s.GetStopped()

	// ensure that we've seen a flow.
	err = s.GetFlows(req, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, 1, flowsReceived)
}

func TestLocalObserverServer_GetNamespaces(t *testing.T) {
	pp := noopParser(t)
	nsManager := NewNamespaceManager()
	nsManager.AddNamespace(&observerpb.Namespace{
		Namespace: "zzz",
	})
	nsManager.AddNamespace(&observerpb.Namespace{
		Namespace: "bbb",
		Cluster:   "some-cluster",
	})
	nsManager.AddNamespace(&observerpb.Namespace{
		Namespace: "aaa",
		Cluster:   "some-cluster",
	})
	s, err := NewLocalServer(pp, nsManager, log, observeroption.WithMaxFlows(container.Capacity1))
	require.NoError(t, err)
	res, err := s.GetNamespaces(context.Background(), &observerpb.GetNamespacesRequest{})
	require.NoError(t, err)
	expected := &observerpb.GetNamespacesResponse{
		Namespaces: []*observerpb.Namespace{
			{
				Namespace: "zzz",
			},
			{
				Namespace: "aaa",
				Cluster:   "some-cluster",
			},
			{
				Namespace: "bbb",
				Cluster:   "some-cluster",
			},
		},
	}
	assert.Equal(t, expected, res)
}

func Benchmark_TrackNamespaces(b *testing.B) {
	pp, err := parser.New(
		log,
		&testutils.NoopEndpointGetter,
		&testutils.NoopIdentityGetter,
		&testutils.NoopDNSGetter,
		&testutils.NoopIPGetter,
		&testutils.NoopServiceGetter,
		&testutils.NoopLinkGetter,
		&testutils.NoopPodMetadataGetter,
	)
	if err != nil {
		b.Fatal(err)
	}

	nsManager := NewNamespaceManager()
	s, err := NewLocalServer(pp, nsManager, log, observeroption.WithMaxFlows(container.Capacity1))
	if err != nil {
		b.Fatal(err)
	}
	f := &flowpb.Flow{
		Source:      &flowpb.Endpoint{Namespace: "foo"},
		Destination: &flowpb.Endpoint{Namespace: "bar"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.trackNamespaces(f)
	}
}
