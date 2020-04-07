// Copyright 2019 Authors of Hubble
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
	"net"
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/fqdncache"
	"github.com/cilium/cilium/pkg/hubble/ipcache"
	"github.com/cilium/cilium/pkg/hubble/logger"
	"github.com/cilium/cilium/pkg/hubble/parser"
	"github.com/cilium/cilium/pkg/hubble/servicecache"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	types "github.com/golang/protobuf/ptypes"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

var fakeDummyCiliumClient = &testutils.FakeCiliumClient{
	FakeEndpointList: func() (endpoints []*models.Endpoint, e error) {
		return nil, nil
	},
	FakeGetEndpoint: func(u uint64) (endpoint *models.Endpoint, e error) {
		return nil, nil
	},
	FakeGetIdentity: func(u uint64) (endpoint *models.Identity, e error) {
		return &models.Identity{}, nil
	},
	FakeGetFqdnCache: func() ([]*models.DNSLookup, error) {
		return nil, nil
	},
}

var allTypes = []*pb.EventTypeFilter{
	{Type: 1},
	{Type: 2},
	{Type: 3},
	{Type: 4},
	{Type: 129},
	{Type: 130},
}

type FakeGRPCServerStream struct {
	OnSetHeader  func(metadata.MD) error
	OnSendHeader func(metadata.MD) error
	OnSetTrailer func(m metadata.MD)
	OnContext    func() context.Context
	OnSendMsg    func(m interface{}) error
	OnRecvMsg    func(m interface{}) error
}

type FakeGetFlowsServer struct {
	OnSend func(response *observer.GetFlowsResponse) error
	*FakeGRPCServerStream
}

func (s *FakeGetFlowsServer) Send(response *observer.GetFlowsResponse) error {
	if s.OnSend != nil {
		// TODO: completely convert this into using pb.Flow
		return s.OnSend(response)
	}
	panic("OnSend not set")
}

func (s *FakeGRPCServerStream) SetHeader(m metadata.MD) error {
	if s.OnSetHeader != nil {
		return s.OnSetHeader(m)
	}
	panic("OnSetHeader not set")
}

func (s *FakeGRPCServerStream) SendHeader(m metadata.MD) error {
	if s.OnSendHeader != nil {
		return s.OnSendHeader(m)
	}
	panic("OnSendHeader not set")
}

func (s *FakeGRPCServerStream) SetTrailer(m metadata.MD) {
	if s.OnSetTrailer != nil {
		s.OnSetTrailer(m)
	}
	panic("OnSetTrailer not set")
}

func (s *FakeGRPCServerStream) Context() context.Context {
	if s.OnContext != nil {
		return s.OnContext()
	}
	panic("OnContext not set")
}

func (s *FakeGRPCServerStream) SendMsg(m interface{}) error {
	if s.OnSendMsg != nil {
		return s.OnSendMsg(m)
	}
	panic("OnSendMsg not set")
}

func (s *FakeGRPCServerStream) RecvMsg(m interface{}) error {
	if s.OnRecvMsg != nil {
		return s.OnRecvMsg(m)
	}
	panic("OnRecvMsg not set")
}

func TestObserverServer_GetLastNFlows(t *testing.T) {
	es := v1.NewEndpoints()
	ipc := ipcache.New()
	svcc := servicecache.New()
	fqdnc := fqdncache.New()

	pp, err := parser.New(es, fakeDummyCiliumClient, fqdnc, ipc, svcc)
	assert.NoError(t, err)

	s, err := NewServer(fakeDummyCiliumClient, es, ipc, fqdnc, svcc, pp, 0xff, 0, logger.GetLogger())
	require.NoError(t, err)
	if s.GetGRPCServer().GetRingBuffer().Cap() != 0x100 {
		t.Errorf("s.ring.Len() got = %#v, want %#v", s.GetGRPCServer().GetRingBuffer().Cap(), 0x100)
	}
	go s.Start()

	m := s.GetGRPCServer().GetEventsChannel()
	for i := uint64(0); i < s.GetGRPCServer().GetRingBuffer().Cap(); i++ {
		tn := monitor.TraceNotifyV0{
			Type: byte(monitorAPI.MessageTypeTrace),
			Hash: uint32(i),
		}
		data := testutils.MustCreateL3L4Payload(tn)
		pl := &pb.Payload{
			Time: &types.Timestamp{Seconds: int64(i)},
			Type: pb.EventType_EventSample,
			Data: data,
		}
		m <- pl
	}
	// Make sure all flows were consumed by the server
	close(m)
	<-s.GetGRPCServer().GetStopped()

	// We could use s.ring.LastWrite() but the Server uses LastWriteParallel
	// so we should use LastWriteParallel in testing as well
	if lastWrite := s.GetGRPCServer().GetRingBuffer().LastWriteParallel(); lastWrite != 0xfe {
		t.Errorf("LastWriteParallel() returns = %v, want %v", lastWrite, 0xfe)
	}

	req := &observer.GetFlowsRequest{
		Number:    10,
		Whitelist: []*pb.FlowFilter{{EventType: allTypes}},
	}
	got := make([]*observer.GetFlowsResponse, 10, 10)
	i := 0
	fakeServer := &FakeGetFlowsServer{
		OnSend: func(response *observer.GetFlowsResponse) error {
			got[i] = response
			i++
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}
	err = s.GetGRPCServer().GetFlows(req, fakeServer)
	if err != nil {
		t.Errorf("GetLastNFlows error = %v, wantErr %v", err, nil)
	}

	if len(got) != 10 {
		t.Errorf("Length of 'got' is not the same as 'wanted'")
	}
	for i := 0; i < 10; i++ {
		assert.Equal(t, int64(245+i), got[i].GetFlow().Time.Seconds)
	}
}

func TestObserverServer_GetLastNFlows_MustNotBlock(t *testing.T) {
	es := v1.NewEndpoints()
	ipc := ipcache.New()
	svcc := servicecache.New()
	fqdnc := fqdncache.New()

	pp, err := parser.New(es, fakeDummyCiliumClient, fqdnc, ipc, svcc)
	assert.NoError(t, err)

	s, err := NewServer(fakeDummyCiliumClient, es, ipc, fqdnc, svcc, pp, 0x4, 0, logger.GetLogger())
	require.NoError(t, err)
	if s.GetGRPCServer().GetRingBuffer().Cap() != 0x8 {
		t.Errorf("s.ring.Len() got = %#v, want %#v", s.GetGRPCServer().GetRingBuffer().Cap(), 0x8)
	}
	go s.Start()

	m := s.GetGRPCServer().GetEventsChannel()
	for i := uint64(0); i < 3; i++ {
		tn := monitor.TraceNotifyV0{
			Type: byte(monitorAPI.MessageTypeTrace),
			Hash: uint32(i),
		}
		data := testutils.MustCreateL3L4Payload(tn)
		pl := &pb.Payload{
			Time: &types.Timestamp{Seconds: int64(i)},
			Type: pb.EventType_EventSample,
			Data: data,
		}
		m <- pl
	}
	close(m)
	<-s.GetGRPCServer().GetStopped()

	if lastWrite := s.GetGRPCServer().GetRingBuffer().LastWriteParallel(); lastWrite != 0x1 {
		t.Errorf("LastWriteParallel() returns = %v, want %v", lastWrite, 0x1)
	}

	// request last 5 flows but only 3 are in the ring buffer
	req := &observer.GetFlowsRequest{
		Number:    5,
		Follow:    false,
		Whitelist: []*pb.FlowFilter{{EventType: allTypes}},
	}
	got := []*observer.GetFlowsResponse{}
	fakeServer := &FakeGetFlowsServer{
		OnSend: func(response *observer.GetFlowsResponse) error {
			got = append(got, response)
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}
	err = s.GetGRPCServer().GetFlows(req, fakeServer)
	assert.Nil(t, err)
	// FIXME: we have an off-by one here due to ring.LastWriteParallel() which
	// returns len-2 (instead of len-1) to be 100% sure to return an entry
	// that has been written to. This means that we only get to read 2 flows
	// because the ring reader cannot position itself as far back as required.
	assert.Equal(t, 2, len(got))
	for i := 0; i < 2; i++ {
		assert.Equal(t, int64(i), got[i].GetFlow().Time.Seconds)
	}
}

func TestObserverServer_GetLastNFlows_With_Follow(t *testing.T) {
	es := v1.NewEndpoints()
	ipc := ipcache.New()
	svcc := servicecache.New()
	fqdnc := fqdncache.New()

	pp, err := parser.New(es, fakeDummyCiliumClient, fqdnc, ipc, svcc)
	assert.NoError(t, err)

	s, err := NewServer(fakeDummyCiliumClient, es, ipc, fqdnc, svcc, pp, 0xff, 0, logger.GetLogger())
	require.NoError(t, err)
	if s.GetGRPCServer().GetRingBuffer().Cap() != 0x100 {
		t.Errorf("s.ring.Len() got = %#v, want %#v", s.GetGRPCServer().GetRingBuffer().Cap(), 0x100)
	}
	go s.Start()

	m := s.GetGRPCServer().GetEventsChannel()
	for i := uint64(0); i < s.GetGRPCServer().GetRingBuffer().Cap(); i++ {
		tn := monitor.TraceNotifyV0{
			Type: byte(monitorAPI.MessageTypeTrace),
			Hash: uint32(i),
		}
		data := testutils.MustCreateL3L4Payload(tn)
		pl := &pb.Payload{
			Time: &types.Timestamp{Seconds: int64(i)},
			Type: pb.EventType_EventSample,
			Data: data,
		}
		m <- pl
	}
	// Make sure all flows were consumed by the server
	close(m)
	<-s.GetGRPCServer().GetStopped()

	// We could use s.ring.LastWrite() but the Server uses LastWriteParallel
	// so we should use LastWriteParallel in testing as well
	if lastWrite := s.GetGRPCServer().GetRingBuffer().LastWriteParallel(); lastWrite != 0xfe {
		t.Errorf("LastWriteParallel() returns = %v, want %v", lastWrite, 0xfe)
	}

	req := &observer.GetFlowsRequest{
		Number:    10,
		Whitelist: []*pb.FlowFilter{{EventType: allTypes}},
		Follow:    true,
	}
	got := make([]*observer.GetFlowsResponse, 12, 12)
	i := 0
	receivedFirstBatch, receivedSecondBatch := make(chan struct{}), make(chan struct{})
	fakeServer := &FakeGetFlowsServer{
		OnSend: func(response *observer.GetFlowsResponse) error {
			got[i] = response
			i++
			if i == 10 {
				close(receivedFirstBatch)
			}
			if i == 12 {
				close(receivedSecondBatch)
			}
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}
	go func() {
		err := s.GetGRPCServer().GetFlows(req, fakeServer)
		if err != nil {
			t.Errorf("GetLastNFlows error = %v, wantErr %v", err, nil)
		}
	}()
	<-receivedFirstBatch

	for i := 0; i < 10; i++ {
		assert.Equal(t, int64(245+i), got[i].GetFlow().Time.Seconds)
	}

	// hacky to restart the events consumer.
	s.grpcServer.SetEventsChannel(make(chan *pb.Payload, 10))
	go s.Start()
	m = s.GetGRPCServer().GetEventsChannel()

	for i := uint64(0); i < 2; i++ {
		tn := monitor.TraceNotifyV0{
			Type: byte(monitorAPI.MessageTypeTrace),
			Hash: uint32(i),
		}
		data := testutils.MustCreateL3L4Payload(tn)
		pl := &pb.Payload{
			Time: &types.Timestamp{Seconds: int64(i + s.GetGRPCServer().GetRingBuffer().Cap())},
			Type: pb.EventType_EventSample,
			Data: data,
		}
		m <- pl
	}

	<-receivedSecondBatch
	for i := 0; i < len(got); i++ {
		assert.Equal(t, int64(245+i), got[i].GetFlow().Time.Seconds)
	}
}

func TestObserverServer_GetFlowsBetween(t *testing.T) {
	es := v1.NewEndpoints()
	ipc := ipcache.New()
	svcc := servicecache.New()
	fqdnc := fqdncache.New()

	pp, err := parser.New(es, fakeDummyCiliumClient, fqdnc, ipc, svcc)
	assert.NoError(t, err)

	s, err := NewServer(fakeDummyCiliumClient, es, ipc, fqdnc, svcc, pp, 0xff, 0, logger.GetLogger())
	require.NoError(t, err)
	if s.GetGRPCServer().GetRingBuffer().Cap() != 0x100 {
		t.Errorf("s.ring.Len() got = %#v, want %#v", s.GetGRPCServer().GetRingBuffer().Cap(), 0x100)
	}
	go s.Start()

	m := s.GetGRPCServer().GetEventsChannel()
	var payloads []*pb.Payload
	for i := uint64(0); i < s.GetGRPCServer().GetRingBuffer().Cap(); i++ {
		tn := monitor.TraceNotifyV0{
			Type: byte(monitorAPI.MessageTypeTrace),
			Hash: uint32(i),
		}
		data := testutils.MustCreateL3L4Payload(tn)
		payload := &pb.Payload{
			Time: &types.Timestamp{Seconds: int64(i)},
			Type: pb.EventType_EventSample,
			Data: data,
		}
		payloads = append(payloads, payload)
		m <- payload
	}
	// Make sure all flows were consumed by the server
	close(m)
	<-s.GetGRPCServer().GetStopped()

	// We could use s.ring.LastWrite() but the Server uses LastWriteParallel
	// so we should use LastWriteParallel in testing as well
	if lastWrite := s.GetGRPCServer().GetRingBuffer().LastWriteParallel(); lastWrite != 0xfe {
		t.Errorf("LastWriteParallel() returns = %v, want %v", lastWrite, 0xfe)
	}

	req := &observer.GetFlowsRequest{
		Since:     &types.Timestamp{Seconds: 2, Nanos: 0},
		Until:     &types.Timestamp{Seconds: 7, Nanos: 0},
		Whitelist: []*pb.FlowFilter{{EventType: allTypes}},
	}
	got := make([]*observer.GetFlowsResponse, 6, 6)
	i := 0
	fakeServer := &FakeGetFlowsServer{
		OnSend: func(response *observer.GetFlowsResponse) error {
			got[i] = response
			i++
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}
	err = s.GetGRPCServer().GetFlows(req, fakeServer)
	if err != nil {
		t.Errorf("GetFlowsBetween error = %v, wantErr %v", err, nil)
	}

	for i := 0; i < 6; i++ {
		assert.Equal(t, int64(i+2), got[i].GetFlow().Time.Seconds)
	}
}

type FakeObserverGetFlowsServer struct {
	OnSend func(*observer.GetFlowsResponse) error
	*FakeGRPCServerStream
}

func (s *FakeObserverGetFlowsServer) Send(flow *observer.GetFlowsResponse) error {
	if s.OnSend != nil {
		return s.OnSend(flow)
	}
	panic("OnSend not set")
}

func TestObserverServer_GetFlows(t *testing.T) {
	numFlows := 10
	count := 0
	fakeServer := &FakeObserverGetFlowsServer{
		OnSend: func(_ *observer.GetFlowsResponse) error {
			count++
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}
	es := v1.NewEndpoints()
	ipc := ipcache.New()
	svcc := servicecache.New()
	fqdnc := fqdncache.New()

	pp, err := parser.New(es, fakeDummyCiliumClient, fqdnc, ipc, svcc)
	assert.NoError(t, err)

	s, err := NewServer(fakeDummyCiliumClient, es, ipc, fqdnc, svcc, pp, 30, 0, logger.GetLogger())
	require.NoError(t, err)
	go s.Start()
	m := s.GetGRPCServer().GetEventsChannel()
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP: net.ParseIP("1.1.1.1"),
		DstIP: net.ParseIP("2.2.2.2"),
	}
	tcp := layers.TCP{}
	ch := s.GetGRPCServer().GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		data, err := testutils.CreateL3L4Payload(monitor.DropNotify{Type: monitorAPI.MessageTypeDrop}, &eth, &ip, &tcp)
		require.NoError(t, err)
		m <- &pb.Payload{Type: pb.EventType_EventSample, Data: data}
		// This payload will be ignored by GetFlows.
		data, err = testutils.CreateL3L4Payload(monitor.TraceNotifyV0{Type: monitorAPI.MessageTypeTrace}, &eth, &ip, &tcp)
		require.NoError(t, err)
		m <- &pb.Payload{Type: pb.EventType_EventSample, Data: data}
	}
	close(ch)
	<-s.GetGRPCServer().GetStopped()
	err = s.GetGRPCServer().GetFlows(&observer.GetFlowsRequest{
		Number: 10,
		Whitelist: []*pb.FlowFilter{
			{
				EventType: []*pb.EventTypeFilter{
					{Type: monitorAPI.MessageTypeDrop},
				},
			},
		},
	}, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, numFlows, count)
}

func TestObserverServer_GetFlowsWithFilters(t *testing.T) {
	numFlows := 10
	count := 0
	fakeServer := &FakeObserverGetFlowsServer{
		OnSend: func(res *observer.GetFlowsResponse) error {
			count++
			assert.Equal(t, "1.1.1.1", res.GetFlow().GetIP().GetSource())
			assert.Equal(t, "2.2.2.2", res.GetFlow().GetIP().GetDestination())
			assert.Equal(t, observer.Verdict_DROPPED, res.GetFlow().Verdict)
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}

	es := v1.NewEndpoints()
	ipc := ipcache.New()
	svcc := servicecache.New()
	fqdnc := fqdncache.New()

	pp, err := parser.New(es, fakeDummyCiliumClient, fqdnc, ipc, svcc)
	assert.NoError(t, err)

	s, err := NewServer(fakeDummyCiliumClient, es, ipc, fqdnc, svcc, pp, 30, 0, logger.GetLogger())
	require.NoError(t, err)
	go s.Start()
	m := s.GetGRPCServer().GetEventsChannel()
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP: net.ParseIP("1.1.1.1"),
		DstIP: net.ParseIP("2.2.2.2"),
	}
	ipRev := layers.IPv4{
		SrcIP: net.ParseIP("2.2.2.2"),
		DstIP: net.ParseIP("1.1.1.1"),
	}
	tcp := layers.TCP{}
	udp := layers.UDP{}
	ch := s.GetGRPCServer().GetEventsChannel()
	for i := 0; i < numFlows; i++ {
		// flow which is matched by the whitelist (to be included)
		data, err := testutils.CreateL3L4Payload(monitor.DropNotify{Type: monitorAPI.MessageTypeDrop}, &eth, &ip, &tcp)
		require.NoError(t, err)
		m <- &pb.Payload{Type: pb.EventType_EventSample, Data: data}
		// flow which is neither matched by the whitelist nor blacklist (to be ignored)
		data, err = testutils.CreateL3L4Payload(monitor.DropNotify{Type: monitorAPI.MessageTypeDrop}, &eth, &ipRev, &tcp)
		require.NoError(t, err)
		m <- &pb.Payload{Type: pb.EventType_EventSample, Data: data}
		// flows which is matched by both the white- and blacklist (to be excluded)
		data, err = testutils.CreateL3L4Payload(monitor.TraceNotifyV0{Type: monitorAPI.MessageTypeTrace}, &eth, &ip, &udp)
		require.NoError(t, err)
		m <- &pb.Payload{Type: pb.EventType_EventSample, Data: data}
	}
	close(ch)
	<-s.GetGRPCServer().GetStopped()
	err = s.GetGRPCServer().GetFlows(&observer.GetFlowsRequest{
		Number: uint64(numFlows),
		Whitelist: []*pb.FlowFilter{
			{SourceIp: []string{"1.1.1.1"}, EventType: allTypes},
		},
		Blacklist: []*pb.FlowFilter{
			{EventType: []*pb.EventTypeFilter{{Type: monitorAPI.MessageTypeTrace}}},
		},
	}, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, numFlows, count)
}

func TestObserverServer_GetFlowsOfANonLocalPod(t *testing.T) {
	numFlows := 5
	count := 0
	fakeServer := &FakeObserverGetFlowsServer{
		OnSend: func(_ *observer.GetFlowsResponse) error {
			count++
			return nil
		},
		FakeGRPCServerStream: &FakeGRPCServerStream{
			OnContext: func() context.Context {
				return context.Background()
			},
		},
	}
	fakeIPGetter := &testutils.FakeIPGetter{
		OnGetIPIdentity: func(ip net.IP) (identity ipcache.IPIdentity, ok bool) {
			if ip.Equal(net.ParseIP("1.1.1.1")) {
				return ipcache.IPIdentity{Namespace: "default", PodName: "foo-bar"}, true
			}
			return ipcache.IPIdentity{}, false
		},
	}

	es := v1.NewEndpoints()
	ipc := ipcache.New()
	svcc := servicecache.New()
	fqdnc := fqdncache.New()

	pp, err := parser.New(es, fakeDummyCiliumClient, fqdnc, fakeIPGetter, svcc)
	assert.NoError(t, err)

	s, err := NewServer(fakeDummyCiliumClient, es, ipc, fqdnc, svcc, pp, 30, 0, logger.GetLogger())
	require.NoError(t, err)
	go s.Start()
	m := s.GetGRPCServer().GetEventsChannel()
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
		DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
	}
	ip := layers.IPv4{
		SrcIP: net.ParseIP("1.1.1.1"),
		DstIP: net.ParseIP("2.2.2.2"),
	}
	tcp := layers.TCP{}
	for i := 0; i < numFlows; i++ {
		data, err := testutils.CreateL3L4Payload(monitor.DropNotify{Type: monitorAPI.MessageTypeDrop}, &eth, &ip, &tcp)
		require.NoError(t, err)
		m <- &pb.Payload{Type: pb.EventType_EventSample, Data: data}
		// This payload will be ignored by GetFlows.
		data, err = testutils.CreateL3L4Payload(monitor.TraceNotifyV0{Type: monitorAPI.MessageTypeTrace}, &eth, &ip, &tcp)
		require.NoError(t, err)
		m <- &pb.Payload{Type: pb.EventType_EventSample, Data: data}
	}
	close(m)
	<-s.GetGRPCServer().GetStopped()

	// pod exist so we will be able to get flows
	flowFilter := []*pb.FlowFilter{
		{
			SourcePod: []string{"default/foo-bar"},
			EventType: []*pb.EventTypeFilter{
				{
					Type: monitorAPI.MessageTypeDrop,
				},
			},
		},
	}
	err = s.GetGRPCServer().GetFlows(&observer.GetFlowsRequest{Whitelist: flowFilter, Number: 5}, fakeServer)
	assert.NoError(t, err)
	assert.Equal(t, numFlows, count)
}
