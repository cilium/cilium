// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/fake"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	relayObserver "github.com/cilium/cilium/pkg/hubble/relay/observer"
	"github.com/cilium/cilium/pkg/hubble/relay/pool"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/hubble/server"
	"github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetOutput(io.Discard)
}

func noopParser(t testing.TB) *parser.Parser {
	pp, err := parser.New(
		log,
		&testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(ip netip.Addr) (endpoint v1.EndpointInfo, ok bool) {
				endpoint, ok = endpoints[ip.String()]
				return
			},
			OnGetEndpointInfoByID: func(id uint16) (endpoint v1.EndpointInfo, ok bool) {
				return nil, false
			},
		},
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

var endpoints map[string]*testutils.FakeEndpointInfo

func init() {
	endpoints = make(map[string]*testutils.FakeEndpointInfo, 254)
	for i := 0; i < 254; i++ {
		ip := fake.IP(fake.WithIPv4())
		endpoints[ip] = &testutils.FakeEndpointInfo{
			ID:           uint64(i),
			IPv4:         net.ParseIP(ip),
			PodNamespace: fake.K8sNamespace(),
			PodName:      fake.K8sPodName(),
			Labels:       fake.K8sLabels(),
		}
	}
}

func getRandomEndpoint() *testutils.FakeEndpointInfo {
	for _, v := range endpoints {
		return v
	}
	return nil
}

func newHubbleObserver(t testing.TB, nodeName string, numFlows int) *observer.LocalObserverServer {
	queueSize := numFlows

	pp := noopParser(t)
	s, err := observer.NewLocalServer(pp, log,
		observeroption.WithMaxFlows(container.Capacity65535),
		observeroption.WithMonitorBuffer(queueSize),
	)
	require.NoError(t, err)

	m := s.GetEventsChannel()

	for i := 0; i < numFlows; i++ {
		tn := monitor.TraceNotifyV0{Type: byte(monitorAPI.MessageTypeTrace)}
		src := getRandomEndpoint()
		dst := getRandomEndpoint()
		srcMAC, _ := net.ParseMAC(fake.MAC())
		dstMAC, _ := net.ParseMAC(fake.MAC())
		data := testutils.MustCreateL3L4Payload(tn,
			&layers.Ethernet{
				SrcMAC:       srcMAC,
				DstMAC:       dstMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				SrcIP:    src.IPv4,
				DstIP:    dst.IPv4,
				Protocol: layers.IPProtocolTCP,
			},
			&layers.TCP{
				SrcPort: layers.TCPPort(fake.Port()),
				DstPort: layers.TCPPort(fake.Port()),
				ACK:     true,
				PSH:     i%4 == 0,
			})
		event := &observerTypes.MonitorEvent{
			Timestamp: time.Unix(int64(i+1), 0),
			NodeName:  nodeName,
			Payload: &observerTypes.PerfEvent{
				Data: data,
				CPU:  0,
			},
		}
		m <- event
	}

	return s
}

func newHubblePeer(t testing.TB, ctx context.Context, address string, hubbleObserver *observer.LocalObserverServer) {
	options := []serveroption.Option{
		serveroption.WithInsecure(),
		serveroption.WithUnixSocketListener(address),
		serveroption.WithObserverService(hubbleObserver),
	}

	srv, err := server.NewServer(log, options...)
	require.NoError(t, err)

	go func() {
		if err := srv.Serve(); err != nil {
			t.Log(err)
			t.Fail()
		}
	}()

	go func() {
		<-ctx.Done()
		close(hubbleObserver.GetEventsChannel())
		<-hubbleObserver.GetStopped()
		srv.Stop()
	}()
}

func benchmarkRelayGetFlows(b *testing.B, withFieldMask bool) {
	tmp := b.TempDir()
	root := "unix://" + filepath.Join(tmp, "peer-")
	ctx := context.Background()
	numFlows := b.N
	numPeers := 2

	// FIXME: number of peers should be constant so that it scales linearly with b.N
	if numFlows > 65535*2 {
		numPeers = numFlows/65535 + 1
	}

	// Create hubble servers listening on unix sockets in temporary directory.
	type peer struct {
		name     string
		address  string
		observer *observer.LocalObserverServer
	}
	peers := make([]peer, numPeers)
	flowsScheduled := 0
	for i := range peers {
		address := fmt.Sprintf("%s%d.sock", root, i)
		name := fake.K8sNodeName()
		numFlowsPerPeer := numFlows / len(peers)
		if i == len(peers)-1 {
			numFlowsPerPeer = numFlows - flowsScheduled
		}
		// can't retrieve one last flow from the buffer
		hubbleObserver := newHubbleObserver(b, name, numFlowsPerPeer+1)
		newHubblePeer(b, ctx, address, hubbleObserver)
		flowsScheduled += numFlowsPerPeer
		peers[i] = peer{name, address, hubbleObserver}
		go hubbleObserver.Start()
	}

	// Create hubble relay server and connect to all peers from previous step.
	ccb := pool.GRPCClientConnBuilder{
		DialTimeout: defaults.DialTimeout,
		Options: []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
			grpc.WithReturnConnectionError(),
		},
	}
	plr := &testutils.FakePeerListReporter{
		OnList: func() []poolTypes.Peer {
			ret := make([]poolTypes.Peer, len(peers))
			for i := range peers {
				conn, err := ccb.ClientConn(peers[i].address, "")
				require.NoError(b, err)
				ret[i] = poolTypes.Peer{
					Peer: peerTypes.Peer{
						Name: peers[i].name,
					},
					Conn: conn,
				}
			}
			return ret
		},
	}
	observerSrv, err := relayObserver.NewServer(
		plr,
		relayObserver.WithLogger(log),
	)
	require.NoError(b, err)

	grpcServer := grpc.NewServer()
	observerpb.RegisterObserverServer(grpcServer, observerSrv)
	reflection.Register(grpcServer)

	socket, err := net.Listen("tcp", "localhost:0")
	require.NoError(b, err)

	go grpcServer.Serve(socket)
	defer grpcServer.Stop()

	conn, err := ccb.ClientConn(socket.Addr().String(), "")
	require.NoError(b, err)
	client := observerpb.NewObserverClient(conn)

	// Make sure that all peers are connected
	nodesResp, err := client.GetNodes(ctx, &observerpb.GetNodesRequest{})
	require.NoError(b, err)
	require.Equal(b, numPeers, len(nodesResp.Nodes))

	getFlowsReq := new(observerpb.GetFlowsRequest)
	if withFieldMask {
		fieldmask, err := fieldmaskpb.New(&flowpb.Flow{}, "time",
			"verdict", "drop_reason",
			"traffic_direction", "trace_observation_point", "Summary",
			"source.ID", "source.pod_name", "source.namespace",
			"destination.ID", "destination.pod_name", "destination.namespace",
			"l4.TCP.source_port",
		)
		require.NoError(b, err)
		getFlowsReq.Experimental = &observerpb.GetFlowsRequest_Experimental{
			FieldMask: fieldmask,
		}
	}
	found := make([]*observerpb.Flow, 0, numFlows)
	b.StartTimer()
	c, err := client.GetFlows(ctx, getFlowsReq)
	require.NoError(b, err)

	for {
		flow, err := c.Recv()
		if err == io.EOF {
			break
		}
		require.NoError(b, err)
		switch f := flow.ResponseTypes.(type) {
		case *observerpb.GetFlowsResponse_Flow:
			found = append(found, f.Flow)
		case *observerpb.GetFlowsResponse_NodeStatus:
		}
	}
	assert.Equal(b, numFlows, len(found))
	b.StopTimer()

	for _, f := range found {
		assert.NotEmpty(b, f.Source.PodName)
		assert.NotEmpty(b, f.Destination.PodName)
		assert.NotZero(b, f.Time)
		assert.NotEmpty(b, f.Summary)
		assert.NotZero(b, f.L4.GetTCP().SourcePort)
	}
}

func BenchmarkRelayGetFlowsWithFieldMask(b *testing.B) {
	benchmarkRelayGetFlows(b, true)
}

func BenchmarkRelayGetFlowsWithoutFieldMask(b *testing.B) {
	benchmarkRelayGetFlows(b, false)
}
