// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

type mockDefaultDialer struct {
	lis *bufconn.Listener
}

func newMockDialConfig(lis *bufconn.Listener) dialClient {
	return &mockDefaultDialer{lis: lis}
}

func (b *mockDefaultDialer) CreateClient(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return b.lis.Dial()
	}
	opts = append(opts, grpc.WithContextDialer(bufDialer))
	return grpc.NewClient("passthrough://bufnet", opts...)
}

type mockFqdnDataServer struct {
	success atomic.Int32
	failure atomic.Int32
}

func (m *mockFqdnDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	limiter := rate.NewLimiter(2*time.Second, 1)
	defer limiter.Stop()
	counter := 0
	for {

		select {
		case <-streamCtx.Done():
			return streamCtx.Err()
		default:
			if counter < 5 {
				stream.Send(&pb.PolicyState{
					RequestId: fmt.Sprintf("%d", counter),
				})
			} else {
				return errors.New("simulated stream failure")
			}
			_, err := stream.Recv()
			if err != nil {
				m.failure.Add(1)
				return err
			}
			m.success.Add(1)
			counter++
		}
		// Limit the rate at which we send the full snapshots
		if err := limiter.Wait(streamCtx); err != nil {
			return err
		}
	}
}

// Implement the missing UpdateMappingRequest method to satisfy the interface.
func (m *mockFqdnDataServer) UpdateMappingRequest(ctx context.Context, req *pb.FQDNMapping) (*pb.UpdateMappingResponse, error) {
	// based on the success or failure of processed request, send appropriate response
	if m.success.Load() > m.failure.Load() {
		m.failure.Add(1)
		return nil, io.EOF
	}
	m.success.Add(1)
	return &pb.UpdateMappingResponse{}, nil
}

func setupClientAndServer(t *testing.T) (ConnectionHandler, *mockFqdnDataServer, func()) {
	buffer := 1024 * 1024
	var connHandler ConnectionHandler
	lis := bufconn.Listen(buffer)

	// Start a simple gRPC server on the bufconn listener
	server := grpc.NewServer()
	mockFqdnDataServer := &mockFqdnDataServer{}
	pb.RegisterFQDNDataServer(server, mockFqdnDataServer)
	go func() {
		if err := server.Serve(lis); err != nil {
			t.Logf("Server serve error: %v", err)
		}
		t.Logf("gRPC server exited unexpectedly")
	}()

	h := hive.New(
		cell.Config(service.DefaultConfig),
		cell.Provide(newDNSRulesTable),
		cell.Provide(NewIPtoEndpointTable),
		cell.Provide(NewPrefixToIdentityTable),
		cell.Provide(func() dialClient {
			return newMockDialConfig(lis)
		},
			newGRPCClient),
		cell.Invoke(func(_c ConnectionHandler) {
			connHandler = _c
		}),
	)
	if err := h.Start(hivetest.Logger(t), t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	require.NotNil(t, connHandler)

	cleanup := func() {
		server.Stop()
		connHandler.StopConnection()
		h.Stop(hivetest.Logger(t), context.TODO())
		_ = lis.Close()
	}

	return connHandler, mockFqdnDataServer, cleanup
}

func TestCreateGRPCClient(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)
	connHandler, _, cleanup := setupClientAndServer(t)
	defer cleanup()

	require.NotNil(t, connHandler)
	err := testutils.WaitUntilWithSleep(func() bool {
		t.Log("Waiting for connection to be established...")
		return connHandler.IsConnected()
	}, 30*time.Second, 5*time.Second)
	require.NoError(t, err, "Connection should be established within timeout")

	// Stop the connection handler
	connHandler.StopConnection()

	err = testutils.WaitUntilWithSleep(func() bool {
		t.Log("Waiting for connection to be closed...")
		return !connHandler.IsConnected()
	}, 5*time.Second, 1*time.Second)
	require.NoError(t, err, "Connection should be closed within timeout")
}

func TestNotifyOnMsg(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)
	var connHandler ConnectionHandler

	connHandler, _, cleanup := setupClientAndServer(t)
	defer cleanup()

	require.NotNil(t, connHandler)

	err := testutils.WaitUntilWithSleep(func() bool {
		return connHandler.IsConnected()
	}, 30*time.Second, 5*time.Second)
	require.NoError(t, err, "Connection should be established within timeout")

	var success atomic.Int32
	var failure atomic.Int32
	totalCalls := 100

	done := make(chan struct{})

	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(totalCalls)

		for range totalCalls {
			go func() {
				defer wg.Done()
				errCall := connHandler.NotifyOnMsg(&pb.FQDNMapping{})
				if errCall != nil {
					failure.Add(1)
					return
				}
				success.Add(1)
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Concurrent NotifyOnMsg calls didn't complete in time")
	}
	require.Equal(t, int32(totalCalls), success.Load()+failure.Load())
	// There should be no failures for NotifyOnMsg calls as in case of agent not available, standalone DNS proxy should handle the requests
	require.Equal(t, int32(0), failure.Load(), "There should be no failures due to simulated connection errors")
}

func TestPolicyStream(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)
	connHandler, server, cleanup := setupClientAndServer(t)
	defer cleanup()

	// Wait for initial connect & stream.
	err := testutils.WaitUntilWithSleep(func() bool { return connHandler.IsConnected() }, 30*time.Second, 5*time.Second)
	require.NoError(t, err, "Connection should be established within timeout")
	err = testutils.WaitUntilWithSleep(func() bool { return server.success.Load() > 0 }, 10*time.Second, 2*time.Second)
	require.NoError(t, err, "Should have at least one successful policy exchange within timeout")
	require.Equal(t, int32(0), server.failure.Load(), "Should not have any failures")

	err = testutils.WaitUntilWithSleep(func() bool { return !connHandler.IsConnected() }, 15*time.Second, 500*time.Millisecond)
	require.NoError(t, err, "Connection should be lost within timeout")
	// Due to the job based reconnect, the connection should be re-established
	err = testutils.WaitUntilWithSleep(func() bool { return connHandler.IsConnected() }, 15*time.Second, 500*time.Millisecond)
	require.NoError(t, err, "Connection should be established within timeout")
}

func assertDNSRules(t *testing.T, c *GRPCClient, epID uint32, pp restore.PortProto, expServerIDs []uint32, expPatterns []string) {
	t.Helper()
	rtxn := c.db.ReadTxn()
	ck := DNSRulesCompositeKey(epID, pp)
	row, _, found := c.dnsRulesTable.Get(rtxn, DNSRulesIndex.Query(ck))
	require.True(t, found, "no DNSRules for ep=%d portProto=%v", epID, pp)

	var gotIDs []uint32
	var gotPatterns []string
	for k, v := range row.DNSRule {
		for _, id := range k.GetSelections() {
			gotIDs = append(gotIDs, id.Uint32())
		}
		if v != nil {
			for _, r := range v.L7Rules.DNS {
				if r.MatchPattern != "" {
					gotPatterns = append(gotPatterns, r.MatchPattern)
				}
			}
		}
	}
	require.ElementsMatch(t, expServerIDs, gotIDs, "server IDs mismatch")
	require.ElementsMatch(t, expPatterns, gotPatterns, "patterns mismatch")
}

func TestUpdateDNSRules(t *testing.T) {
	db := statedb.New()
	table, err := newDNSRulesTable(db)
	require.NoError(t, err)

	logger := hivetest.Logger(t)
	c := &GRPCClient{
		logger:        logger,
		db:            db,
		dnsRulesTable: table,
	}

	pp53 := restore.MakeV2PortProto(53, u8proto.UDP)
	pp54 := restore.MakeV2PortProto(54, u8proto.TCP)

	tests := []struct {
		name   string
		input  []*pb.DNSPolicy
		checks []struct {
			epID      uint32
			pp        restore.PortProto
			serverIDs []uint32
			patterns  []string
		}
	}{
		{
			name: "single pattern single server",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 100,
					DnsPattern:       []string{"example.com"},
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:     53,
						DnsServerProto:    uint32(u8proto.UDP),
						DnsServerIdentity: 200,
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{100, pp53, []uint32{200}, []string{"example.com"}},
			},
		},
		{
			name: "multiple patterns single server",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 101,
					DnsPattern:       []string{"a.com", "b.com"},
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:     54,
						DnsServerProto:    uint32(u8proto.TCP),
						DnsServerIdentity: 210,
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{101, pp54, []uint32{210}, []string{"a.com", "b.com"}},
			},
		},
		{
			name: "multiple servers same policy",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 102,
					DnsPattern:       []string{"group.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 220},
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 221},
					},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{102, pp53, []uint32{220, 221}, []string{"group.com"}},
			},
		},
		{
			name: "multiple policies different servers",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 103,
					DnsPattern:       []string{"one.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 230},
					},
				},
				{
					SourceEndpointId: 103,
					DnsPattern:       []string{"two.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 231},
					},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{103, pp53, []uint32{230, 231}, []string{"one.com", "two.com"}},
			},
		},
		{
			name: "different ports same endpoint",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 104,
					DnsPattern:       []string{"p53.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 53, DnsServerProto: uint32(u8proto.UDP), DnsServerIdentity: 240},
					},
				},
				{
					SourceEndpointId: 104,
					DnsPattern:       []string{"p54.com"},
					DnsServers: []*pb.DNSServer{
						{DnsServerPort: 54, DnsServerProto: uint32(u8proto.TCP), DnsServerIdentity: 241},
					},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{104, pp53, []uint32{240}, []string{"p53.com"}},
				{104, pp54, []uint32{241}, []string{"p54.com"}},
			},
		},
		{
			name: "empty patterns single server (nil policy entry)",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 110,
					// DnsPattern omitted -> len==0 => nil policy value stored
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:     53,
						DnsServerProto:    uint32(u8proto.UDP),
						DnsServerIdentity: 2100,
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{110, pp53, []uint32{2100}, []string{}}, // expect no patterns
			},
		},
		{
			name: "No dns server identity",
			input: []*pb.DNSPolicy{
				{
					SourceEndpointId: 110,
					DnsPattern:       []string{"p53.com"},
					DnsServers: []*pb.DNSServer{{
						DnsServerPort:  53,
						DnsServerProto: uint32(u8proto.UDP),
					}},
				},
			},
			checks: []struct {
				epID      uint32
				pp        restore.PortProto
				serverIDs []uint32
				patterns  []string
			}{
				{110, pp53, []uint32{0}, []string{"p53.com"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := c.updateDNSRules(tc.input)
			require.NoError(t, err)

			for _, chk := range tc.checks {
				assertDNSRules(t, c, chk.epID, chk.pp, chk.serverIDs, chk.patterns)
			}
		})
	}
}

func updateMapping(t *testing.T, client *GRPCClient, id uint64, ident identity.NumericIdentity, ip string) {
	t.Helper()
	ipAddr, err := netip.ParseAddr(ip)
	require.NoError(t, err)
	input := []*pb.IdentityToEndpointMapping{
		{
			Identity: ident.Uint32(),
			EndpointInfo: []*pb.EndpointInfo{
				{
					Id: id,
					Ip: [][]byte{ipAddr.AsSlice()},
				},
			},
		},
	}

	err = client.updateIPToEndpoint(input)
	require.NoError(t, err)
}

func checkMapping(t *testing.T, client *GRPCClient, ip string, expectedID uint64, expectedIdent identity.NumericIdentity, shouldExist bool) {
	t.Helper()
	rtxn := client.db.ReadTxn()
	addr, err := netip.ParseAddr(ip)
	require.NoError(t, err)
	mapping, _, found := client.ipToEndpointTable.Get(rtxn, IdIPToEndpointIndex.Query(addr))
	if shouldExist {
		require.True(t, found)
		require.Equal(t, []netip.Addr{addr}, mapping.IP)
		require.Equal(t, expectedIdent, mapping.Identity)
		require.Equal(t, expectedID, mapping.ID)
	} else {
		require.False(t, found)
	}
}

func TestNewIPtoIdentityTable(t *testing.T) {
	// Create a new StateDB instance
	db := statedb.New()

	// Test successful table creation
	ipTable, err := NewIPtoEndpointTable(db)
	require.NoError(t, err)
	require.NotNil(t, ipTable)

	logger := hivetest.Logger(t)
	client := &GRPCClient{
		logger:            logger,
		db:                db,
		ipToEndpointTable: ipTable,
	}

	// Initial check - table should be empty
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), false)
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.1, identity 1, ID 100
	updateMapping(t, client, 100, identity.NumericIdentity(1), "192.168.1.1")
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), true)
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), false)

	updateMapping(t, client, 100, identity.NumericIdentity(1), "192.168.1.1")
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), true)
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.2, identity 2, ID 200
	updateMapping(t, client, 200, identity.NumericIdentity(2), "192.168.1.2")
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(2), true)
	checkMapping(t, client, "192.168.1.1", 100, identity.NumericIdentity(1), false)

	// Update mapping - modify existing entry
	updateMapping(t, client, 200, identity.NumericIdentity(3), "192.168.1.2")
	checkMapping(t, client, "192.168.1.2", 200, identity.NumericIdentity(3), true)
}

func checkPrefixMapping(t *testing.T, client *GRPCClient, prefix string, expectedIdent identity.NumericIdentity, shouldExist bool) {
	t.Helper()
	rtxn := client.db.ReadTxn()
	pfx, err := netip.ParsePrefix(prefix)
	require.NoError(t, err)
	mapping, _, found := client.prefixToIdentityTable.Get(rtxn, PrefixToIdentityIndex.Query(pfx))
	if shouldExist {
		require.True(t, found)
		require.Equal(t, []netip.Prefix{pfx}, mapping.Prefix)
		require.Equal(t, expectedIdent, mapping.Identity)
	} else {
		require.False(t, found)
	}
}

func updatePrefixMapping(t *testing.T, client *GRPCClient, ident identity.NumericIdentity, prefix string) {
	t.Helper()
	ipBytes, err := netip.MustParsePrefix(prefix).MarshalBinary()
	require.NoError(t, err)
	input := []*pb.IdentityToPrefixMapping{
		{
			Identity: ident.Uint32(),
			Prefix:   [][]byte{ipBytes},
		},
	}

	err = client.updatePrefixToIdentity(input)
	require.NoError(t, err)
}

func TestNewPrefixToIdentityTable(t *testing.T) {
	// Create a new StateDB instance
	db := statedb.New()

	// Test successful table creation
	prefixTable, err := NewPrefixToIdentityTable(db)
	require.NoError(t, err)
	require.NotNil(t, prefixTable)

	logger := hivetest.Logger(t)
	client := &GRPCClient{
		logger:                logger,
		db:                    db,
		prefixToIdentityTable: prefixTable,
	}

	// Initial check - table should be empty
	checkPrefixMapping(t, client, "192.168.1.1/24", identity.NumericIdentity(1), false)
	checkPrefixMapping(t, client, "192.168.1.2/16", identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.1/24, identity 1
	updatePrefixMapping(t, client, identity.NumericIdentity(1), "192.168.1.1/24")
	checkPrefixMapping(t, client, "192.168.1.1/24", identity.NumericIdentity(1), true)
	checkPrefixMapping(t, client, "192.168.1.2/32", identity.NumericIdentity(2), false)

	// Expected: 1 entry for 192.168.1.2/16, identity 2
	updatePrefixMapping(t, client, identity.NumericIdentity(2), "192.168.1.2/16")
	checkPrefixMapping(t, client, "192.168.1.2/16", identity.NumericIdentity(2), true)
	checkPrefixMapping(t, client, "192.168.1.1/32", identity.NumericIdentity(1), false)

	// Update mapping - modify existing entry
	updatePrefixMapping(t, client, identity.NumericIdentity(3), "192.168.1.2/16")
	checkPrefixMapping(t, client, "192.168.1.2/16", identity.NumericIdentity(3), true)
}
