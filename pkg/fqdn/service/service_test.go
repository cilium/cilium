// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"iter"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

var (
	sourceIdentity   = identity.NumericIdentity(1)
	sourceEndpointId = uint16(101)
	destIdentity     = identity.NumericIdentity(2)
	destEndpointId   = uint16(102)
	sourceIP         = "1.2.3.4/32"
	sourceIPV6       = "2001:db8::1/128"
	destIP           = "5.6.7.8/32"
)

// mockEndpointManager provides a simple test implementation that returns
// fake endpoints for specific test IPs
type mockEndpointManager struct {
	endpointmanager.EndpointManager
}

func (m *mockEndpointManager) LookupIP(ip netip.Addr) *endpoint.Endpoint {
	// Return mock endpoints for test IPs
	sourceAddr := netip.MustParsePrefix(sourceIP).Addr()
	destAddr := netip.MustParsePrefix(destIP).Addr()

	switch ip {
	case sourceAddr:
		ep := &endpoint.Endpoint{ID: sourceEndpointId,
			DNSZombies: &fqdn.DNSZombieMappings{
				Mutex: lock.Mutex{},
			},
		}

		ep.UpdateLogger(nil)
		ep.DNSHistory = fqdn.NewDNSCache(0)

		return ep
	case destAddr:
		ep := &endpoint.Endpoint{ID: destEndpointId}
		return ep
	default:
		// Fall back to the real implementation for other IPs
		return m.EndpointManager.LookupIP(ip)
	}
}

type bufconnListener struct {
	buf *bufconn.Listener
}

func newBufconnListener(lis *bufconn.Listener) *bufconnListener {
	return &bufconnListener{buf: lis}
}

func (b *bufconnListener) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	return b.buf, nil
}

type mockUpdater struct{}

func (m *mockUpdater) UpdateIdentities(_, _ identity.IdentityMap) <-chan struct{} {
	out := make(chan struct{})
	close(out)
	return out
}

func TestFQDNDataServer(t *testing.T) {

	test := map[string]struct {
		port                     int
		enableL7Proxy            bool
		enableStandaloneDNSProxy bool
		serverPort               int
		err                      error
	}{
		"Successfully running the server": {
			port:                     1234,
			enableL7Proxy:            true,
			enableStandaloneDNSProxy: true,
			// Random port for the server should run ideally
			// but for the test we are using bufconn
			// which will not use the port
			serverPort: 40045,
			err:        nil,
		},
	}

	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)

	for scenario, tt := range test {
		t.Run(scenario, func(t *testing.T) {

			h := hive.New(
				cell.Config(DefaultConfig),
				cell.Provide(
					func(logger *slog.Logger) endpointmanager.EndpointsLookup {
						return endpointmanager.New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, endpointmanager.EndpointManagerConfig{})
					},

					func(logger *slog.Logger) *ipcache.IPCache {
						return ipcache.NewIPCache(&ipcache.Configuration{
							Context:           t.Context(),
							Logger:            logger,
							IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
							IdentityUpdater:   &mockUpdater{},
						})
					},
					func(ipc *ipcache.IPCache, logger *slog.Logger) namemanager.NameManager {
						return namemanager.New(namemanager.ManagerParams{
							Logger: logger,
							Config: namemanager.NameManagerConfig{
								MinTTL:            1,
								DNSProxyLockCount: defaults.DNSProxyLockCount,
								StateDir:          defaults.StateDir,
							},
							IPCache: ipc,
						})
					},
					func(lc cell.Lifecycle, logger *slog.Logger) messagehandler.DNSMessageHandler {
						return messagehandler.NewDNSMessageHandler(
							messagehandler.DNSMessageHandlerParams{
								Lifecycle:         lc,
								Logger:            logger,
								NameManager:       nil,
								ProxyAccessLogger: nil,
							})
					},
					func() *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableL7Proxy:    tt.enableL7Proxy,
							ToFQDNsProxyPort: tt.port,
						}
					},
					func() listenConfig {
						return newBufconnListener(lis)
					},
					newIdentityToIPsTable,
					newPolicyRulesTable,
					newServer,
				),
				cell.Invoke(func(_ *FQDNDataServer) {}))

			hive.AddConfigOverride(
				h,
				func(cfg *FQDNConfig) {
					cfg.EnableStandaloneDNSProxy = tt.enableStandaloneDNSProxy
					cfg.StandaloneDNSProxyServerPort = tt.serverPort
				})

			tlog := hivetest.Logger(t)
			if err := h.Start(tlog, t.Context()); err != nil {
				t.Fatalf("failed to start: %s", err)
			}

			// To check if the server is running, we need to create a gRPC client
			// and try to connect to the server. If the server is not running,
			// the client will return an error.
			// If the server is running, we will get a response from the server.
			conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)

			c := pb.NewFQDNDataClient(conn)

			connected := false
			testutils.WaitUntil(func() bool {
				stream, err := c.StreamPolicyState(t.Context())
				if err != nil {
					return false
				}
				response, err := stream.Recv()
				if err != nil {
					return false
				}

				if response.GetRequestId() == "" {
					return false
				} else {
					connected = true
					return true
				}
			}, 5*time.Second)

			// If the server is running, we should get a response from the server
			if !connected && tt.err == nil {
				t.Fatalf("failed to connect to server")
			}

			t.Cleanup(func() {
				//Stop the client
				conn.Close()
				// Stop the server
				if err := h.Stop(tlog, context.TODO()); err != nil {
					t.Fatalf("failed to stop: %s", err)
				}
			})
		})
	}
}

func setupServer(t *testing.T, port int, enableL7Proxy bool, enableStandaloneDNSProxy bool, standaloneDNSProxyServerPort int, lis *bufconn.Listener) (*hive.Hive, *FQDNDataServer) {

	var fqdnDataServer *FQDNDataServer
	h := hive.New(
		cell.Module(
			"test-fqdn-grpc-server",
			"Test FQDN gRPC server",
			cell.Config(DefaultConfig),
			cell.Provide(
				func(logger *slog.Logger) endpointmanager.EndpointsLookup {
					baseEM := endpointmanager.New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, endpointmanager.EndpointManagerConfig{})
					return &mockEndpointManager{EndpointManager: baseEM}
				},

				func(logger *slog.Logger) *ipcache.IPCache {
					return ipcache.NewIPCache(&ipcache.Configuration{
						Context:           t.Context(),
						IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
					})
				},
				func(ipc *ipcache.IPCache, logger *slog.Logger) namemanager.NameManager {
					return namemanager.New(namemanager.ManagerParams{
						Logger: logger,
						Config: namemanager.NameManagerConfig{
							MinTTL:            1,
							DNSProxyLockCount: defaults.DNSProxyLockCount,
							StateDir:          defaults.StateDir,
						},
						IPCache: ipc,
					})
				},
				func(lc cell.Lifecycle, logger *slog.Logger, nm namemanager.NameManager) messagehandler.DNSMessageHandler {
					return messagehandler.NewDNSMessageHandler(
						messagehandler.DNSMessageHandlerParams{
							Lifecycle:         lc,
							Logger:            logger,
							NameManager:       nm,
							ProxyAccessLogger: nil,
						})
				},
				func() *option.DaemonConfig {
					return &option.DaemonConfig{
						EnableL7Proxy:    enableL7Proxy,
						ToFQDNsProxyPort: port,
					}
				},
				func() listenConfig {
					return newBufconnListener(lis)
				},
				newPolicyRulesTable,
				newIdentityToIPsTable,
				newServer,
			)),
		cell.Invoke(func(_f *FQDNDataServer) {
			fqdnDataServer = _f
		}))

	hive.AddConfigOverride(
		h,
		func(cfg *FQDNConfig) {
			cfg.EnableStandaloneDNSProxy = enableStandaloneDNSProxy
			cfg.StandaloneDNSProxyServerPort = standaloneDNSProxyServerPort
		})
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	t.Cleanup(func() {
		// Stop the server
		if err := h.Stop(tlog, context.TODO()); err != nil {
			t.Fatalf("failed to stop: %s", err)
		}
	})
	return h, fqdnDataServer
}

// addEndpointMapping adds source and destination endpoint to the server.
func addEndpointMapping(t *testing.T, fqdnDataServer *FQDNDataServer) {
	// Add the source endpoint mapping to the server with 2 IPs (IPv4 + IPv6)
	prefix := netip.MustParsePrefix(sourceIP)
	validCIDR := types.NewPrefixCluster(prefix, 0)
	dummyIdentity := ipcache.Identity{ID: sourceIdentity}
	fqdnDataServer.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR, nil, nil, nil, dummyIdentity, 0, nil, 0)
	prefix = netip.MustParsePrefix(sourceIPV6)
	validCIDR = types.NewPrefixCluster(prefix, 0)
	fqdnDataServer.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR, nil, nil, nil, dummyIdentity, 0, nil, 0)
	// Add the destination endpoint mapping to the server
	prefix = netip.MustParsePrefix(destIP)
	validCIDR = types.NewPrefixCluster(prefix, 0)
	dummyIdentity = ipcache.Identity{ID: destIdentity}
	fqdnDataServer.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR, nil, nil, nil, dummyIdentity, 0, nil, 0)
}

// Test the gRPC server and client connection
// GRPC server should be able to create a stream with the client.
// It should send the current policy state to the client and the client should be able to receive it.
// The server starts a watch on the policy rules being updated in the database.
// On each update to the policy rules, the server should send the updated policy state to the client.
func TestSuccessfullyStreamPolicyState(t *testing.T) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)
	_, fqdnDataServer := setupServer(t, 1234, true, true, 40045, lis)

	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	// Update the endpoint information(identity to IP) in the server
	addEndpointMapping(t, fqdnDataServer)

	c := pb.NewFQDNDataClient(conn)

	connected := false
	var receivedResultClient *pb.PolicyState
	var clientStream pb.FQDNData_StreamPolicyStateClient
	var closeChan = make(chan struct{}, 1)
	// A goroutine to simulate the server sending policy rules updates to grpc server.
	// This will run in the background and update the policy rules every 2 seconds
	// This mimics the CNP updates that would normally trigger the server to send policy state updates to the client.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		count := 1
		for {
			select {
			case <-closeChan:
				return
			case <-ticker.C:
				policyRules := createSelectorPolicies(count, ValidWithDNS)
				fqdnDataServer.UpdatePolicyRules(policyRules)
				count++
			}
		}
	}()

	clientStream, err = c.StreamPolicyState(t.Context())
	require.NoError(t, err)

	count := 0
	testutils.WaitUntil(func() bool {
		receivedResultClient, err = clientStream.Recv()
		if err != nil {
			return false
		}
		if receivedResultClient.GetRequestId() != "" {
			t.Logf("Received request from client: %s", receivedResultClient.GetRequestId())
			clientStream.Send(&pb.PolicyStateResponse{
				RequestId: receivedResultClient.GetRequestId(),
				Response:  pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
			})
			// Increment the count for each response received
			if len(receivedResultClient.GetEgressL7DnsPolicy()) > 0 {
				receivedRules := receivedResultClient.GetEgressL7DnsPolicy()
				sourceEndpointIDPolicyCount := 0
				for _, r := range receivedRules {
					if r.GetSourceEndpointId() == uint32(sourceEndpointId) {
						sourceEndpointIDPolicyCount++
					}
				}
				// Ensure no duplicate policies for the same endpoint
				require.Equal(t, 1, sourceEndpointIDPolicyCount)
				count++
			}
			connected = true
			if count == 2 { // We expect to receive 2 responses from the server as we are adding 2 identities with policy rules
				return true
			}
		}
		return false
	}, 5*time.Second)

	// If the server is running, we should get a response from the server
	if !connected {
		t.Fatalf("failed to connect to server")
	}

	// close the connection from the client
	// and check if the server received the response
	if clientStream != nil {
		clientStream.CloseSend()
	} else {
		t.Fatalf("clientStream is nil, cannot close stream")
	}

	// close the goroutine that is sending updates to the server
	closeChan <- struct{}{}

	t.Cleanup(func() {
		//Stop the client
		conn.Close()
	})
}

// Updates to the identity to IPs mapping should trigger the server to send the updated policy state to the client.
func TestSuccessfullyStreamPolicyStateOnIdentityToIPsChange(t *testing.T) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)
	_, fqdnDataServer := setupServer(t, 1234, true, true, 40045, lis)

	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	// Add the policy rules to the server
	fqdnDataServer.UpdatePolicyRules(createSelectorPolicies(2, ValidWithDNS))

	c := pb.NewFQDNDataClient(conn)
	connected := false
	var receivedResultClient *pb.PolicyState
	var clientStream pb.FQDNData_StreamPolicyStateClient
	var closeChan = make(chan struct{}, 1)
	// A goroutine to simulate the identity to IPs mapping updates.
	// This will run in the background and update the identity to IPs mapping every 2 seconds.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		count := 1
		for {
			select {
			case <-closeChan:
				return
			case <-ticker.C:
				if count <= 2 {
					addEndpointMapping(t, fqdnDataServer)
				}
				count++
			}
		}
	}()

	clientStream, err = c.StreamPolicyState(t.Context())
	require.NoError(t, err)

	count := 0
	testutils.WaitUntil(func() bool {
		receivedResultClient, err = clientStream.Recv()
		if err != nil {
			return false
		}
		if receivedResultClient.GetRequestId() != "" {
			t.Logf("Received request from client: %s", receivedResultClient.GetRequestId())
			clientStream.Send(&pb.PolicyStateResponse{
				RequestId: receivedResultClient.GetRequestId(),
				Response:  pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
			})
			if len(receivedResultClient.GetIdentityToEndpointMapping()) > 0 {
				count++
			}
			connected = true
			if count == 2 { // We expect to receive 2 responses from the server
				return true
			}
		}
		return false
	}, 5*time.Second)

	// If the server is running, we should get a response from the server
	if !connected {
		t.Fatalf("failed to connect to server")
	}

	// close the connection from the client
	// and check if the server received the response
	if clientStream != nil {
		clientStream.CloseSend()
	} else {
		t.Fatalf("clientStream is nil, cannot close stream")
	}

	// close the goroutine that is sending updates to the server
	closeChan <- struct{}{}

	t.Cleanup(func() {
		//Stop the client
		conn.Close()
	})
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, h cell.Health) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func TestHandleIPUpsert(t *testing.T) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)

	// create a new server instance
	_, server := setupServer(t, 1234, true, true, 40045, lis)

	// Prepare a valid IPv4 (1.2.3.4/32).
	prefix := netip.MustParsePrefix("1.2.3.4/32")
	validCIDR := types.NewPrefixCluster(prefix, 0)
	dummyIdentity := ipcache.Identity{ID: 1}

	// Call OnIPIdentityCacheChange with identity 1 and ip: 1.2.3.4/32.
	// Expectation: currentIdentityToIP:{1: [1.2.3.4/32]}
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR, nil, nil, nil, dummyIdentity, 0, nil, 0)
	identityToIP, _, found := server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity.ID))
	require.True(t, found)
	require.Equal(t, 1, identityToIP.IPs.Len())
	require.True(t, identityToIP.IPs.Has(prefix))

	// Call OnIPIdentityCacheChange with Upsert with identity change(1->2) for same ip: 1.2.3.4/32.
	// Expectation: currentIdentityToIP:{2: [1.2.3.4/32]}
	dummyIdentity2 := ipcache.Identity{ID: 2}
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR, nil, nil, &dummyIdentity, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)
	require.Equal(t, 1, identityToIP.IPs.Len())
	require.True(t, identityToIP.IPs.Has(prefix))
	_, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)

	// Call OnIPIdentityCacheChange with Upsert with identity 2 for ip: 4.5.6.7/32.
	// Expectation: currentIdentityToIP:{2: [1.2.3.4/32, 4.5.6.7/32]}
	prefix2 := netip.MustParsePrefix("4.5.6.7/32")
	validCIDR2 := types.NewPrefixCluster(prefix2, 0)
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR2, nil, nil, nil, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)
	require.Equal(t, 2, identityToIP.IPs.Len())

	// Call OnIPIdentityCacheChange with Upsert with identity 2 for ip: 8.9.10.11/24.
	// Expectation: currentIdentityToIP:{2: [1.2.3.4/32, 4.5.6.7/32, 8.9.10.11/24]}
	prefix3 := netip.MustParsePrefix("8.9.10.11/24")
	validCIDR3 := types.NewPrefixCluster(prefix3, 0)
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR3, nil, nil, nil, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)
	require.Equal(t, 3, identityToIP.IPs.Len())
	_, ipv4 := server.prefixLengths.ToBPFData()
	require.Len(t, ipv4, 3) // [32 24 0]

	// Call OnIPIdentityCacheChange with Delete for identity 2 and ip: 10.10.10.10/24.
	// Expectation: currentIdentityToIP:{2: [1.2.3.4/32, 4.5.6.7/32]}
	prefix4 := netip.MustParsePrefix("10.10.10.10/24")
	validCIDR4 := types.NewPrefixCluster(prefix4, 0)
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR4, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)
	require.Equal(t, 3, identityToIP.IPs.Len())
	_, ipv4 = server.prefixLengths.ToBPFData()
	require.Len(t, ipv4, 3) // [32 24  0]

	// Call OnIPIdentityCacheChange with Delete for identity 2 and ip: 8.9.10.11/24.
	// Expectation: currentIdentityToIP:{2: [1.2.3.4/32, 4.5.6.7/32]}
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR3, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)
	require.Equal(t, 2, identityToIP.IPs.Len())
	_, ipv4 = server.prefixLengths.ToBPFData()
	require.Len(t, ipv4, 2) // [32  0]

	// Call OnIPIdentityCacheChange with Delete for identity 2 and ip: 4.5.6.7/32.
	// Expectation: currentIdentityToIP:{2: [1.2.3.4/32]}
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR2, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)
	require.Equal(t, 1, identityToIP.IPs.Len())
	require.True(t, identityToIP.IPs.Has(prefix))

	// Call again OnIPIdentityCacheChange with Delete for identity 2 and ip: 4.5.6.7/32.
	// Expectation: currentIdentityToIP:{2: [1.2.3.4/32]}
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR2, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.True(t, found)
	require.Equal(t, 1, identityToIP.IPs.Len())
	require.True(t, identityToIP.IPs.Has(prefix))

	// Call again OnIPIdentityCacheChange with Delete for identity 2 and ip: 1.2.3.4/32.
	// Expectation: currentIdentityToIP:{}
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	identityToIP, _, found = server.identityToIPsTable.Get(server.db.ReadTxn(), idIndexIdentityToIP.Query(dummyIdentity2.ID))
	require.False(t, found)

	data := server.identityToIPsTable.All(server.db.ReadTxn())
	for d := range data {
		t.Fatalf("Expected no data in identityToIPsTable, but found: %v", d)
	}
}

// TestIsEnabled tests the IsEnabled method of FQDNDataServer
func TestIsEnabled(t *testing.T) {
	tests := map[string]struct {
		enableL7Proxy                bool
		enableStandaloneDNSProxy     bool
		standaloneDNSProxyServerPort int
		toFQDNsProxyPort             int
		expectedEnabled              bool
	}{
		"Standalone DNS proxy enabled with valid configuration": {
			enableL7Proxy:                true,
			enableStandaloneDNSProxy:     true,
			standaloneDNSProxyServerPort: 40045,
			toFQDNsProxyPort:             40046,
			expectedEnabled:              true,
		},
		"Standalone DNS proxy disabled": {
			enableL7Proxy:                true,
			enableStandaloneDNSProxy:     false,
			standaloneDNSProxyServerPort: 40045,
			toFQDNsProxyPort:             40046,
			expectedEnabled:              false,
		},
		"L7 proxy disabled": {
			enableL7Proxy:                false,
			enableStandaloneDNSProxy:     true,
			standaloneDNSProxyServerPort: 40045,
			toFQDNsProxyPort:             40046,
			expectedEnabled:              false,
		},
		"Invalid standalone DNS proxy server port": {
			enableL7Proxy:                true,
			enableStandaloneDNSProxy:     true,
			standaloneDNSProxyServerPort: 0,
			toFQDNsProxyPort:             40046,
			expectedEnabled:              false,
		},
		"Invalid ToFQDNs proxy port": {
			enableL7Proxy:                true,
			enableStandaloneDNSProxy:     true,
			standaloneDNSProxyServerPort: 40045,
			toFQDNsProxyPort:             0,
			expectedEnabled:              false,
		},
	}

	for scenario, tt := range tests {
		t.Run(scenario, func(t *testing.T) {
			buffer := 1024 * 1024
			lis := bufconn.Listen(buffer)

			_, server := setupServer(t, tt.toFQDNsProxyPort, tt.enableL7Proxy, tt.enableStandaloneDNSProxy, tt.standaloneDNSProxyServerPort, lis)

			enabled := server.IsEnabled()
			require.Equal(t, tt.expectedEnabled, enabled)
		})
	}
}

// PolicyType defines the type of selector policy to create
type PolicyType int

const (
	ValidWithDNS    PolicyType = iota // Valid policy with DNS rules
	ValidWithoutDNS                   // Valid policy without DNS rules
)

// testSelectorPolicy is a configurable mock selector policy
type testSelectorPolicy struct {
	policyType PolicyType
}

func (sp *testSelectorPolicy) DistillPolicy(logger *slog.Logger, owner policy.PolicyOwner, redirects map[string]uint16) *policy.EndpointPolicy {
	return nil
}

func (sp *testSelectorPolicy) RedirectFilters() iter.Seq2[*policy.L4Filter, policy.PerSelectorPolicyTuple] {
	switch sp.policyType {
	case ValidWithDNS:
		return sp.createValidDNSPolicy()
	case ValidWithoutDNS:
		return sp.createValidNonDNSPolicy()
	default:
		return sp.createValidDNSPolicy()
	}
}

// createSelectorCache creates a common selector cache setup used by both DNS and non-DNS policies
func (sp *testSelectorPolicy) createSelectorCache() (policy.CachedSelector, *policy.SelectorCache) {
	dnsServerIdentity := destIdentity
	// slogloggercheck: the default logger is enough for tests.
	sc := policy.NewSelectorCache(logging.DefaultSlogLogger,
		identity.IdentityMap{
			dnsServerIdentity: labels.LabelArray{
				labels.Label{
					Key:   "app",
					Value: "test",
				},
			},
		},
	)
	sc.SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	dummySelectorCacheUser := &testpolicy.DummySelectorCacheUser{}
	endpointSelector := api.NewESFromLabels(labels.ParseSelectLabel("app=test"))
	cachedSelector, _ := sc.AddIdentitySelectorForTest(dummySelectorCacheUser, policy.EmptyStringLabels, endpointSelector)
	return cachedSelector, sc
}

// createPolicyIterator creates a common iterator for policy maps
func createPolicyIterator(policyMaps policy.L4PolicyMaps) iter.Seq2[*policy.L4Filter, policy.PerSelectorPolicyTuple] {
	return func(yield func(*policy.L4Filter, policy.PerSelectorPolicyTuple) bool) {
		for l4 := range policyMaps.Filters() {
			for cs, perSelectorPolicy := range l4.PerSelectorPolicies {
				if !yield(l4, policy.PerSelectorPolicyTuple{
					Policy:   perSelectorPolicy,
					Selector: cs,
				}) {
					return
				}
			}
		}
	}
}

func (sp *testSelectorPolicy) createValidDNSPolicy() iter.Seq2[*policy.L4Filter, policy.PerSelectorPolicyTuple] {
	cachedSelector, _ := sp.createSelectorCache()
	expectedPolicy := policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			Ingress:  false,
			PerSelectorPolicies: policy.L7DataMap{
				cachedSelector: &policy.PerSelectorPolicy{
					Verdict:  policytypes.Allow,
					L7Parser: policy.ParserTypeDNS,
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{
							{
								MatchName:    "example.com",
								MatchPattern: "*.cilium.io",
							},
						},
					},
				},
			},
		},
	})

	return createPolicyIterator(expectedPolicy)
}

func (sp *testSelectorPolicy) createValidNonDNSPolicy() iter.Seq2[*policy.L4Filter, policy.PerSelectorPolicyTuple] {
	cachedSelector, _ := sp.createSelectorCache()

	// Create a policy without DNS rules (HTTP policy)
	expectedPolicy := policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x06,
			Ingress:  false,
			PerSelectorPolicies: policy.L7DataMap{
				cachedSelector: &policy.PerSelectorPolicy{
					Verdict:  policytypes.Allow,
					L7Parser: policy.ParserTypeHTTP, // HTTP instead of DNS
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/api"},
						},
					},
				},
			},
		},
	})

	return createPolicyIterator(expectedPolicy)
}

func createSelectorPolicies(count int, policyType PolicyType) map[identity.NumericIdentity]policy.SelectorPolicy {
	policies := make(map[identity.NumericIdentity]policy.SelectorPolicy, count)
	for i := 1; i <= count; i++ {
		policies[identity.NumericIdentity(i)] = &testSelectorPolicy{
			policyType: policyType,
		}
	}
	return policies
}

// TestUpdatePolicyRules tests the UpdatePolicyRules method of FQDNDataServer
// It verifies that the method correctly updates the policy rules table and handles different scenarios.
// The test covers adding, updating, and re-applying policies, ensuring that only DNS policies
// create entries in the policyRulesTable.
func TestUpdatePolicyRules(t *testing.T) {
	// Helper function to count and validate stored policy rules
	validateStoredPolicyRules := func(t *testing.T, server *FQDNDataServer, expectedDNSPolicies int, step string) {
		storedRules := server.policyRulesTable.All(server.db.ReadTxn())
		storeRulesCount := 0
		for rule := range storedRules {
			if rule.PolicyRules != nil {
				storeRulesCount++
			}
		}
		// Only DNS policies should create entries in policyRulesTable
		require.Equal(t, expectedDNSPolicies, storeRulesCount, "%s: Expected %d DNS policies, got %d", step, expectedDNSPolicies, storeRulesCount)
	}

	// Create fresh server instance
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)
	_, server := setupServer(t, 1234, true, true, 40045, lis)

	// Step 1: Start with empty policy map
	t.Log("Step 1: Starting with empty policy map")
	emptyPolicies := make(map[identity.NumericIdentity]policy.SelectorPolicy)
	err := server.UpdatePolicyRules(emptyPolicies)
	require.NoError(t, err, "Failed to handle empty policies")
	validateStoredPolicyRules(t, server, 0, "Empty policies")

	// Step 2: Apply HTTP policy first (should not create DNS table entries)
	t.Log("Step 2: Adding HTTP policy for identity 1 (should not create table entries)")
	httpPolicies := createSelectorPolicies(1, ValidWithoutDNS) // Identity 1 with HTTP policy
	err = server.UpdatePolicyRules(httpPolicies)
	require.NoError(t, err, "Failed to add HTTP policy")
	validateStoredPolicyRules(t, server, 0, "HTTP policy added (no DNS table change)")

	// Step 3: Apply DNS policy for identity 1 and 2
	t.Log("Step 3: Adding DNS policy for identity 1 and 2")
	dnsPolicies := createSelectorPolicies(1, ValidWithDNS) // Identity 1 with DNS policy, but we'll use it for identity 2
	dnsPolicies[identity.NumericIdentity(2)] = dnsPolicies[identity.NumericIdentity(1)]
	err = server.UpdatePolicyRules(dnsPolicies)
	require.NoError(t, err, "Failed to add DNS policy")
	validateStoredPolicyRules(t, server, 2, "DNS policy added")

	// Step 4: Update existing DNS policy with HTTP policy for identity 2
	t.Log("Step 4: Update existing DNS policy with HTTP policy for identity 2")
	dnsPolicies[identity.NumericIdentity(2)] = &testSelectorPolicy{policyType: ValidWithoutDNS}
	err = server.UpdatePolicyRules(dnsPolicies)
	require.NoError(t, err, "Failed to add HTTP policy")
	validateStoredPolicyRules(t, server, 1, "DNS policy removed after HTTP update")

	// Step 5: Apply different DNS policy for identity 4 (should add another entry)
	t.Log("Step 5: Adding different DNS policy for identity 4")
	dnsPolicies[identity.NumericIdentity(4)] = dnsPolicies[identity.NumericIdentity(1)]
	err = server.UpdatePolicyRules(dnsPolicies)
	require.NoError(t, err, "Failed to add second DNS policy")
	validateStoredPolicyRules(t, server, 2, "Second DNS policy added")

	// Step 6: Apply same DNS policy again (should be idempotent)
	t.Log("Step 6: Re-applying same DNS policy (should be idempotent)")
	err = server.UpdatePolicyRules(dnsPolicies)
	require.NoError(t, err, "Failed to re-apply DNS policy")
	validateStoredPolicyRules(t, server, 2, "DNS policy re-applied")

	// Step 7: Test nil policies (should be no-op)
	t.Log("Step 7: Testing with nil policies (should be no-op)")
	err = server.UpdatePolicyRules(nil)
	require.NoError(t, err, "Failed to handle nil policies")
	validateStoredPolicyRules(t, server, 2, "Nil policies (no-op)")

	// Step 8: Test deletion of DNS policies for identity 1
	t.Log("Step 8: Deleting DNS policy for identity 1")
	dnsPolicies[identity.NumericIdentity(1)] = nil
	err = server.UpdatePolicyRules(dnsPolicies)
	require.NoError(t, err, "Failed to delete DNS policy for identity 1")
	validateStoredPolicyRules(t, server, 1, "DNS policy for identity 1 deleted")
}

// TestUpdateMappingRequest tests the UpdateMappingRequest method focusing on key functionality
func TestUpdateMappingRequest(t *testing.T) {
	buffer := 1024 * 1024
	lis := bufconn.Listen(buffer)
	_, server := setupServer(t, 1234, true, true, 40045, lis)

	addEndpointMapping(t, server) // Add a valid endpoint mapping for the test

	testCases := map[string]struct {
		mapping          *pb.FQDNMapping
		expectedResponse pb.ResponseCode
		shouldError      bool
		errorMessage     string
	}{
		"nil source IP should return invalid argument error": {
			mapping: &pb.FQDNMapping{
				SourceIp:     nil,
				Fqdn:         "example.com",
				RecordIp:     [][]byte{[]byte("10.20.30.40")},
				Ttl:          300,
				ResponseCode: dns.RcodeSuccess,
			},
			expectedResponse: pb.ResponseCode_RESPONSE_CODE_ERROR_INVALID_ARGUMENT,
			shouldError:      true,
			errorMessage:     "source IP is nil in FQDN mapping",
		},
		"empty record IPs should return success": {
			mapping: &pb.FQDNMapping{
				SourceIp: []byte("1.2.3.4"),
				Fqdn:     "example.com",
				RecordIp: [][]byte{}, // Empty record IPs
			},
			expectedResponse: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
			shouldError:      false,
		},
		"endpoint not found should return error": {
			mapping: &pb.FQDNMapping{
				SourceIp:     []byte("192.168.1.1"), // Non-existent IP
				Fqdn:         "example.com",
				RecordIp:     [][]byte{[]byte("1.2.3.4")},
				Ttl:          300,
				ResponseCode: dns.RcodeSuccess,
			},
			expectedResponse: pb.ResponseCode_RESPONSE_CODE_ERROR_ENDPOINT_NOT_FOUND,
			shouldError:      true,
			errorMessage:     "endpoint not found for IP",
		},
		"fqdn is empty string should return error": {
			mapping: &pb.FQDNMapping{
				SourceIp:     []byte("1.2.3.4"),
				Fqdn:         "",
				RecordIp:     [][]byte{[]byte("5.6.7.8")},
				Ttl:          300,
				ResponseCode: dns.RcodeSuccess,
			},
			expectedResponse: pb.ResponseCode_RESPONSE_CODE_ERROR_INVALID_ARGUMENT,
			shouldError:      true,
			errorMessage:     "FQDN is nil or empty in FQDN mapping",
		},
		"valid mapping should succeed": {
			mapping: &pb.FQDNMapping{
				SourceIp:     []byte("1.2.3.4"),
				Fqdn:         "example.com",
				RecordIp:     [][]byte{[]byte("5.6.7.8")},
				Ttl:          300,
				ResponseCode: dns.RcodeSuccess,
			},
			expectedResponse: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
			shouldError:      false,
		},
	}

	for scenario, tc := range testCases {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			response, err := server.UpdateMappingRequest(ctx, tc.mapping)

			if tc.shouldError {
				require.Error(t, err, "Expected an error for scenario: %s", scenario)
				if tc.errorMessage != "" {
					require.Contains(t, err.Error(), tc.errorMessage, "Error message should contain expected text")
				}
			} else {
				require.NoError(t, err, "Expected no error for scenario: %s", scenario)
			}

			require.NotNil(t, response, "Response should not be nil")
			require.Equal(t, tc.expectedResponse, response.Response, "Response code mismatch for scenario: %s", scenario)
		})
	}
}
