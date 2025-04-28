// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"

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
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

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
				cell.Config(defaultConfig),
				cell.Provide(
					func(logger *slog.Logger) endpointmanager.EndpointManager {
						return endpointmanager.New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
					},

					func(em endpointmanager.EndpointManager, logger *slog.Logger) *ipcache.IPCache {
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
			cell.Config(defaultConfig),
			cell.Provide(
				func(logger *slog.Logger) endpointmanager.EndpointManager {
					return endpointmanager.New(logger, nil, &dummyEpSyncher{}, nil, nil, nil)
				},

				func(em endpointmanager.EndpointManager, logger *slog.Logger) *ipcache.IPCache {
					return ipcache.NewIPCache(&ipcache.Configuration{
						Context:           t.Context(),
						IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
					})
				},
				func(ipc *ipcache.IPCache) namemanager.NameManager {
					return namemanager.New(namemanager.ManagerParams{
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
			cfg.EnableStandaloneDNSProxy = true
			cfg.StandaloneDNSProxyServerPort = 40045
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
				policyRules := make(map[identity.NumericIdentity]policy.SelectorPolicy)
				policyRules[identity.NumericIdentity(count)] = nil
				fqdnDataServer.UpdatePolicyRules(policyRules, true)
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
			count++
			connected = true
			if count == 2 { // We expect to receive 2 responses from the server (one for initial connection and one for the first update)
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
