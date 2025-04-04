// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/hive"
	health "github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

func TestFQDNDataServer(t *testing.T) {
	// testutils.PrivilegedTest(t)

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
			serverPort:               40045,
			err:                      nil,
		},
		"Failure on running the server due to invalid server port": {
			port:                     1234,
			serverPort:               0,
			enableStandaloneDNSProxy: true,
			enableL7Proxy:            true,
			err:                      errors.New("listen tcp: address -1: invalid port"),
		},
	}

	for scenario, tt := range test {
		t.Run(scenario, func(t *testing.T) {

			em := endpointmanager.New(&dummyEpSyncher{}, nil, nil, nil, nil)
			pr := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())
			ipc := ipcache.NewIPCache(&ipcache.Configuration{
				Context:           context.TODO(),
				IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
				PolicyHandler:     pr.GetSelectorCache(),
				DatapathHandler:   em,
			})
			nm := namemanager.New(namemanager.ManagerParams{
				Config: namemanager.NameManagerConfig{
					MinTTL:            1,
					DNSProxyLockCount: defaults.DNSProxyLockCount,
					StateDir:          defaults.StateDir,
				},
				IPCache: ipc,
			})

			hive := hive.New(
				Cell,
				cell.Provide(func() *ipcache.IPCache {
					return ipc
				}),
				cell.Provide(func() endpointmanager.EndpointManager {
					return em
				}),
				cell.Provide(func() namemanager.NameManager { return nm }),
				cell.Provide(func(lc cell.Lifecycle, p health.Provider, jr job.Registry) job.Group {
					h := p.ForModule(cell.FullModuleID{"test"})
					jg := jr.NewGroup(h)
					lc.Append(jg)
					return jg
				}),
				cell.Provide(func(lc cell.Lifecycle) messagehandler.DNSRequestHandler {
					return messagehandler.NewDNSRequestHandler(
						messagehandler.DNSRequestHandlerParams{
							Lifecycle:         lc,
							Logger:            hivetest.Logger(t),
							NameManager:       nm,
							ProxyInstance:     nil,
							ProxyAccessLogger: nil,
						})
				}),
				cell.Invoke(newServer),
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			hive.RegisterFlags(flags)
			// Set the flags for the fqdn server
			flags.Set("enable-standalone-dns-proxy", fmt.Sprintf("%t", tt.enableStandaloneDNSProxy))
			flags.Set("to-fqdns-server-port", fmt.Sprintf("%d", tt.serverPort))

			// Set the flags for the l7 proxy(from cilium agent)
			option.Config.EnableL7Proxy = tt.enableL7Proxy
			option.Config.ToFQDNsProxyPort = tt.port

			tlog := hivetest.Logger(t)
			if err := hive.Start(tlog, context.Background()); err != nil {
				t.Fatalf("failed to start: %s", err)
			}

			// To check if the server is running, we need to create a gRPC client
			// and try to connect to the server. If the server is not running,
			// the client will return an error.
			// If the server is running, we will get a response from the server.
			conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", tt.serverPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

			c := pb.NewFQDNDataClient(conn)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			connected := false
			testutils.WaitUntil(func() bool {
				stream, err := c.StreamPolicyState(ctx)
				if err != nil {
					return false
				}
				response, err := stream.Recv()
				if err != nil {
					return false
				}
				if response == nil {
					return false
				} else {
					// Check if the response is not empty
					connected = true
					return true
				}
			}, 2*time.Second)
			if !connected && tt.err == nil {
				t.Fatalf("failed to connect to server")
			}

			hive.Stop(tlog, context.Background())
			if err != nil {
				t.Fatalf("failed to stop: %s", err)
			}
		})
	}
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, h cell.Health) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func TestHandleIPUpsert(t *testing.T) {
	endptMgr := endpointmanager.New(&dummyEpSyncher{}, nil, nil, nil, nil)

	// create a new server instance
	server := NewServer(endptMgr, nil, 1234, logging.DefaultSlogLogger)

	// Prepare a valid IPv4 (1.2.3.4/32).
	prefix := netip.MustParsePrefix("1.2.3.4/32")
	validCIDR := types.NewPrefixCluster(prefix, 0)
	dummyIdentity := ipcache.Identity{ID: 1}

	// Call OnIPIdentityCacheChange with identity 1 and ip: 1.2.3.4/32.
	// Expectation: currentIdentityToIp:{1: [1.2.3.4/32]}
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR, nil, nil, nil, dummyIdentity, 0, nil, 0)
	ips := server.currentIdentityToIp[dummyIdentity.ID]
	require.Len(t, ips, 1)
	require.Equal(t, net.ParseIP("1.2.3.4").To4(), ips[0])

	// Call OnIPIdentityCacheChange with Upsert with identity change(1->2) for same ip: 1.2.3.4/32.
	// Expectation: currentIdentityToIp:{2: [1.2.3.4/32]}
	dummyIdentity2 := ipcache.Identity{ID: 2}
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR, nil, nil, &dummyIdentity, dummyIdentity2, 0, nil, 0)
	ips = server.currentIdentityToIp[dummyIdentity2.ID]
	require.Len(t, ips, 1)
	require.Equal(t, net.ParseIP("1.2.3.4").To4(), ips[0])
	require.Empty(t, server.currentIdentityToIp[dummyIdentity.ID])

	// Call OnIPIdentityCacheChange with Upsert with identity 2 for ip: 4.5.6.7/32.
	// Expectation: currentIdentityToIp:{2: [1.2.3.4/32, 4.5.6.7/32]}
	prefix2 := netip.MustParsePrefix("4.5.6.7/32")
	validCIDR2 := types.NewPrefixCluster(prefix2, 0)
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR2, nil, nil, nil, dummyIdentity2, 0, nil, 0)
	ips = server.currentIdentityToIp[dummyIdentity2.ID]
	require.Len(t, ips, 2)

	// Call OnIPIdentityCacheChange with Upsert with identity 2 for ip: 8.9.10.11/24.
	// Expectation: currentIdentityToIp:{2: [1.2.3.4/32, 4.5.6.7/32]}
	prefix3 := netip.MustParsePrefix("8.9.10.11/24")
	validCIDR3 := types.NewPrefixCluster(prefix3, 0)
	server.OnIPIdentityCacheChange(ipcache.Upsert, validCIDR3, nil, nil, nil, dummyIdentity2, 0, nil, 0)
	ips = server.currentIdentityToIp[dummyIdentity2.ID]
	require.Len(t, ips, 2) // We expect 2 IPs for the same identity as /24 CIDR is not added.

	// Call OnIPIdentityCacheChange with Delete for identity 2 and ip: 4.5.6.7/32.
	// Expectation: currentIdentityToIp:{2: [1.2.3.4/32]}
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR2, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	ips = server.currentIdentityToIp[dummyIdentity2.ID]
	require.Len(t, ips, 1)
	require.Equal(t, net.ParseIP("1.2.3.4").To4(), ips[0])

	// Call again OnIPIdentityCacheChange with Delete for identity 2 and ip: 4.5.6.7/32.
	// Expectation: currentIdentityToIp:{2: [1.2.3.4/32]}
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR2, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	ips = server.currentIdentityToIp[dummyIdentity2.ID]
	require.Len(t, ips, 1)
	require.Equal(t, net.ParseIP("1.2.3.4").To4(), ips[0])

	// Call again OnIPIdentityCacheChange with Delete for identity 2 and ip: 1.2.3.4/32.
	// Expectation: currentIdentityToIp:{}
	server.OnIPIdentityCacheChange(ipcache.Delete, validCIDR, nil, nil, &dummyIdentity2, dummyIdentity2, 0, nil, 0)
	require.Empty(t, server.currentIdentityToIp)
	require.Empty(t, server.currentIdentityToIp[dummyIdentity2.ID])
}
