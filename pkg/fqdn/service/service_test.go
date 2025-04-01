// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestRunServer(t *testing.T) {
	testutils.PrivilegedTest(t)

	test := map[string]struct {
		port   int
		server *FQDNDataServer
		err    error
	}{
		"Success on running the server": {
			port: 1234,
			server: &FQDNDataServer{
				log: logging.DefaultSlogLogger,
			},
			err: nil,
		},
		"Failure on running the server": {
			port: -1,
			server: &FQDNDataServer{
				log: logging.DefaultSlogLogger,
			},
			err: errors.New("listen tcp: address -1: invalid port"),
		},
	}

	for scenario, tt := range test {
		t.Run(scenario, func(t *testing.T) {

			go func() {
				err := RunServer(tt.port, tt.server)
				if err != nil {
					require.Equal(t, tt.err.Error(), err.Error())
					// If the error is not nil, then terminate the test
					return
				} else {
					require.Equal(t, tt.err, err)
				}
			}()

			// Give the server some time to start
			time.Sleep(1 * time.Second)

			// Try to connect to the server
			conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", tt.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

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
	server := NewServer(endptMgr, func(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) error {
		return nil
	}, logging.DefaultSlogLogger)

	// Prepare a valid IPv4 (1.2.3.4/32).
	prefix := netip.MustParsePrefix("1.2.3.4")
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
	require.Len(t, server.currentIdentityToIp[dummyIdentity.ID], 0)

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
}
