// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/dns"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/cilium/pkg/u8proto"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

var testLog = slog.Default()

func TestNewStandaloneDNSProxy(t *testing.T) {
	tests := []struct {
		name string
		args *StandaloneDNSProxyArgs
		err  error
	}{
		{
			name: "Valid grpc server port",
			args: &StandaloneDNSProxyArgs{
				toFQDNsServerPort: 1234,
				enableL7Proxy:     true,
			},
			err: nil,
		},
		{
			name: "Invalid grpc server port",
			args: &StandaloneDNSProxyArgs{
				toFQDNsServerPort: 0,
				enableL7Proxy:     true,
			},
			err: errors.New("toFQDNsServerPort is 0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sdp, err := NewStandaloneDNSProxy(tt.args, testLog)
			if err != nil {
				require.Equal(t, tt.err, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, sdp)
		})
	}
}

func TestStandaloneDNSProxyWhenDisabled(t *testing.T) {
	test := map[string]struct {
		args *StandaloneDNSProxyArgs
		err  error
	}{
		"L7ProxyDisbaled": {
			args: &StandaloneDNSProxyArgs{
				toFQDNsServerPort:        4321,
				enableStandaloneDNsProxy: false,
				enableL7Proxy:            false,
			},
			err: nil,
		},
		"StandaloneDNSProxyDisabled": {
			args: &StandaloneDNSProxyArgs{
				toFQDNsServerPort:        4321,
				enableStandaloneDNsProxy: false,
				enableL7Proxy:            true,
			},
			err: nil,
		},
	}

	for name, tt := range test {
		t.Run(name, func(t *testing.T) {
			sdp, err := NewStandaloneDNSProxy(tt.args, testLog)
			require.NoError(t, err)
			require.Nil(t, sdp.DNSProxy)
		})
	}
}

func TestStandaloneDNSProxyWhenEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)

	sdp, err := NewStandaloneDNSProxy(&StandaloneDNSProxyArgs{
		DNSProxyConfig: dnsproxy.DNSProxyConfig{
			Address:                "",
			Port:                   1234,
			IPv4:                   true,
			IPv6:                   true,
			EnableDNSCompression:   true,
			MaxRestoreDNSIPs:       10,
			ConcurrencyLimit:       10,
			ConcurrencyGracePeriod: 10,
			DNSProxyType:           dnsproxy.StandaloneDNSProxy,
		},
		toFQDNsServerPort:        4321,
		enableStandaloneDNsProxy: true,
		enableL7Proxy:            true,
	}, testLog)
	require.NoError(t, err)

	sdp.StartStandaloneDNSProxy()
	defer sdp.StopStandaloneDNSProxy()

	// check if the server is running
	require.Equal(t, dnsproxy.StandaloneDNSProxy, sdp.DNSProxy.DNSProxyType)
	require.NotNil(t, sdp.ciliumAgentConnectionTrigger)
}

type MockFQDNDataServer struct {
	pb.UnimplementedFQDNDataServer
}

func (m *MockFQDNDataServer) UpdateMappingRequest(ctx context.Context, in *pb.FQDNMapping) (*pb.UpdateMappingResponse, error) {
	return &pb.UpdateMappingResponse{
		Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
	}, nil
}

// create a channel to receive the policy state
var dnsPoliciesResult = make(chan *pb.PolicyStateResponse)

func (m *MockFQDNDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	//Receive the success message from the SDP
	go func() {
		res, err := stream.Recv()
		if err != nil {
			testLog.Error("Error receiving policy state response", logfields.Error, err)
		}
		dnsPoliciesResult <- res
		// Send the close message
		stream.Context().Done()
	}()
	go func() {
		// Send the current state of the policy state
		err := stream.Send(&pb.PolicyState{
			EgressL7DnsPolicy: []*pb.DNSPolicy{
				{
					SourceEndpointId: 1,
					DnsPattern:       []string{"*.cilium.io", "example.com"},
					DnsServers: []*pb.DNSServer{
						{
							DnsServerIdentity: 2,
							DnsServerPort:     53,
							DnsServerProto:    17,
						},
					},
				},
			},
			RequestId: "1",
			IdentityToEndpointMapping: []*pb.IdentityToEndpointMapping{
				{
					Identity: 1,
					EndpointInfo: []*pb.EndpointInfo{
						{
							Ip: [][]byte{net.ParseIP("1.1.1.0")},
							Id: 100,
						},
					},
				},
				{
					Identity: 2,
					EndpointInfo: []*pb.EndpointInfo{
						{
							Ip: [][]byte{net.ParseIP("1.1.1.1")},
							Id: 101,
						},
					},
				},
			},
		})
		if err != nil {
			testLog.Error("Error sending policy state", logfields.Error, err)
		}
	}()

	testLog.Info("Waiting for the stream to finish")
	<-stream.Context().Done()
	testLog.Info("Stream finished")
	return stream.Context().Err()
}

func setupStandaloneDNSProxy(t *testing.T, ctx context.Context) (*StandaloneDNSProxy, func()) {
	buffer := 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()

	server := &MockFQDNDataServer{}
	pb.RegisterFQDNDataServer(baseServer, server)
	go func() {
		if err := baseServer.Serve(lis); err != nil {
			// The server is closed, so we can ignore the error
			// as it is expected when the test ends
			// and the server is closed.
			testLog.Error("Error serving bufnet listener", logfields.Error, err)
		}
	}()

	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithKeepaliveParams(kacp))

	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}

	sdp, err := NewStandaloneDNSProxy(&StandaloneDNSProxyArgs{
		DNSProxyConfig: dnsproxy.DNSProxyConfig{
			Address: "",
			Port:    1234,
			IPv4:    true,
			IPv6:    false,
		},
		toFQDNsServerPort:        4321,
		enableStandaloneDNsProxy: true,
		enableL7Proxy:            true,
	}, testLog)
	require.NoError(t, err)

	sdp.connection = conn

	closer := func() {
		if sdp.Client != nil {
			sdp.connection.Close()
		}
		err := lis.Close()
		if err != nil {
			t.Error("Error closing bufnet listener", err)
		}
		baseServer.Stop()
	}

	return sdp, closer
}

func TestSubscribeToPolicyState(t *testing.T) {
	testutils.PrivilegedTest(t)

	sdp, closer := setupStandaloneDNSProxy(t, context.Background())
	defer closer()

	// Create the client
	err := sdp.CreateClient(context.Background())
	require.NoError(t, err)
	tr, err := trigger.NewTrigger(trigger.Parameters{
		TriggerFunc: func(reasons []string) {
			time.Sleep(time.Second)
		},
	})
	require.NoError(t, err)
	sdp.ciliumAgentConnectionTrigger = tr
	// Add a dummy dns proxy server
	sdp.DNSProxy, err = dnsproxy.StartDNSProxy(sdp.args.DNSProxyConfig, // any address, any port, enable ipv4, enable ipv6, enable compression, max 1000 restore IPs
		// LookupEPByIP
		func(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
			return &endpoint.Endpoint{}, false, nil
		},
		// LookupSecIDByIP
		func(ip netip.Addr) (ipcache.Identity, bool) {
			return ipcache.Identity{}, false
		},
		// LookupIPsBySecID
		func(nid identity.NumericIdentity) []string {
			return []string{}
		},
		// NotifyOnDNSMsg
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, dstAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)
	require.NoError(t, err)

	// StreamPolicyState is called successfully
	go func() {
		context, cancel := context.WithCancel(context.Background())
		sdp.cancelStreamPolicyStateStream = cancel
		err = sdp.streamPolicyState(context)
		require.Contains(t, err.Error(), "rpc error: code = Canceled desc = grpc: the client connection is closing")
	}()

	// check if the server received the success or not
	result := <-dnsPoliciesResult
	require.Equal(t, pb.ResponseCode_RESPONSE_CODE_NO_ERROR, result.GetResponse())
	// Check the data sent from the server is added
	require.Equal(t, map[string]uint64{"1.1.1.1": 101, "1.1.1.0": 100}, sdp.ipToEndpointIdCache)
	require.Equal(t, map[string]uint32{"1.1.1.1": 2, "1.1.1.0": 1}, sdp.ipToIdentityCache)

	// // check the dnsResult channel is empty
	select {
	case <-dnsPoliciesResult:
		for _, s := range sdp.DNSProxy.DNSServers {
			s.Shutdown()
		}
		t.Fatalf("dnsPoliciesResult channel is not empty")
	default:
		t.Logf("dnsPoliciesResult channel is empty")
	}
}

func TestCreateClientIsCreatedSuccessfully(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	err := sdp.CreateClient(ctx)
	require.NoError(t, err)

	// check if the client is created
	require.NotNil(t, sdp.Client)
	// Check if dns rules stream is created
	require.NotNil(t, sdp.policyStateStream)
}

func TestCreateClientFails(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	sdp.connection = nil
	err := sdp.CreateClient(ctx)
	require.Error(t, err)
}

func TestNotifyOnDNSMsg(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	err := sdp.CreateClient(ctx)
	require.NoError(t, err)

	ep := &endpoint.Endpoint{
		SecurityIdentity: &identity.Identity{
			ID: 1,
		},
	}
	serverId := identity.NumericIdentity(2)
	msg := new(dns.Msg)
	msg.SetQuestion("test.com.", dns.TypeA)
	retARR, err := dns.NewRR(msg.Question[0].Name + " 60 IN A 1.1.1.1")
	if err != nil {
		panic(err)
	}
	msg.Answer = append(msg.Answer, retARR)

	// Case 1: NotifyOnDNSMsg is called successfully
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1:80", serverId, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 53), msg, "udp", true, nil)
	require.NoError(t, err)

	// Case 2: NotifyOnDNSMsg is called with invalid epIpPort
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1", serverId, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 53), msg, "udp", true, nil)
	require.Error(t, err)

	// Case 3: NotifyOnDNSMsg is called with nil client
	sdp.Client = nil
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1:80", serverId, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 53), msg, "udp", true, nil)
	require.Error(t, err)

	// Case 4: NotifyOnDNSMsg is called with invalid msg
	err = sdp.CreateClient(ctx)
	require.NoError(t, err)
	msg = new(dns.Msg)
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1:80", serverId, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 53), msg, "udp", true, nil)
	require.Equal(t, errors.New("Invalid DNS message"), err)

}

func TestCreateSubscriptionStream(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	// First check if the subscription stream is created successfully
	err := sdp.CreateClient(ctx)
	require.NoError(t, err)

	err = sdp.createStreamPolicyStateStream(ctx)
	require.NoError(t, err)
	require.NotNil(t, sdp.policyStateStream)

	// Now check if the subscription stream is created again if the dnsRulesStream is not nil
	current := sdp.policyStateStream
	err = sdp.createStreamPolicyStateStream(ctx)
	require.NoError(t, err)
	require.NotNil(t, sdp.policyStateStream)
	require.NotEqual(t, current, sdp.policyStateStream)

	// Now check if the subscription stream is not created if the client is nil
	sdp.Client = nil
	err = sdp.createStreamPolicyStateStream(ctx)
	require.Error(t, err)
}

var (
	ipToEndpointIdCache = map[string]uint64{"1.1.1.10": 1}
	ipToIdentityCache   = map[string]uint32{"1.1.1.10": 100}
)

func TestLookupSecIDByIP(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	sdp.ipToIdentityCache = ipToIdentityCache
	// Case 1: LookupSecIDByIP is called successfully
	secID, found := sdp.LookupSecIDByIP(netip.MustParseAddr("1.1.1.10"))
	require.True(t, found)
	require.Equal(t, ipcache.Identity{
		ID:     identity.NumericIdentity(100),
		Source: source.Local,
	}, secID)

	// Case 2: LookupSecIDByIP is called with invalid ip
	secID, found = sdp.LookupSecIDByIP(netip.MustParseAddr("2.2.2.2"))
	require.False(t, found)
	require.Equal(t, ipcache.Identity{}, secID)
}

func TestLookEPByIP(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	sdp.ipToEndpointIdCache = ipToEndpointIdCache
	sdp.ipToIdentityCache = ipToIdentityCache
	// Case 1: LookupEPByIP is called successfully
	ep, _, err := sdp.LookupEPByIP(netip.MustParseAddr("1.1.1.10"))
	require.NoError(t, err)
	require.NotNil(t, ep)
	require.Equal(t, uint64(1), ep.GetID())
	require.Equal(t, identity.NumericIdentity(100), ep.SecurityIdentity.ID)

	// Case 2: LookupEPByIP is called with invalid ip
	ep, _, err = sdp.LookupEPByIP(netip.MustParseAddr("2.2.2.2"))
	require.Error(t, err)
	require.Nil(t, ep)
}

func TestUpdatePolicyState(t *testing.T) {
	testutils.PrivilegedTest(t)

	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Address:                "",
		Port:                   1234,
		IPv4:                   true,
		IPv6:                   true,
		EnableDNSCompression:   true,
		MaxRestoreDNSIPs:       10,
		ConcurrencyLimit:       10,
		ConcurrencyGracePeriod: 10,
		DNSProxyType:           dnsproxy.StandaloneDNSProxy,
	}
	epId := uint32(1)
	dnsServerIps := []net.IP{
		net.ParseIP("2.2.2.2"),
	}
	var dnsIps [][]byte
	for _, i := range dnsServerIps {
		dnsIps = append(dnsIps, []byte(i.String()))
	}

	epIps := []net.IP{
		net.ParseIP("1.1.1.1"),
	}
	var ips [][]byte
	for _, i := range epIps {
		ips = append(ips, []byte(i.String()))
	}

	dstPortProto := restore.MakeV2PortProto(53, u8proto.UDP) // Set below when we setup the server!
	IdentityToEndpointMapping := []*pb.IdentityToEndpointMapping{
		{
			Identity: 2,
			EndpointInfo: []*pb.EndpointInfo{
				{
					Ip: dnsIps,
					Id: 101,
				},
			},
		},
		{
			Identity: 3,
			EndpointInfo: []*pb.EndpointInfo{
				{
					Ip: dnsIps,
					Id: 102,
				},
			},
		},
		{
			Identity: 1,
			EndpointInfo: []*pb.EndpointInfo{
				{
					Ip: ips,
					Id: 100,
				},
			},
		},
	}
	var test = []struct {
		name string
		args *pb.PolicyState
		err  error
		out  map[restore.PortProto][]identity.NumericIdentitySlice
	}{
		{
			name: "Single DNS Policy with single DNS server",
			args: &pb.PolicyState{
				EgressL7DnsPolicy: []*pb.DNSPolicy{
					{
						SourceEndpointId: epId,
						DnsPattern:       []string{"*.cilium.io", "example.com"},
						DnsServers: []*pb.DNSServer{
							{
								DnsServerIdentity: 2,
								DnsServerPort:     53,
								DnsServerProto:    17,
							},
						},
					},
				},
				IdentityToEndpointMapping: IdentityToEndpointMapping,
			},
			err: nil,
			out: map[restore.PortProto][]identity.NumericIdentitySlice{
				dstPortProto: {
					{identity.NumericIdentity(2)},
				},
			},
		},
		{
			name: "Single DNS Policy with multiple port and protocol DNS servers",
			args: &pb.PolicyState{
				EgressL7DnsPolicy: []*pb.DNSPolicy{
					{
						SourceEndpointId: epId,
						DnsPattern:       []string{"*.cilium.io", "example.com"},
						DnsServers: []*pb.DNSServer{
							{
								DnsServerIdentity: 2,
								DnsServerPort:     53,
								DnsServerProto:    17,
							},
							{
								DnsServerIdentity: 3,
								DnsServerPort:     53,
								DnsServerProto:    17,
							},
						},
					},
				},
				IdentityToEndpointMapping: IdentityToEndpointMapping,
			},
			err: nil,
			out: map[restore.PortProto][]identity.NumericIdentitySlice{
				dstPortProto: {
					{identity.NumericIdentity(2), identity.NumericIdentity(3)},
				},
			},
		},
		{
			name: "Multiple DNS Policies with same identity",
			args: &pb.PolicyState{
				EgressL7DnsPolicy: []*pb.DNSPolicy{
					{
						SourceEndpointId: epId,
						DnsPattern:       []string{"*.aws.io"},
						DnsServers: []*pb.DNSServer{
							{
								DnsServerIdentity: 2,
								DnsServerPort:     53,
								DnsServerProto:    17,
							},
						},
					},
					{
						SourceEndpointId: epId,
						DnsPattern:       []string{"*.cilium.io", "example.com"},
						DnsServers: []*pb.DNSServer{
							{
								DnsServerIdentity: 3,
								DnsServerPort:     53,
								DnsServerProto:    17,
							},
						},
					},
				},
				IdentityToEndpointMapping: IdentityToEndpointMapping,
			},
			err: nil,
			out: map[restore.PortProto][]identity.NumericIdentitySlice{
				dstPortProto: {
					{identity.NumericIdentity(2)},
					{identity.NumericIdentity(3)},
				},
			},
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := dnsproxy.StartDNSProxy(dnsProxyConfig, // any address, any port, enable ipv4, enable ipv6, enable compression, max 1000 restore IPs
				// LookupEPByIP
				func(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
					return &endpoint.Endpoint{}, false, nil
				},
				// LookupSecIDByIP
				func(ip netip.Addr) (ipcache.Identity, bool) {
					return ipcache.Identity{}, false
				},
				// LookupIPsBySecID
				func(nid identity.NumericIdentity) []string {
					return []string{}
				},
				// NotifyOnDNSMsg
				func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, dstAddr netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
					return nil
				},
			)
			require.NoError(t, err, "error starting DNS Proxy")
			sdp.DNSProxy = proxy

			_, err = sdp.UpdatePolicyState(tt.args)
			if err != nil {
				require.Equal(t, tt.err, err)
				return
			}
			require.NoError(t, err)

			allowedRules, err := sdp.DNSProxy.GetAllowedRulesForEndpoint(uint64(epId))
			require.NoError(t, err)
			// Compare the allowed rules with the expected output
			for portProto, expectedSelectors := range tt.out {
				actualSelectors, ok := allowedRules[portProto]
				require.True(t, ok)
				require.Equal(t, len(expectedSelectors), len(actualSelectors))
			}

			// Shutdown the DNS Proxy
			for _, s := range sdp.DNSProxy.DNSServers {
				s.Shutdown()
			}
		})
	}
}
