// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"errors"
	"fmt"
	"iter"
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

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

const (
	dnsServerIdentity = identity.NumericIdentity(2)
	endpointIdentity  = identity.NumericIdentity(1)
)

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, h cell.Health) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

type Dummy struct {
	repo policy.PolicyRepository
}

func (s *Dummy) GetPolicyRepository() policy.PolicyRepository {
	return s.repo
}

func (s *Dummy) GetProxyPort(string) (uint16, error) {
	return 0, nil
}

func (s *Dummy) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *Dummy) GetCompilationLock() types.CompilationLock {
	return nil
}

func (s *Dummy) GetCIDRPrefixLengths() (s6, s4 []int) {
	return nil, nil
}

func (s *Dummy) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

func (s *Dummy) Loader() types.Loader {
	return nil
}

func (s *Dummy) Orchestrator() types.Orchestrator {
	return nil
}

func (s *Dummy) BandwidthManager() types.BandwidthManager {
	return nil
}

func (s *Dummy) IPTablesManager() types.IptablesManager {
	return nil
}

func (s *Dummy) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *Dummy) RemoveRestoredDNSRules(epID uint16) {}

func (s *Dummy) AddIdentity(id *identity.Identity) {}

func (s *Dummy) RemoveIdentity(id *identity.Identity) {}

func (s *Dummy) RemoveOldAddNewIdentity(old, new *identity.Identity) {}

func server(ctx context.Context, t *testing.T) (*FQDNDataServer, pb.FQDNDataClient, func()) {
	buffer := 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()
	endptMgr := endpointmanager.New(&dummyEpSyncher{}, nil, nil)
	repo := policy.NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	do := &Dummy{
		repo: repo,
	}
	// Add a test endpoint
	ep := endpoint.NewTestEndpointWithState(do, nil, do, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), 1, endpoint.StateReady)
	ep.IPv4 = netip.MustParseAddr("1.1.1.1")
	err := endptMgr.ExposeTestEndpoint(ep)
	if err != nil {
		panic(err)
	}

	server := NewServer(endptMgr,
		func(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) error {
			// Mocking the response for the test
			if qname == "example.com" {
				return nil
			}
			return errors.New("Failed to update fqdn mapping")
		},
		logging.DefaultSlogLogger,
	)
	// Add the identity to ip mapping
	server.currentIdentityToIp = map[identity.NumericIdentity][]net.IP{
		endpointIdentity:  {net.ParseIP("1.1.1.1")},
		dnsServerIdentity: {net.ParseIP("1.1.1.0")},
	}

	pb.RegisterFQDNDataServer(baseServer, server)
	go func() {
		if err := baseServer.Serve(lis); err != nil {
			server.log.Error("Failed to serve bufnet listener", logfields.Error, err)
		}
	}()

	conn, err := grpc.NewClient("passthrough://bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		server.log.Error("Failed to dial bufnet", logfields.Error, err)
	}
	closer := func() {
		server.ctx.Done()

		err := lis.Close()
		if err != nil {
			server.log.Error("Failed to close bufnet listener", logfields.Error, err)
		}
		baseServer.Stop()
	}

	client := pb.NewFQDNDataClient(conn)

	return server, client, closer
}

func TestUpdateMappingRequest(t *testing.T) {
	ctx := context.Background()

	_, client, closer := server(ctx, t)
	defer closer()

	type expected struct {
		out *pb.UpdateMappingResponse
		err error
	}

	responseIps := []string{
		"2.2.2.2",
	}
	var ips [][]byte
	for _, i := range responseIps {
		ips = append(ips, []byte(i))
	}

	tests := map[string]struct {
		in       *pb.FQDNMapping
		expected expected
	}{
		"Success on updating the fqdn ips": {
			in: &pb.FQDNMapping{
				Fqdn:           "example.com",
				RecordIp:       ips,
				Ttl:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &pb.UpdateMappingResponse{
					Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
				},
				err: nil,
			},
		},
		"Failure due to update of fqdn ips": {
			in: &pb.FQDNMapping{
				Fqdn:           "failure.com",
				RecordIp:       ips,
				Ttl:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &pb.UpdateMappingResponse{},
				err: errors.New("rpc error: code = Unknown desc = cannot update DNS cache: Failed to update fqdn mapping"),
			},
		},
		"Success on response code non zero": {
			in: &pb.FQDNMapping{
				Fqdn:           "example.com",
				RecordIp:       ips,
				Ttl:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   1,
			},
			expected: expected{
				out: &pb.UpdateMappingResponse{
					Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
				},
				err: nil,
			},
		},
		"Failure due to endpoint not found": {
			in: &pb.FQDNMapping{
				Fqdn:           "example.com",
				RecordIp:       ips,
				Ttl:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.0"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &pb.UpdateMappingResponse{},
				err: errors.New("rpc error: code = Unknown desc = endpoint not found for IP: 1.1.1.0"),
			},
		},
		"Success if length of response ips is 0": {
			in: &pb.FQDNMapping{
				Fqdn:           "example.com",
				RecordIp:       [][]byte{},
				Ttl:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &pb.UpdateMappingResponse{
					Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
				},
				err: nil,
			},
		},
	}

	for scenario, tt := range tests {
		t.Run(scenario, func(t *testing.T) {
			out, err := client.UpdateMappingRequest(ctx, tt.in)
			require.Equal(t, tt.expected.out.GetResponse(), out.GetResponse())
			if err != nil {
				require.Equal(t, tt.expected.err.Error(), err.Error())
			} else {
				require.Equal(t, tt.expected.err, err)
			}
		})
	}
}

type dummySelectorPolicy struct{}

func (sp *dummySelectorPolicy) DistillPolicy(logger *slog.Logger, owner policy.PolicyOwner, redirects map[string]uint16) *policy.EndpointPolicy {
	return nil
}

func (sp *dummySelectorPolicy) RedirectFilters() iter.Seq2[*policy.L4Filter, policy.PerSelectorPolicyTuple] {
	sc := policy.NewSelectorCache(
		logging.DefaultSlogLogger,
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
	cachedSelector, _ := sc.AddIdentitySelector(dummySelectorCacheUser, policy.EmptyStringLabels, endpointSelector)
	expectedPolicy := policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			Ingress:  false,
			PerSelectorPolicies: policy.L7DataMap{
				cachedSelector: &policy.PerSelectorPolicy{
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
		"ANY/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x00,
			Ingress:  false,
		},
	})

	// return the expected policy
	return func(yield func(*policy.L4Filter, policy.PerSelectorPolicyTuple) bool) {
		expectedPolicy.ForEach(func(l4 *policy.L4Filter) bool {
			for cs, perSelectorPolicy := range l4.PerSelectorPolicies {
				return yield(l4, policy.PerSelectorPolicyTuple{
					Policy:   perSelectorPolicy,
					Selector: cs,
				})
			}
			return true
		})
	}
}

func TestSuccessfullyStreamPolicyState(t *testing.T) {
	ctx := context.Background()
	server, client, closer := server(ctx, t)
	defer closer()

	type in struct {
		snaptshot   map[identity.NumericIdentity]policy.SelectorPolicy
		policyRules *pb.PolicyState
	}

	tests := map[string]struct {
		in in
	}{
		"Success on sending the rules to the client": {
			in: in{
				snaptshot: map[identity.NumericIdentity]policy.SelectorPolicy{
					endpointIdentity: &dummySelectorPolicy{},
				},
				policyRules: &pb.PolicyState{
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
							Identity: 2,
							EndpointInfo: []*pb.EndpointInfo{
								{
									Ip: [][]byte{[]byte("1.1.1.0")},
								},
							},
						},
						{
							Identity: 1,
							EndpointInfo: []*pb.EndpointInfo{
								{
									Ip: [][]byte{[]byte("1.1.1.1")},
									Id: 1,
								},
							},
						},
					},
				},
			},
		},
		"Success on sending empty rules to the client": {
			in: in{
				snaptshot:   map[identity.NumericIdentity]policy.SelectorPolicy{},
				policyRules: &pb.PolicyState{},
			},
		},
	}

	for scenario, test := range tests {
		t.Run(scenario, func(t *testing.T) {
			// set the server snapshot
			server.currentSnapshot = test.in.snaptshot

			// Client subscribes to the DNS rules
			outClient, err := client.StreamPolicyState(ctx)
			require.NoError(t, err)

			// Server sends the DNS rules
			actualOut, err := outClient.Recv()
			require.NoError(t, err)
			require.Equal(t, len(test.in.policyRules.GetEgressL7DnsPolicy()), len(actualOut.GetEgressL7DnsPolicy()))

			for i, expectedPolicy := range test.in.policyRules.GetEgressL7DnsPolicy() {
				actualPolicy := actualOut.GetEgressL7DnsPolicy()[i]
				require.Equal(t, expectedPolicy.GetSourceEndpointId(), actualPolicy.GetSourceEndpointId())
				require.Equal(t, expectedPolicy.GetDnsPattern(), actualPolicy.GetDnsPattern())
				require.Equal(t, len(expectedPolicy.GetDnsServers()), len(actualPolicy.GetDnsServers()))
				for j, expectedServer := range expectedPolicy.GetDnsServers() {
					actualServer := actualPolicy.GetDnsServers()[j]
					require.Equal(t, expectedServer.GetDnsServerPort(), actualServer.GetDnsServerPort())
					require.Equal(t, expectedServer.GetDnsServerProto(), actualServer.GetDnsServerProto())
				}
			}

			for i, expectedMapping := range test.in.policyRules.GetIdentityToEndpointMapping() {
				actualMapping := actualOut.GetIdentityToEndpointMapping()[i]
				require.Equal(t, expectedMapping.GetIdentity(), actualMapping.GetIdentity())
				require.Equal(t, len(expectedMapping.GetEndpointInfo()), len(actualMapping.GetEndpointInfo()))
				for j, expectedInfo := range expectedMapping.GetEndpointInfo() {
					actualInfo := actualMapping.GetEndpointInfo()[j]
					for _, ip := range expectedInfo.GetIp() {
						require.Equal(t, string(ip), net.IP(actualInfo.GetIp()[j]).String())
					}
					require.Equal(t, expectedInfo.GetId(), actualInfo.GetId())
				}
			}

			err = outClient.Send(&pb.PolicyStateResponse{
				Response:  pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
				RequestId: actualOut.RequestId,
			})
			require.NoError(t, err)

			_, val := server.dnsMappingResult.Load(actualOut.RequestId)
			require.True(t, val)

			// Client closes the connection
			err = outClient.CloseSend()
			require.NoError(t, err)

			// Wait for a second before checking if the server has received the close signal
			sleepTime := time.NewTimer(1 * time.Second)
			<-sleepTime.C
			// Server receives the close signal and deletes the mapping
			_, val = server.dnsMappingResult.Load(actualOut.RequestId)
			require.False(t, val)
		})
	}
}

func TestFailureToStreamPolicyState(t *testing.T) {
	ctx := context.Background()
	server, client, closer := server(ctx, t)
	defer closer()

	// Client subscribes to the DNS rules
	outClient, err := client.StreamPolicyState(ctx)
	require.NoError(t, err)

	for {
		actualOut, err := outClient.Recv()
		if err != nil {
			// This is expected as the server has received the success as false
			// So the client should receive an error and reestablish the stream
			require.Equal(t, "rpc error: code = Canceled desc = context canceled", err.Error())
			break
		}
		require.NoError(t, err)

		// Client sends a failure response
		err = outClient.Send(&pb.PolicyStateResponse{
			Response:  pb.ResponseCode_RESPONSE_CODE_SERVER_FAILURE,
			RequestId: actualOut.RequestId,
		})
		require.NoError(t, err)

		mapValue, _ := server.dnsMappingResult.Load(actualOut.RequestId)
		require.False(t, mapValue)
	}
}

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
			conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", tt.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

		})
	}
}
