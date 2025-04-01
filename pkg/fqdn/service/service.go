// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

type updateOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) error

type FQDNDataServer struct {
	pb.UnimplementedFQDNDataServer

	ctx           context.Context
	closeServer   func()
	closeServerMu lock.Mutex // Protects access to closeServer

	endpointManager endpointmanager.EndpointManager

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg updateOnDNSMsgFunc

	// snapshotMutex is a mutex to protect the current state of the DNS rules
	snapshotMutex lock.Mutex

	// identityToIpMutex is a mutex to protect the current state of the identity to Ip mapping
	identityToIpMutex lock.Mutex

	// currentIdentityToIp is a map of the identity to list of Ips
	currentIdentityToIp map[identity.NumericIdentity][]net.IP

	// log is the logger for the FQDNDataServer
	log *slog.Logger
}

var (
	kaep = keepalive.EnforcementPolicy{
		PermitWithoutStream: true, // Allow pings even when there are no active streams
	}
	kasp = keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}
)

// StreamPolicyState is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we start a goroutine to receive the DNS policies ACKs
// The flow of the method is as follows:
// 1. Add the stream to the map( called by the client i.e SDP)
// 2. Start a goroutine to receive the DNS policies ACKs for that particular client.
// 3. Send the current state of the DNS rules to the client (We store the current state fo DNS rules during the endpoint regeneration see UpdatePolicyRulesLocked)
// 4. Wait for the context to be done
func (s *FQDNDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	return nil
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(endpointManager endpointmanager.EndpointManager, updateOnDNSMsg updateOnDNSMsgFunc, logger *slog.Logger) *FQDNDataServer {
	ctx := context.Background()

	s := &FQDNDataServer{
		endpointManager:     endpointManager,
		updateOnDNSMsg:      updateOnDNSMsg,
		ctx:                 ctx,
		currentIdentityToIp: make(map[identity.NumericIdentity][]net.IP),
		log:                 logger.With(logfields.LogSubsys, "fqdn/server"),
	}

	go func() {
		<-s.ctx.Done()
		s.log.Info("FQDN service context done, cleaning up resources")
		if s.ctx.Err() != nil {
			s.log.Error("FQDN service context error: ", logfields.Error, s.ctx.Err())
		}
		s.closeServerMu.Lock()
		closeFunc := s.closeServer
		s.closeServerMu.Unlock()
		if closeFunc != nil {
			closeFunc()
		}
	}()

	return s
}

// OnIPIdentityCacheChange is a method to receive the IP identity cache change events
func (s *FQDNDataServer) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr types.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	s.identityToIpMutex.Lock()
	defer s.identityToIpMutex.Unlock()

	if cidr.ClusterID() == 0 {

		ipNet := cidr.AsIPNet()
		ones, _ := ipNet.Mask.Size()

		if (ipNet.IP.To4() != nil && ones != 32) || (ipNet.IP.To4() == nil && ones != 128) {
			s.log.Info("CIDR mask not supported", logfields.CIDR, cidr.String())
		} else {
			switch modType {
			case ipcache.Upsert:
				if oldID != nil {
					// Remove from the old identity
					if ips, ok := s.currentIdentityToIp[oldID.ID]; ok {
						for i, ip := range ips {
							if ip.Equal(ipNet.IP) {
								s.currentIdentityToIp[oldID.ID] = append(ips[:i], ips[i+1:]...)
								break
							}
						}
					}
				}
				s.currentIdentityToIp[newID.ID] = append(s.currentIdentityToIp[newID.ID], ipNet.IP)

			case ipcache.Delete:
				if oldID != nil {
					if ips, ok := s.currentIdentityToIp[oldID.ID]; ok {
						for i, ip := range ips {
							if ip.Equal(ipNet.IP) {
								s.currentIdentityToIp[oldID.ID] = append(ips[:i], ips[i+1:]...)
								break
							}
						}
					}
				}
			}
		}
	}
}

// UpdatePolicyRulesLocked updates the current state of the DNS rules with the given policies and sends the current state of the DNS rules to the client
// This method is called:
// 1. when the DNS rules are updated during the endpoint regeneration, we store the state of the DNS rules with flag rulesUpdate as true
// 2. when the client subscribes to DNS policies, we send the current state of the DNS rules to the client(flag rulesUpdate as false)
// 3. when the IP identity cache changes, we update the current state of the identity to IP mapping and send the current state of the DNS rules to
// the client(flag rulesUpdate as false)
func (s *FQDNDataServer) UpdatePolicyRulesLocked(policies map[identity.NumericIdentity]policy.SelectorPolicy, rulesUpdate bool) error {
	s.snapshotMutex.Lock()
	defer s.snapshotMutex.Unlock()

	return nil
}

// UpdateMappingRequest updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are not empty, update the cilium agent with the mapping
func (s *FQDNDataServer) UpdateMappingRequest(ctx context.Context, mappings *pb.FQDNMapping) (*pb.UpdateMappingResponse, error) {
	return &pb.UpdateMappingResponse{
		Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
	}, nil
}

// RunServer starts the Standalone DNS Proxy grpc server on the given port
func RunServer(port int, server *FQDNDataServer) error {
	address := fmt.Sprintf("localhost:%d", port)
	server.log.Info("Starting Standalone DNS Proxy server on: ", logfields.Address, address)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		server.log.Error("Failed to listen: ", logfields.Error, err)
		return err
	}
	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	pb.RegisterFQDNDataServer(grpcServer, server)

	closer := func() {
		grpcServer.GracefulStop()
	}
	server.closeServerMu.Lock()
	server.closeServer = closer
	server.closeServerMu.Unlock()

	if err := grpcServer.Serve(lis); err != nil {
		server.log.Error("Failed to serve: ", logfields.Error, err)
		return err
	}

	return nil
}
