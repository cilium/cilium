// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

// FQDNDataServer is the server for the standalone DNS proxy grpc server
// It is responsible for handling the FQDN mapping requests from the SDP
// and sending the DNS Policy updates to the SDP.
type FQDNDataServer struct {
	pb.UnimplementedFQDNDataServer

	// port is the port on which the standalone DNS proxy grpc server will run
	port int

	// grpcServer is the grpc server for the standalone DNS proxy
	grpcServer *grpc.Server

	endpointManager endpointmanager.EndpointManager

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg messagehandler.DNSRequestHandler

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

type PolicyUpdater interface {
	UpdatePolicyRulesLocked(map[identity.NumericIdentity]policy.SelectorPolicy, bool) error
}

// StreamPolicyState is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we start a goroutine to receive the DNS policies ACKs
// The flow of the method is as follows:
// 1. Add the stream to the map( called by the client i.e SDP)
// 2. Start a goroutine to receive the DNS policies ACKs for that particular client.
// 3. Send the current state of the DNS rules to the client (We store the current state fo DNS rules during the endpoint regeneration see UpdatePolicyRulesLocked)
// 4. Wait for the context to be done
func (s *FQDNDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	stream.Send(&pb.PolicyState{})
	return nil
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(endpointManager endpointmanager.EndpointManager, updateOnDNSMsg messagehandler.DNSRequestHandler, port int, logger *slog.Logger) *FQDNDataServer {

	s := &FQDNDataServer{
		port:                port,
		endpointManager:     endpointManager,
		updateOnDNSMsg:      updateOnDNSMsg,
		currentIdentityToIp: make(map[identity.NumericIdentity][]net.IP),
		log:                 logger.With(logfields.LogSubsys, "fqdn/server"),
	}

	return s
}

// OnIPIdentityCacheChange is a method to receive the IP identity cache change events
func (s *FQDNDataServer) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr types.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	s.identityToIpMutex.Lock()
	defer s.identityToIpMutex.Unlock()

	ipNet := cidr.AsIPNet()

	if cidr.ClusterID() == 0 && cidr.IsSingleIP() {
		switch modType {
		case ipcache.Upsert:
			if oldID != nil {
				// Remove from the old identity
				s.deleteFromIdentityToIPLocked(oldID, ipNet.IP)
			}
			s.currentIdentityToIp[newID.ID] = append(s.currentIdentityToIp[newID.ID], ipNet.IP)

		case ipcache.Delete:
			if oldID != nil {
				s.deleteFromIdentityToIPLocked(oldID, ipNet.IP)
			}
		}
	}
}

// deleteFromIdentityToIPLocked deletes the given IP from the identity to IP mapping
// It is called when the IP identity cache changes and the IP is deleted from the mapping
// It is also called when the IP is upserted with a new identity
// It is called with the identityToIpMutex lock held
func (s *FQDNDataServer) deleteFromIdentityToIPLocked(identity *ipcache.Identity, ip net.IP) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	if ips, ok := s.currentIdentityToIp[identity.ID]; ok {
		newIps := slices.DeleteFunc(ips, func(existing net.IP) bool {
			return existing.Equal(ip)
		})
		if len(newIps) == 0 {
			delete(s.currentIdentityToIp, identity.ID)
		} else {
			s.currentIdentityToIp[identity.ID] = newIps
		}
	}
	return nil
}

// UpdatePolicyRulesLocked updates the current state of the DNS rules with the given policies and sends the current state of the DNS rules to the client
// This method is called:
// 1. when the DNS rules are updated during the endpoint regeneration, we store the state of the DNS rules with flag rulesUpdate as true
// 2. when the client subscribes to DNS policies, we send the current state of the DNS rules to the client(flag rulesUpdate as false)
// 3. when the IP identity cache changes, we update the current state of the identity to IP mapping and send the current state of the DNS rules to
// the client(flag rulesUpdate as false)
// The UpdatePolicyRulesLocked method is called with the proxy.mutex lock held
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

// Starts the Standalone DNS Proxy grpc server on the given port
func (s *FQDNDataServer) Start() error {
	address := fmt.Sprintf("localhost:%d", s.port)
	s.log.Info("Starting Standalone DNS Proxy server on: ", logfields.Address, address)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		s.log.Error("Failed to listen: ", logfields.Error, err)
		return err
	}
	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	s.grpcServer = grpcServer

	pb.RegisterFQDNDataServer(grpcServer, s)

	if err := s.grpcServer.Serve(lis); err != nil {
		s.log.Error("Failed to serve: ", logfields.Error, err)
		return err
	}

	return nil
}

func (s *FQDNDataServer) Stop() {
	if s.grpcServer == nil {
		s.log.Error("GRPC server is nil, cannot stop")
		return
	}
	s.log.Info("Stopping Standalone DNS Proxy server")
	// Stop the grpc server
	s.grpcServer.GracefulStop()
}
