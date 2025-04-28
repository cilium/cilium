// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
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

// rulesSnapshot is a struct that holds the current state of the policy rules
// It is used to send the current state of the policy rules to the client(standalone DNS proxy)
type rulesSnapshot struct {
	lock.Mutex
	// rules is the current state of the policy rules
	rules map[identity.NumericIdentity]policy.SelectorPolicy
}

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

	// streams is a map of the active streams and their cancel functions
	// Streams are added when a client(standalone dns proxy) subscribes to policy rules and removed when the client/server closes the connection
	streams lock.Map[pb.FQDNData_StreamPolicyStateServer, context.CancelFunc]

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg messagehandler.DNSMessageHandler

	// identityToIPMutex is a mutex to protect the current state of the identity to Ip mapping
	identityToIPMutex lock.Mutex

	// currentIdentityToIP is a map of the identity to list of IPs
	currentIdentityToIP map[identity.NumericIdentity][]netip.Prefix

	// rulesSnapshot is a snapshot of the current state of the policy rules
	rulesSnapshot rulesSnapshot

	// policyRulesResponse is a map of the request id(unique uuid) to the response received from the standalone DNS proxy
	// It is used to track the response for the policy rules sent to the standalone DNS proxy
	policyRulesResponse lock.Map[string, pb.ResponseCode]

	// prefixLengths tracks the unique set of prefix lengths for IPv4 and
	// IPv6 addresses in order to optimize longest prefix match lookups.
	prefixLengths *counter.PrefixLengthCounter

	// log is the logger for the FQDNDataServer
	log *slog.Logger

	// listener is used to create a net.Listener when starting the grpc server
	listener listenConfig
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

// listenConfig is an interface that abstracts the creation of a net.Listener.
type listenConfig interface {
	Listen(ctx context.Context, network, addr string) (net.Listener, error)
}

// defaultListener implements Listener by using net.ListenConfig.
type defaultListener struct{}

func (d *defaultListener) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, network, addr)
}

var _ listenConfig = &defaultListener{}

func newDefaultListener() listenConfig {
	return &defaultListener{}
}

type PolicyUpdater interface {
	// UpdatePolicyRules is used to update the current state of the policy rules at the
	// gRPC server. These rules are sent to the standalone DNS proxy.
	// This is currently being called whenever there is a policy regeneration event
	// for an endpoint.
	UpdatePolicyRules(map[identity.NumericIdentity]policy.SelectorPolicy, bool) error
}

// StreamPolicyState is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we start a goroutine to receive the DNS policies ACKs for that particular client.
// The flow of the method is as follows:
//  1. Add the stream to the local map(called by the client i.e SDP)
//  2. Start a goroutine to receive the DNS policies ACKs for that particular client.
//  3. Send the current state of the DNS rules to the client (We store the current state of
//     DNS rules during the endpoint regeneration see UpdatePolicyRules)
//  4. Wait for the context to be done and return the error if any
//  5. Delete the stream from the local map
func (s *FQDNDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	s.streams.Store(stream, cancel)

	ackRecvStream := make(chan struct{}, 1)
	// Start a goroutine to receive the DNS policies ACKs
	go func() {
		if err := s.receiveDNSPolicyACKs(stream, ackRecvStream); err != nil {
			s.log.Error("Error receiving DNS policies ACK", logfields.Error, err)
			cancel() // Cancel the context to close the stream
			s.deleteStream(stream)
			return
		}
	}()

	// Wait for the ACK to be received
	<-ackRecvStream
	s.log.Debug("Received ACK for DNS policies")

	//Send the current state of the DNS policies to the client
	s.log.Debug("Sending current state of DNS policies to the client")
	if err := s.UpdatePolicyRules(nil, false); err != nil {
		s.log.Error("Error sending current state of DNS rules", logfields.Error, err)
		cancel() // Cancel the context to close the stream
		s.deleteStream(stream)
		return err
	}

	s.log.Debug("Waiting for context to be done for streaming DNS policies")
	<-streamCtx.Done()
	err := streamCtx.Err()
	if err == nil {
		s.log.Error("Context done for streaming DNS policies", logfields.Error, err)
	}
	s.deleteStream(stream)
	return err
}

// receiveDNSPolicyACKs receives the DNS policies ACKs from the client
// If the success is false, we can send cancel signal to the channel
// in that case SDP will recreate the stream.
// The flow of the method is as follows:
// 1. Close the ACK channel for the stream to send the current state of the DNS policies
// 2. Start a loop to receive the DNS policies ACKs
// 3. If the context is done, return the error
// 4. If the error is not nil, return the error
// 5. If the response code is not NO_ERROR, send cancel signal to the channel
// 6. Delete the request from the map
func (s *FQDNDataServer) receiveDNSPolicyACKs(stream pb.FQDNData_StreamPolicyStateServer, ack chan struct{}) error {
	close(ack)

	for {
		select {
		case <-stream.Context().Done():
			s.log.Info("Stream context is finished, closing the stream")
			return stream.Context().Err()
		default:
			// Continue receiving the DNS policies ACKs
		}
		response, err := stream.Recv()
		if err != nil {
			s.log.Error("Error receiving DNS policies ACK", logfields.Error, err)
			return err
		}
		s.log.Debug("Received DNS policies ACK", logfields.Response, response)
		requestId := response.GetRequestId()
		_, ok := s.policyRulesResponse.Load(requestId)
		if !ok {
			s.log.Warn("Received Message id not found", logfields.ID, requestId)
		} else {
			s.log.Debug("Received response for dns message id", logfields.ID, requestId)

			// We can send cancel signal to the channel if the response code is not NO_ERROR,
			// in that case SDP will recreate the stream.
			responseCode := response.GetResponse()
			if responseCode != pb.ResponseCode_RESPONSE_CODE_NO_ERROR {
				s.log.Error("Received error response for dns message id", logfields.ID, requestId)
				cancel, ok := s.streams.Load(stream)
				if ok {
					cancel()
				}
			}

			// Delete the request from the map
			s.policyRulesResponse.Delete(requestId)
			s.log.Debug("Deleted request id from the map: ", logfields.ID, requestId)
		}
	}
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(endpointManager endpointmanager.EndpointManager, updateOnDNSMsg messagehandler.DNSMessageHandler, port int, logger *slog.Logger, listener listenConfig) *FQDNDataServer {
	fqdnDataServer := &FQDNDataServer{
		port:                port,
		endpointManager:     endpointManager,
		updateOnDNSMsg:      updateOnDNSMsg,
		currentIdentityToIP: make(map[identity.NumericIdentity][]netip.Prefix),
		log:                 logger,
		prefixLengths:       counter.DefaultPrefixLengthCounter(),
		listener:            listener,
		streams:             lock.Map[pb.FQDNData_StreamPolicyStateServer, context.CancelFunc]{},
		rulesSnapshot: rulesSnapshot{
			rules: make(map[identity.NumericIdentity]policy.SelectorPolicy),
		},
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	fqdnDataServer.grpcServer = grpcServer
	pb.RegisterFQDNDataServer(grpcServer, fqdnDataServer)
	return fqdnDataServer
}

// deleteStream deletes the stream from the map
func (s *FQDNDataServer) deleteStream(stream pb.FQDNData_StreamPolicyStateServer) {
	_, ok := s.streams.Load(stream)
	if ok {
		s.log.Info("Deleting stream: ", logfields.ID, stream)
		s.streams.Delete(stream)
	} else {
		s.log.Warn("Stream not found: ", logfields.ID, stream)
	}
}

// OnIPIdentityCacheChange is a method to receive the IP identity cache change events
func (s *FQDNDataServer) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr types.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	s.identityToIPMutex.Lock()
	defer s.identityToIPMutex.Unlock()

	if cidr.ClusterID() != 0 {
		return
	}
	prefix := cidr.AsPrefix()
	if cidr.ClusterID() == 0 {
		switch modType {
		case ipcache.Upsert:
			if oldID != nil {
				// Remove from the old identity
				s.deleteFromIdentityToIPLocked(oldID, prefix)
			}
			s.currentIdentityToIP[newID.ID] = append(s.currentIdentityToIP[newID.ID], prefix)
			s.prefixLengths.Add([]netip.Prefix{prefix})
		case ipcache.Delete:
			if oldID != nil {
				s.deleteFromIdentityToIPLocked(oldID, prefix)
			}
		}
	}
}

// deleteFromIdentityToIPLocked deletes the given IP from the identity to IP mapping
// It is called when the IP identity cache changes and the IP is deleted from the mapping
// It is also called when the IP is upserted with a new identity
// It removes the prefix from the prefixLengths map
// It is called with the identityToIpMutex lock held
func (s *FQDNDataServer) deleteFromIdentityToIPLocked(identity *ipcache.Identity, prefix netip.Prefix) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	if ips, ok := s.currentIdentityToIP[identity.ID]; ok {
		newIPs := slices.DeleteFunc(ips, func(existing netip.Prefix) bool {
			if existing == prefix {
				s.prefixLengths.Delete([]netip.Prefix{prefix})
				return true
			}
			return false
		})
		if len(newIPs) == 0 {
			delete(s.currentIdentityToIP, identity.ID)
		} else {
			s.currentIdentityToIP[identity.ID] = newIPs
		}
	}
	return nil
}

// UpdatePolicyRules updates the current state of the DNS rules with the given policies and sends the current state of the DNS rules to the client
// This method is called:
// 1. when the DNS rules are updated during the endpoint regeneration, we store the state of the DNS rules with flag rulesUpdate as true
// 2. when the client subscribes to DNS policies, we send the current state of the DNS rules to the client(flag rulesUpdate as false)
// 3. when the IP identity cache changes, we update the current state of the identity to IP mapping and send the current state of the DNS rules to
// the client(flag rulesUpdate as false)
// Note: this method is sending constant test data on purpose and will be updated with the actual implementation in the future PRs for the standalone DNS proxy
func (s *FQDNDataServer) UpdatePolicyRules(policies map[identity.NumericIdentity]policy.SelectorPolicy, rulesUpdate bool) error {
	s.rulesSnapshot.Lock()
	defer s.rulesSnapshot.Unlock()

	// This is a temporary implementation to send the current state of the DNS rules to the client and used for testing
	requestId := uuid.New().String()
	policyState := &pb.PolicyState{
		RequestId: requestId,
	}

	s.streams.Range(func(stream pb.FQDNData_StreamPolicyStateServer, cancel context.CancelFunc) bool {
		s.log.Debug("Sending DNS policies to client", logfields.ID, requestId)
		s.policyRulesResponse.Store(requestId, pb.ResponseCode_RESPONSE_CODE_NO_ERROR)
		if err := stream.Send(policyState); err != nil {
			s.log.Error("Error sending DNS policies to client: ", logfields.Error, err)
			// Cancel the goroutine and remove the stream from the map eventually
			cancel()
		}
		return true
	})
	return nil
}

// UpdateMappingRequest updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are not empty, update the cilium agent with the mapping
// Note: this method is left empty on purpose and will be updated with the actual implementation in the future PRs for the standalone DNS proxy
func (s *FQDNDataServer) UpdateMappingRequest(ctx context.Context, mappings *pb.FQDNMapping) (*pb.UpdateMappingResponse, error) {
	return &pb.UpdateMappingResponse{
		Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
	}, nil
}

// ListenAndServe starts the Standalone DNS Proxy gRPC server on the given port
func (s *FQDNDataServer) ListenAndServe(ctx context.Context, health cell.Health) error {
	listenErrs := make(chan error)
	go func() {
		defer close(listenErrs)

		address := fmt.Sprintf("localhost:%d", s.port)
		s.log.Info("Starting Standalone DNS Proxy server on", logfields.Address, address)
		lis, err := s.listener.Listen(ctx, "tcp", address)
		if err != nil {
			s.log.Error("Failed to listen", logfields.Error, err)
			listenErrs <- err
			return
		}

		if err := s.grpcServer.Serve(lis); err != nil {
			s.log.Error("Failed to serve the standalone DNS Proxy gRPC server", logfields.Error, err)
			listenErrs <- err

		}
	}()

	health.OK(fmt.Sprintf("Serving at %d", s.port))

	select {
	case err := <-listenErrs:
		return err
	case <-ctx.Done():
		s.Stop()
		<-listenErrs
		return nil
	}
}

func (s *FQDNDataServer) Stop() {
	if s.grpcServer == nil {
		return
	}
	// clean up the streams
	s.streams.Range(func(stream pb.FQDNData_StreamPolicyStateServer, cancel context.CancelFunc) bool {
		cancel()
		return true
	})
	if !s.streams.IsEmpty() {
		s.log.Warn("Not all streams are closed, some stream might be still active")
	}
	// Stop the grpc server
	s.grpcServer.GracefulStop()
}
