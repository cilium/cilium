// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/rate"
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

	// db is the database used to store the policy rules table
	db *statedb.DB

	// policyRulesTable is the table used to store the policy rules
	// Changes to this table are used to send the current state of the DNS rules to the client
	policyRulesTable statedb.RWTable[policyRules]

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg messagehandler.DNSMessageHandler

	// identityToIPsTable is a table for storing the current state of the identity to IPs mapping
	identityToIPsTable statedb.RWTable[identityToIPs]

	// prefixLengths tracks the unique set of prefix lengths for IPv4 and
	// IPv6 addresses in order to optimize longest prefix match lookups.
	prefixLengths *counter.PrefixLengthCounter

	// log is the logger for the FQDNDataServer
	log *slog.Logger

	// listener is used to create a net.Listener when starting the grpc server
	listener listenConfig
}

type policyRules struct {
	Identity identity.NumericIdentity
	SelPol   policy.SelectorPolicy
}

type identityToIPs struct {
	Identity identity.NumericIdentity
	IPs      part.Set[netip.Prefix]
}

const (
	PolicyRulesTableName   = "policy-rules"
	IdentityToIPsTableName = "identity-to-ip"
)

var (
	idIndex = statedb.Index[policyRules, identity.NumericIdentity]{
		Name: "id",
		FromObject: func(e policyRules) index.KeySet {
			return index.NewKeySet(index.Uint32(e.Identity.Uint32()))
		},
		FromKey: func(key identity.NumericIdentity) index.Key {
			return index.Uint32(key.Uint32())
		},
		FromString: index.Uint32String,
		Unique:     true,
	}
	idIndexIdentityToIP = statedb.Index[identityToIPs, identity.NumericIdentity]{
		Name: "id",
		FromObject: func(e identityToIPs) index.KeySet {
			return index.NewKeySet(index.Uint32(e.Identity.Uint32()))
		},
		FromKey: func(key identity.NumericIdentity) index.Key {
			return index.Uint32(key.Uint32())
		},
		FromString: index.Uint32String,
		Unique:     true,
	}
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

var closedWatchChannel = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// StreamPolicyState is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we subscribe to the changes in the policy rules table and send the current state of the DNS rules to the client.
// The flow of the method is as follows:
//  1. Send the current state of the DNS rules to the client.
//  2. Subscribe to the changes in the policy rules table and wait for changes.
//  3. For each change in the policy rules table, send the current state of the DNS rules to the client.
//  4. If the stream context is done, return.
func (s *FQDNDataServer) StreamPolicyState(stream pb.FQDNData_StreamPolicyStateServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()

	rulesWatch := closedWatchChannel

	for {

		select {
		case <-streamCtx.Done():
			return streamCtx.Err()
		case <-rulesWatch:
			// If there are changes in the policy rules table, we will send the current state
			// of the DNS policies to the client.
			rules, watch := s.policyRulesTable.AllWatch(s.db.ReadTxn())
			if err := s.sendAndRecvAckForDNSPolicies(stream, rules); err != nil {
				return err
			}
			rulesWatch = watch
		}
		// Limit the rate at which we send the full snapshots
		if err := limiter.Wait(streamCtx); err != nil {
			return err
		}
	}

}

// sendAndRecvAckForDNSPolicies sends the current state of the DNS policies to the client
// and waits for the ACK from the client.
// Note: this method is sending constant test data on purpose and will be updated with the actual implementation in the future PRs for the standalone DNS proxy
func (s *FQDNDataServer) sendAndRecvAckForDNSPolicies(stream pb.FQDNData_StreamPolicyStateServer, rules iter.Seq2[policyRules, statedb.Revision]) error {
	requestID := uuid.New().String()
	policyState := &pb.PolicyState{
		RequestId: requestID,
	}

	if err := stream.Send(policyState); err != nil {
		s.log.Error("Error sending DNS policies to client", logfields.Error, err)
		return err
	}
	response, err := stream.Recv()
	if err != nil {
		s.log.Error("Error receiving DNS policies ACK from client", logfields.Error, err)
		return err
	}

	s.log.Debug("Received DNS policies ACK from client", logfields.Response, response)
	return nil
}

// newPolicyRulesTable creates a new table for storing the policy rules and registers it with the database.
func newPolicyRulesTable(db *statedb.DB) (statedb.RWTable[policyRules], error) {
	tbl, err := statedb.NewTable(
		PolicyRulesTableName,
		idIndex,
	)
	if err != nil {
		return nil, err
	}
	err = db.RegisterTable(tbl)
	if err != nil {
		return nil, fmt.Errorf("failed to register table %s: %w", PolicyRulesTableName, err)
	}
	return tbl, nil
}

// newIdentityToIPsTable creates a new table for storing the identity to IP mapping and registers it with the database.
func newIdentityToIPsTable(db *statedb.DB) (statedb.RWTable[identityToIPs], error) {
	tbl, err := statedb.NewTable(
		IdentityToIPsTableName,
		idIndexIdentityToIP,
	)
	if err != nil {
		return nil, err
	}
	err = db.RegisterTable(tbl)
	if err != nil {
		return nil, fmt.Errorf("failed to register table identity-to-ip: %w", err)
	}
	return tbl, nil
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(params serverParams) *FQDNDataServer {

	fqdnDataServer := &FQDNDataServer{
		port:               params.Config.StandaloneDNSProxyServerPort,
		endpointManager:    params.EndpointManager,
		updateOnDNSMsg:     params.DNSRequestHandler,
		log:                params.Logger,
		prefixLengths:      counter.DefaultPrefixLengthCounter(),
		listener:           params.DefaultListener,
		db:                 params.DB,
		policyRulesTable:   params.PolicyRulesTable,
		identityToIPsTable: params.IdentityToIPsTable,
	}

	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	fqdnDataServer.grpcServer = grpcServer
	pb.RegisterFQDNDataServer(grpcServer, fqdnDataServer)
	return fqdnDataServer
}

// OnIPIdentityCacheChange is a method to receive the IP identity cache change events
func (s *FQDNDataServer) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr types.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata, endpointFlags uint8) {
	if cidr.ClusterID() != 0 {
		return
	}

	txn := s.db.WriteTxn(s.identityToIPsTable)
	defer txn.Abort()
	prefix := cidr.AsPrefix()
	if cidr.ClusterID() == 0 {
		switch modType {
		case ipcache.Upsert:
			if oldID != nil {
				// Remove from the old identity
				err := s.deleteFromIdentityToIPLocked(txn, oldID, prefix)
				if err != nil {
					s.log.Error("Failed to delete old identity from identity to IP mapping", logfields.Error, err)
					return
				}
			}

			newObj := identityToIPs{
				Identity: newID.ID,
				IPs:      part.NewSet(prefix),
			}
			_, _, err := s.identityToIPsTable.Modify(txn, newObj, func(oldObj identityToIPs, newObj identityToIPs) identityToIPs {
				// Update the existing record with the new IPs
				newIPs := oldObj.IPs.Union(part.NewSet(prefix))
				return identityToIPs{
					Identity: oldObj.Identity,
					IPs:      newIPs,
				}
			})
			if err != nil {
				s.log.Error("Failed to update identity to IP mapping", logfields.Error, err)
				return
			}
			s.prefixLengths.Add([]netip.Prefix{prefix})
		case ipcache.Delete:
			if oldID != nil {
				err := s.deleteFromIdentityToIPLocked(txn, oldID, prefix)
				if err != nil {
					s.log.Error("Failed to delete identity from identity to IP mapping", logfields.Error, err)
					return
				}
			}
		}
	}
	txn.Commit()
}

// deleteFromIdentityToIPLocked deletes the given IP from the identity to IP mapping
// It is called when the IP identity cache changes and the IP is deleted from the mapping
// It is also called when the IP is upserted with a new identity
// It removes the prefix from the prefixLengths map
// It is called with the identityToIpMutex lock held
func (s *FQDNDataServer) deleteFromIdentityToIPLocked(txn statedb.WriteTxn, identity *ipcache.Identity, prefix netip.Prefix) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}

	existing, _, found := s.identityToIPsTable.Get(txn, idIndexIdentityToIP.Query(identity.ID))
	if !found {
		return fmt.Errorf("identity %d not found in identity to IP mapping", identity.ID.Uint32())
	}

	newIPs := existing.IPs.Delete(prefix)
	if existing.IPs.Has(prefix) {
		// If the prefix was found, we need to remove it from the prefixLength
		s.prefixLengths.Delete([]netip.Prefix{prefix})
	}

	if newIPs.Len() == 0 {
		// If no IPs remain, delete the record.
		_, _, err := s.identityToIPsTable.Delete(txn, existing)
		if err != nil {
			return fmt.Errorf("failed to delete identity to IP mapping: %w", err)
		}
	} else {
		// Update the record with the new IP list.
		_, _, err := s.identityToIPsTable.Insert(txn, identityToIPs{
			Identity: identity.ID,
			IPs:      newIPs,
		})
		if err != nil {
			return fmt.Errorf("failed to insert identity to IP mapping: %w", err)
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
	// This is a temporary implementation to send the current state of the DNS rules to the client and used for testing
	wtxn := s.db.WriteTxn(s.policyRulesTable)
	defer wtxn.Abort()
	for id, selPol := range policies {
		_, _, err := s.policyRulesTable.Insert(wtxn, policyRules{
			Identity: id,
			SelPol:   selPol,
		})
		if err != nil {
			return err
		}

	}
	wtxn.Commit()
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

	// Stop the grpc server
	s.grpcServer.GracefulStop()
}

func init() {
	part.RegisterKeyType(
		func(prefix netip.Prefix) []byte { return []byte(prefix.String()) })
}
