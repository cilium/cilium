// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

const (
	DNSRulesTableName     = "sdp-dns-rules"
	IPtoIdentityTableName = "sdp-ip-to-identity"
)

var (
	// Keepalive parameters for gRPC connections
	kap = keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             3 * time.Second,
		PermitWithoutStream: true,
	}
)

type IPtoIdentity struct {
	IP       netip.Addr
	Identity identity.NumericIdentity
}

var (
	idIPToIdentityIndex = statedb.Index[IPtoIdentity, netip.Addr]{
		Name: "ip",
		FromObject: func(e IPtoIdentity) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(e.IP))
		},
		FromKey: func(key netip.Addr) index.Key {
			return index.NetIPAddr(key)
		},
		FromString: index.NetIPAddrString,
		Unique:     true,
	}
)

func (i IPtoIdentity) TableHeader() []string {
	return []string{
		"IP",
		"Identity",
	}
}

func (i IPtoIdentity) TableRow() []string {
	return []string{
		i.IP.String(),
		fmt.Sprintf("%d", i.Identity.Uint32()),
	}
}

type dialClient interface {
	Dial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error)
}

// defaultDialClient implements dialClient by using grpc.NewClient.
type defaultDialClient struct{}

func (d *defaultDialClient) Dial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.NewClient(target, opts...)
}

var _ dialClient = &defaultDialClient{}

func newDefaultDialClient() dialClient {
	return &defaultDialClient{}
}

// ConnectionHandler defines the interface for standalone DNS proxy connection handler
type ConnectionHandler interface {
	// StopConnection stops the gRPC connection
	// It is responsible for closing the connection with the Cilium agent.
	StopConnection()

	// NotifyOnMsg notifies the gRPC client about DNS messages received by the standalone DNS proxy
	// This method is called by the DNS proxy when it receives a DNS message.
	// It is responsible for sending the DNS message to the Cilium agent for further processing.
	// Note: This method is intentionally left empty for now. And will be implemented in future PRs.
	NotifyOnMsg() error

	// IsConnected returns the current connection status
	IsConnected() bool
}

// GRPCClient  is a gRPC connection handler for standalone DNS proxy communication with Cilium agent
type GRPCClient struct {
	logger *slog.Logger

	// connectionManager is responsible for managing the gRPC connection to the Cilium agent
	connManager *connectionManager

	// port is the port on which the Cilium agent is listening for gRPC connections
	port    uint16
	address string

	// connectInProgress indicates if a connection attempt is currently in progress to prevent overlapping dials
	// This field is used to ensure that only one connection attempt is made at a time.
	connectInProgress atomic.Bool

	// policyStreamActive indicates if the policy stream (i.e., the gRPC stream for DNS policy updates) is currently active
	policyStreamActive atomic.Bool

	// dialClient is used to create gRPC client connections
	dialClient dialClient
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(logger *slog.Logger, fqdnConfig service.FQDNConfig, dialClient dialClient) *GRPCClient {
	return &GRPCClient{
		logger:      logger,
		port:        uint16(fqdnConfig.StandaloneDNSProxyServerPort),
		dialClient:  dialClient,
		address:     fmt.Sprintf("localhost:%d", uint16(fqdnConfig.StandaloneDNSProxyServerPort)),
		connManager: newConnectionManager(logger),
	}
}

// ConnectToAgent attempts to connect to the Cilium agent
// This method runs periodically and tries to establish a gRPC connection
// The flow is as follows:
// 1. If already connected, return immediately
// 2. If a connection attempt is already in progress, return immediately
// 3. Attempt to dial the Cilium agent
// 4. If dial fails, log the error and return
func (c *GRPCClient) ConnectToAgent(ctx context.Context) error {
	if c.connManager.isConnected() {
		return nil
	}

	// Prevent overlapping dial attempts.
	if !c.connectInProgress.CompareAndSwap(false, true) {
		return nil
	}
	defer c.connectInProgress.Store(false)

	conn, err := c.dialClient.Dial(
		c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kap),
	)
	if err != nil {
		c.logger.Error("Dial failed", logfields.Error, err)
		return err
	}

	conn.Connect()

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	for {
		state := conn.GetState()
		if state == connectivity.Ready {
			c.connManager.updateConnection(conn)
			c.logger.Info("gRPC connection established")
			return nil
		}
		if state == connectivity.TransientFailure || state == connectivity.Shutdown {
			_ = conn.Close()
			c.connManager.updateConnection(nil)
			return fmt.Errorf("connection failed with state: %v", state)
		}
		if !conn.WaitForStateChange(timeoutCtx, state) {
			_ = conn.Close()
			c.connManager.updateConnection(nil)
			return fmt.Errorf("connection timeout: %w", timeoutCtx.Err())
		}
	}
}

// handleConnEvent handles connection events emitted by the connection manager
// It starts the policy stream if a connection is established
func (c *GRPCClient) handleConnEvent(ctx context.Context, ev connEvent) error {
	if ev.Connected {
		if c.policyStreamActive.CompareAndSwap(false, true) {
			// Use observer-provided context so that shutdown cancels the stream.
			go c.handlePolicyStream(ctx)
		}
	}
	return nil
}

// handlePolicyStream runs the policy stream to receive DNS policy updates from the Cilium agent
func (c *GRPCClient) handlePolicyStream(ctx context.Context) {
	// Ensure policyStreamActive is reset when this goroutine exits
	defer func() {
		c.policyStreamActive.Store(false)
		c.logger.Debug("Policy stream goroutine exiting, reset policyStreamActive to false")
	}()

	client, rev, err := c.connManager.getFqdnClientWithRev()
	if err != nil {
		c.logger.Error("Cannot start policy stream: no active client", logfields.Error, err)
		return
	}

	stream, err := client.StreamPolicyState(ctx)
	if err != nil {
		c.logger.Error("Failed to open policy stream", logfields.Error, err)
		if isConnectionError(err) {
			c.connManager.removeConnection(rev)
		}
		return
	}
	c.logger.Info("Policy state stream established")

	for {
		state, err := stream.Recv()
		if err != nil {
			c.logger.Error("Policy stream recv failed", logfields.Error, err)
			if isConnectionError(err) {
				c.connManager.removeConnection(rev)
			}
			return
		}
		response := &pb.PolicyStateResponse{
			Response: pb.ResponseCode_RESPONSE_CODE_NO_ERROR,
		}
		err = c.updatePolicyState(state)
		if err != nil {
			//Note: We need to update the response code based on the error type
			// Will be implemented in future PRs with updatePolicyState implementation
			c.logger.Error("Failed to update policy state", logfields.Error, err)
		}
		if sendErr := stream.Send(response); sendErr != nil {
			c.logger.Error("Policy stream ACK send failed", logfields.Error, sendErr)
			if isConnectionError(sendErr) {
				c.connManager.removeConnection(rev)
			}
			return
		}
	}
}

// IsConnected returns the current connection status
func (c *GRPCClient) IsConnected() bool {
	return c.connManager.isConnected()
}

func (c *GRPCClient) StopConnection() {
	// Close the connection if it exists
	err := c.connManager.Close()
	if err != nil {
		c.logger.Error("Failed to close connection", logfields.Error, err)
	}
	// Update connection manager state
	c.connManager.updateConnection(nil)
	c.logger.Info("Stopped gRPC connection")
}

// NotifyOnMsg is called by the DNS proxy when it receives a DNS message.
func (c *GRPCClient) NotifyOnMsg() error {
	if !c.connManager.isConnected() {
		return fmt.Errorf("not connected to agent")
	}

	client, rev, err := c.connManager.getFqdnClientWithRev()
	if err != nil {
		return err
	}

	// Placeholder: real implementation will build a pb.FQDNMapping from the DNS message
	_, err = client.UpdateMappingRequest(context.Background(), &pb.FQDNMapping{})
	if err != nil && isConnectionError(err) {
		c.logger.Error("Connection error during UpdateMappingRequest", logfields.Error, err)
		c.connManager.removeConnection(rev)
	}
	return err
}

func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	switch {
	case errors.Is(err, io.EOF):
		return true
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		// Per-RPC deadline: do not nuke the connection
		return false
	}

	st, ok := status.FromError(err)
	if !ok {
		// Non-status error: could be a net/transport error; be conservative and keep connection unless EOF already caught.
		return false
	}

	switch st.Code() {
	case codes.Unavailable:
		return true
	case codes.Internal, codes.Unknown:
		return true
	case codes.Canceled, codes.DeadlineExceeded:
		return false
	default:
		return false
	}
}

// newDNSRulesTable creates a new table for storing the DNS rules and registers it with the database.
// This table will be used to store the DNS rules for the standalone DNS proxy.
// The standalone DNS proxy will use this table to retrieve the DNS rules and update the DNS proxy with the
// latest rules received from the Cilium agent.
func newDNSRulesTable(db *statedb.DB) (statedb.RWTable[service.PolicyRules], error) {
	return statedb.NewTable(
		db,
		DNSRulesTableName,
		service.PolicyRulesIndex,
	)
}

// newIPtoIdentityTable creates a new table for storing the IP to identity mappings.
func newIPtoIdentityTable(db *statedb.DB) (statedb.RWTable[IPtoIdentity], error) {
	return statedb.NewTable(
		db,
		IPtoIdentityTableName,
		idIPToIdentityIndex,
	)
}

// updatePolicyState processes the received PolicyState message and updates the DNSRules/IPToIdentity table accordingly.
func (c *GRPCClient) updatePolicyState(state *pb.PolicyState) error {
	// Placeholder implementation - actual implementation will update the DNS rules table
	return nil
}
