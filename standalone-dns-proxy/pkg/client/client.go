// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

const (
	DNSRulesTableName     = "sdp-dns-rules"
	IPtoIdentityTableName = "sdp-ip-to-identity"
)

func DNSRulesCompositeKey(epID uint32, pp restore.PortProto) uint64 {
	return (uint64(epID) << 32) | uint64(pp)
}

type DNSRules struct {
	EndpointID uint32
	PortProto  restore.PortProto
	DNSRule    policy.L7DataMap
}

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
	DNSRulesIndex = statedb.Index[DNSRules, uint64]{
		Name: "id",
		FromObject: func(e DNSRules) index.KeySet {
			return index.NewKeySet(index.Uint64(DNSRulesCompositeKey(e.EndpointID, e.PortProto)))
		},
		FromKey: func(key uint64) index.Key {
			return index.Uint64(key)
		},
		FromString: index.Uint64String,
		Unique:     true,
	}

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

// TableHeader implements statedb.TableWritable.
func (p DNSRules) TableHeader() []string {
	return []string{"EndpointID", "PortProto", "DNS Rules"}
}

// TableRow implements statedb.TableWritable.
func (p DNSRules) TableRow() []string {
	var dnsRules string
	for _, sel := range p.DNSRule {
		if sel != nil && sel.L7Rules.DNS != nil {
			dnsRules += fmt.Sprintf("%v|", sel.L7Rules.DNS)
		}

	}
	return []string{
		fmt.Sprintf("%d", p.EndpointID),
		p.PortProto.String(),
		dnsRules,
	}
}

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
	NotifyOnMsg(msg *pb.FQDNMapping) error

	// IsConnected returns the current connection status
	// connected is a cheap, in-memory flag that indicates whether the client has installed a gRPC connection.
	// DNS proxy can read this deterministically without causing network probes or races with gRPC internals.
	IsConnected() bool
}

// GRPCClient  is a gRPC connection handler for standalone DNS proxy communication with Cilium agent
type GRPCClient struct {
	logger *slog.Logger

	db            *statedb.DB
	dnsRulesTable statedb.RWTable[DNSRules]

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

	// connected indicates whether a gRPC connection has been established
	connected atomic.Bool
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(logger *slog.Logger, fqdnConfig service.FQDNConfig, dialClient dialClient, db *statedb.DB, dnsRulesTable statedb.RWTable[DNSRules]) *GRPCClient {
	return &GRPCClient{
		logger:        logger,
		port:          uint16(fqdnConfig.StandaloneDNSProxyServerPort),
		dialClient:    dialClient,
		address:       fmt.Sprintf("localhost:%d", uint16(fqdnConfig.StandaloneDNSProxyServerPort)),
		connManager:   newConnectionManager(logger),
		db:            db,
		dnsRulesTable: dnsRulesTable,
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

	c.connManager.updateConnection(conn)
	c.logger.Info("gRPC client connection installed (dial complete)")
	return nil
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
		c.connected.Store(false)
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
	c.connected.Store(true)

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
	return c.connected.Load()
}

func (c *GRPCClient) StopConnection() {
	// Close the connection if it exists
	err := c.connManager.Close()
	if err != nil {
		c.logger.Error("Failed to close connection", logfields.Error, err)
	}

	c.connected.Store(false)
	// Update connection manager state
	c.connManager.updateConnection(nil)
	c.logger.Info("Stopped gRPC connection")
}

// NotifyOnMsg is called by the DNS proxy when it receives a DNS message.
func (c *GRPCClient) NotifyOnMsg(msg *pb.FQDNMapping) error {
	if !c.connManager.isConnected() {
		return fmt.Errorf("not connected to agent")
	}

	client, rev, err := c.connManager.getFqdnClientWithRev()
	if err != nil {
		return err
	}

	// Placeholder: real implementation will build a pb.FQDNMapping from the DNS message
	_, err = client.UpdateMappingRequest(context.Background(), msg)
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
func newDNSRulesTable(db *statedb.DB) (statedb.RWTable[DNSRules], error) {
	return statedb.NewTable(
		db,
		DNSRulesTableName,
		DNSRulesIndex,
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
	err := c.updateDNSRules(state.GetEgressL7DnsPolicy())
	if err != nil {
		return err
	}
	return nil
}

// updateDNSRules updates the DNS rules table with the received DNS policies.
func (c *GRPCClient) updateDNSRules(rules []*pb.DNSPolicy) error {
	wtxn := c.db.WriteTxn(c.dnsRulesTable)
	defer wtxn.Abort()

	// Clear existing entries as we are replacing the entire mapping with the given snapshot.
	err := c.dnsRulesTable.DeleteAll(wtxn)
	if err != nil {
		c.logger.Error("Failed to clear existing DNS rules", logfields.Error, err)
		return err
	}

	// create a mapping of endpointID to PortProto to L7DataMap, similar to what DNS proxy expects
	endpointIdToRule := make(map[uint32]map[restore.PortProto]policy.L7DataMap)
	for _, rule := range rules {
		portProtoToServerIdentity := make(map[restore.PortProto]identity.NumericIdentitySlice)
		for _, dnsServer := range rule.GetDnsServers() {
			pp := restore.MakeV2PortProto(uint16(dnsServer.GetDnsServerPort()), u8proto.U8proto(dnsServer.GetDnsServerProto()))
			portProtoToServerIdentity[pp] = append(portProtoToServerIdentity[pp], identity.NumericIdentity(dnsServer.GetDnsServerIdentity()))
		}

		portProtoToDNSrules := make(map[restore.PortProto]policy.L7DataMap)
		for portProto, identities := range portProtoToServerIdentity {
			dnsRulesSlice := make([]api.PortRuleDNS, 0, len(rule.GetDnsPattern()))
			for _, pat := range rule.GetDnsPattern() {
				dnsRulesSlice = append(dnsRulesSlice, api.PortRuleDNS{
					MatchPattern: pat,
				})
			}
			cs := make(policy.L7DataMap)
			if len(dnsRulesSlice) == 0 {
				cs[&DNSServerIdentity{Identities: identities}] = nil

			} else {
				cs[&DNSServerIdentity{Identities: identities}] = &policy.PerSelectorPolicy{
					L7Rules: api.L7Rules{
						DNS: dnsRulesSlice,
					},
				}
			}
			portProtoToDNSrules[portProto] = cs
		}
		// Process each DNS policy rule
		epId := rule.GetSourceEndpointId()
		if _, ok := endpointIdToRule[epId]; !ok {
			endpointIdToRule[epId] = make(map[restore.PortProto]policy.L7DataMap)
		}

		for portProto, cs := range portProtoToDNSrules {
			if _, ok := endpointIdToRule[epId][portProto]; !ok {
				endpointIdToRule[epId][portProto] = make(policy.L7DataMap)
			}

			maps.Copy(endpointIdToRule[epId][portProto], cs)
		}
	}

	for epId, portProtoToRules := range endpointIdToRule {
		for portProto, rules := range portProtoToRules {
			dnsRule := DNSRules{
				EndpointID: epId,
				PortProto:  portProto,
				DNSRule:    rules,
			}
			if _, _, err := c.dnsRulesTable.Insert(wtxn, dnsRule); err != nil {
				c.logger.Error("Failed to insert DNS rule into table", logfields.Error, err)
				return err
			}
		}
	}
	wtxn.Commit()

	return nil
}

// DNSServerIdentity contains the identities of the DNS servers and used to
// determine if a DNS request is allowed or not from standalone DNS proxy.
// It adheres the interface policy.CachedSelector and reuses the
// in agent dns proxy filtering path.
type DNSServerIdentity struct {
	Identities identity.NumericIdentitySlice
}

func (d *DNSServerIdentity) Selects(_ *versioned.VersionHandle, identity identity.NumericIdentity) bool {
	return slices.Contains(d.Identities, identity)
}

func (d *DNSServerIdentity) String() string {
	identityStrings := make([]string, len(d.Identities))
	for i, id := range d.Identities {
		identityStrings[i] = strconv.FormatUint(uint64(id), 10)
	}
	return strings.Join(identityStrings, ",")
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) IsWildcard() bool {
	return false
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) IsNone() bool {
	return false
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) GetSelections(_ *versioned.VersionHandle) identity.NumericIdentitySlice {
	return d.Identities
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) GetMetadataLabels() labels.LabelArray {
	return nil
}
