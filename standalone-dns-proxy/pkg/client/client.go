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

	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

const (
	DNSRulesTableName         = "sdp-dns-rules"
	IPtoEndpointTableName     = "sdp-ip-to-endpoint"
	PrefixToIdentityTableName = "sdp-prefix-to-identity"
)

func DNSRulesCompositeKey(epID uint32, pp restore.PortProto) uint64 {
	return (uint64(epID) << 32) | uint64(pp)
}

type DNSRules struct {
	EndpointID uint32
	PortProto  restore.PortProto
	DNSRule    policy.L7DataMap
}

type PrefixToIdentity struct {
	Prefix   []netip.Prefix
	Identity identity.NumericIdentity
}

type IPtoEndpointInfo struct {
	IP       []netip.Addr
	ID       uint64
	Identity identity.NumericIdentity
}

var (
	// Keepalive parameters for gRPC connections
	kap = keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             1 * time.Second,
		PermitWithoutStream: true,
	}
)

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
	IdIPToEndpointIndex = statedb.Index[IPtoEndpointInfo, netip.Addr]{
		Name: "ip",
		FromObject: func(e IPtoEndpointInfo) index.KeySet {
			keys := make([]index.Key, 0, len(e.IP))
			for _, ip := range e.IP {
				keys = append(keys, index.NetIPAddr(ip))
			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(key netip.Addr) index.Key {
			return index.NetIPAddr(key)
		},
		FromString: index.NetIPAddrString,
		Unique:     true,
	}
	PrefixToIdentityIndex = statedb.Index[PrefixToIdentity, netip.Prefix]{
		Name: "prefix",
		FromObject: func(p PrefixToIdentity) index.KeySet {
			keys := make([]index.Key, 0, len(p.Prefix))
			for _, prefix := range p.Prefix {
				keys = append(keys, index.NetIPPrefix(prefix))
			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(key netip.Prefix) index.Key {
			return index.NetIPPrefix(key)
		},
		FromString: index.NetIPPrefixString,
		Unique:     false,
	}
	IdentityToPrefixIndex = statedb.Index[PrefixToIdentity, identity.NumericIdentity]{
		Name: "id",
		FromObject: func(p PrefixToIdentity) index.KeySet {
			return index.NewKeySet(index.Uint32(p.Identity.Uint32()))
		},
		FromKey: func(key identity.NumericIdentity) index.Key {
			return index.Uint32(key.Uint32())
		},
		FromString: index.Uint32String,
		Unique:     true,
	}
)

// TableHeader implements statedb.TableWritable.
func (p DNSRules) TableHeader() []string {
	return []string{"EndpointID", "PortProto", "DNS Rules"}
}

// TableRow implements statedb.TableWritable.
func (p DNSRules) TableRow() []string {
	var dnsRules strings.Builder
	for _, sel := range p.DNSRule {
		if sel != nil && sel.L7Rules.DNS != nil {
			fmt.Fprintf(&dnsRules, "%v|", sel.L7Rules.DNS)
		}

	}
	return []string{
		fmt.Sprintf("%d", p.EndpointID),
		p.PortProto.String(),
		dnsRules.String(),
	}
}

func (i IPtoEndpointInfo) TableHeader() []string {
	return []string{
		"IP",
		"Endpoint ID",
		"Identity",
	}
}

func (i IPtoEndpointInfo) TableRow() []string {
	return []string{
		fmt.Sprintf("%v", i.IP),
		fmt.Sprintf("%d", i.ID),
		fmt.Sprintf("%d", i.Identity.Uint32()),
	}
}

func (p PrefixToIdentity) TableRow() []string {
	return []string{
		fmt.Sprintf("%v", p.Prefix),
		fmt.Sprintf("%d", p.Identity.Uint32()),
	}
}

func (i PrefixToIdentity) TableHeader() []string {
	return []string{
		"Prefix",
		"Identity",
	}
}

type dialClient interface {
	CreateClient(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error)
}

// defaultDialClient implements dialClient by using grpc.NewClient.
type defaultDialClient struct{}

func (d *defaultDialClient) CreateClient(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
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

	db                    *statedb.DB
	dnsRulesTable         statedb.RWTable[DNSRules]
	ipToEndpointTable     statedb.RWTable[IPtoEndpointInfo]
	prefixToIdentityTable statedb.RWTable[PrefixToIdentity]

	// port is the port on which the Cilium agent is listening for gRPC connections
	port    uint16
	address string

	// dialClient is used to create gRPC client connections
	dialClient dialClient

	// connected indicates whether a gRPC connection has been established
	connected atomic.Bool

	// grpc client connection to the Cilium agent
	client *grpc.ClientConn
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(params clientParams) *GRPCClient {
	return &GRPCClient{
		logger:                params.Logger,
		port:                  uint16(params.FQDNConfig.StandaloneDNSProxyServerPort),
		dialClient:            params.DialClient,
		address:               fmt.Sprintf("localhost:%d", uint16(params.FQDNConfig.StandaloneDNSProxyServerPort)),
		db:                    params.DB,
		dnsRulesTable:         params.DNSRulesTable,
		ipToEndpointTable:     params.IPtoEndpointTable,
		prefixToIdentityTable: params.PrefixToIdentityTable,
	}
}

// InitClient creates a new gRPC client
func (c *GRPCClient) InitClient() error {
	conn, err := c.dialClient.CreateClient(
		c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kap),
	)
	if err != nil {
		c.logger.Error("Client creation failed", logfields.Error, err)
		return err
	}

	c.client = conn
	c.logger.Info("gRPC client created")
	return nil
}

// createPolicyStream starts the policy stream to receive DNS policy updates from the Cilium agent
// if the policy stream is not already established.
func (c *GRPCClient) createPolicyStream(ctx context.Context) error {
	if !c.IsConnected() {
		defer func() {
			c.connected.Store(false)
		}()

		fqdnClient := pb.NewFQDNDataClient(c.client)
		stream, err := fqdnClient.StreamPolicyState(context.Background())
		if err != nil {
			c.logger.Error("Failed to open policy stream", logfields.Error, err)
			return err
		}
		defer stream.CloseSend()

		c.logger.Info("Policy state stream established")

		for {
			state, err := stream.Recv()
			if err != nil {
				c.logger.Error("Policy stream recv failed", logfields.Error, err)
				return err
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
				return sendErr
			}
			c.connected.Store(true)
		}
	} else {
		c.logger.Debug("Already connected, skipping policy stream start")
	}
	return nil
}

// IsConnected returns the current connection status
func (c *GRPCClient) IsConnected() bool {
	return c.connected.Load()
}

func (c *GRPCClient) StopConnection() {
	// Close the connection if it exists
	if c.client != nil {
		err := c.client.Close()
		if err != nil {
			c.logger.Error("Failed to close connection", logfields.Error, err)
		}
	}

	c.connected.Store(false)
	c.logger.Info("Stopped gRPC connection")
}

// NotifyOnMsg is called by the DNS proxy when it receives a DNS message.
func (c *GRPCClient) NotifyOnMsg(msg *pb.FQDNMapping) error {
	client := pb.NewFQDNDataClient(c.client)

	_, err := client.UpdateMappingRequest(context.Background(), msg)
	if err != nil && isConnectionError(err) {
		c.logger.Error("Connection error during UpdateMappingRequest", logfields.Error, err)
		// Return nil as standalone dns proxy can still continue to handle the DNS requests
		return nil
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

// NewIPtoEndpointTable creates a new table for storing the IP to endpoint mappings.
func NewIPtoEndpointTable(db *statedb.DB) (statedb.RWTable[IPtoEndpointInfo], error) {
	return statedb.NewTable(
		db,
		IPtoEndpointTableName,
		IdIPToEndpointIndex,
	)
}

func NewPrefixToIdentityTable(db *statedb.DB) (statedb.RWTable[PrefixToIdentity], error) {
	return statedb.NewTable(
		db,
		PrefixToIdentityTableName,
		IdentityToPrefixIndex,
		PrefixToIdentityIndex,
	)
}

// updatePolicyState processes the received PolicyState message and updates the DNSRules/IPToEndpoint table accordingly.
func (c *GRPCClient) updatePolicyState(state *pb.PolicyState) error {
	err := c.updateDNSRules(state.GetEgressL7DnsPolicy())
	if err != nil {
		return err
	}
	err = c.updateIPToEndpoint(state.GetIdentityToEndpointMapping())
	if err != nil {
		return err
	}
	err = c.updatePrefixToIdentity(state.GetIdentityToPrefixMapping())
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
					Verdict: types.Allow,
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

// updateIPToEndpoint updates the IP to endpoint table with the received identity to endpoint mappings.
func (c *GRPCClient) updateIPToEndpoint(mappings []*pb.IdentityToEndpointMapping) error {
	wtxn := c.db.WriteTxn(c.ipToEndpointTable)
	defer wtxn.Abort()

	// Clear existing entries as we are replacing the entire mapping with the given snapshot.
	c.ipToEndpointTable.DeleteAll(wtxn)

	for _, mapping := range mappings {
		for _, epInfo := range mapping.GetEndpointInfo() {
			ips := make([]netip.Addr, 0, len(epInfo.GetIp()))
			for _, ip := range epInfo.GetIp() {
				addr, ok := netip.AddrFromSlice(ip)
				if !ok {
					return fmt.Errorf("invalid IP address: %v", ip)
				}
				ips = append(ips, addr)
			}
			_, _, err := c.ipToEndpointTable.Insert(wtxn, IPtoEndpointInfo{
				IP:       ips,
				ID:       epInfo.GetId(),
				Identity: identity.NumericIdentity(mapping.GetIdentity()),
			})
			if err != nil {
				return err
			}
		}
	}
	wtxn.Commit()

	return nil
}

func (c *GRPCClient) updatePrefixToIdentity(mappings []*pb.IdentityToPrefixMapping) error {
	wtxn := c.db.WriteTxn(c.prefixToIdentityTable)
	defer wtxn.Abort()

	// Clear existing entries as we are replacing the entire mapping with the given snapshot.
	c.prefixToIdentityTable.DeleteAll(wtxn)

	for _, mapping := range mappings {
		prefixes := make([]netip.Prefix, 0, len(mapping.GetPrefix()))
		for _, ip := range mapping.GetPrefix() {
			var prefix netip.Prefix
			err := prefix.UnmarshalBinary(ip)
			if err != nil {
				return err
			}
			prefixes = append(prefixes, prefix)
		}
		_, _, err := c.prefixToIdentityTable.Insert(wtxn, PrefixToIdentity{
			Prefix:   prefixes,
			Identity: identity.NumericIdentity(mapping.GetIdentity()),
		})
		if err != nil {
			return err
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

func (d *DNSServerIdentity) Selects(identity identity.NumericIdentity) bool {
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
func (d *DNSServerIdentity) GetSelections() identity.NumericIdentitySlice {
	return d.Identities
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) GetSelectionsAt(types.SelectorSnapshot) identity.NumericIdentitySlice {
	return d.Identities
}

// Not being used in the standalone dns proxy path
func (d *DNSServerIdentity) GetMetadataLabels() labels.LabelArray {
	return nil
}
