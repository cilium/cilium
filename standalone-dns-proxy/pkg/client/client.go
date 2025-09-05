// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/identity"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

const (
	DNSRulesTableName     = "sdp-dns-rules"
	IPtoEndpointTableName = "sdp-ip-to-endpoint"
)

type EndpointInfo struct {
	ID       uint64
	Identity identity.NumericIdentity
}

type IPtoEndpointInfo struct {
	IP       netip.Prefix
	Endpoint EndpointInfo
}

var (
	IdIPToEndpointIndex = statedb.Index[IPtoEndpointInfo, netip.Prefix]{
		Name: "ip",
		FromObject: func(e IPtoEndpointInfo) index.KeySet {
			return index.NewKeySet(index.NetIPPrefix(e.IP))
		},
		FromKey: func(key netip.Prefix) index.Key {
			return index.NetIPPrefix(key)
		},
		FromString: index.NetIPPrefixString,
		Unique:     true,
	}
)

func (i IPtoEndpointInfo) TableHeader() []string {
	return []string{
		"IP",
		"Endpoint ID",
		"Identity",
	}
}

func (i IPtoEndpointInfo) TableRow() []string {
	return []string{
		i.IP.String(),
		fmt.Sprintf("%d", i.Endpoint.ID),
		fmt.Sprintf("%d", i.Endpoint.Identity.Uint32()),
	}
}

// ConnectionHandler defines the interface for standalone DNS proxy connection handler
type ConnectionHandler interface {
	// StartConnection starts the gRPC connection through a hive/job
	// It is responsible for establishing the connection with the Cilium agent.
	// This method is called when the standalone DNS proxy starts.
	StartConnection()

	// StopConnection stops the gRPC connection and removes all hive/job
	// It is responsible for closing the connection with the Cilium agent.
	StopConnection()

	// NotifyOnMsg notifies the gRPC client about DNS messages received by the standalone DNS proxy
	// This method is called by the DNS proxy when it receives a DNS message.
	// It is responsible for sending the DNS message to the Cilium agent for further processing.
	// Note: This method is intentionally left empty for now. And will be implemented in future PRs.
	NotifyOnMsg() error
}

// GRPCClient  is a gRPC connection handler for standalone DNS proxy communication with Cilium agent
type GRPCClient struct {
	logger *slog.Logger

	db                *statedb.DB
	ipToEndpointTable statedb.RWTable[IPtoEndpointInfo]
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(logger *slog.Logger, db *statedb.DB, ipToEndpointTable statedb.RWTable[IPtoEndpointInfo]) *GRPCClient {
	return &GRPCClient{
		logger:            logger,
		db:                db,
		ipToEndpointTable: ipToEndpointTable,
	}
}

func (c *GRPCClient) StartConnection() {
	c.logger.Info("Starting gRPC connection for standalone DNS proxy")
	// Here we would typically start the gRPC connection to the Cilium agent.
	// This is a placeholder for the actual implementation.
	// Adding a dummy call to updatePolicyState to avoid unused method warning.
	c.updatePolicyState(&pb.PolicyState{})
}

func (c *GRPCClient) StopConnection() {
}

// Note: This method is intentionally left empty for now. Will be implemented in future PRs.
func (c *GRPCClient) NotifyOnMsg() error {
	c.logger.Info("DNS message received")
	return nil
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

// NewIPtoEndpointTable creates a new table for storing the IP to endpoint mappings.
func NewIPtoEndpointTable(db *statedb.DB) (statedb.RWTable[IPtoEndpointInfo], error) {
	return statedb.NewTable(
		db,
		IPtoEndpointTableName,
		IdIPToEndpointIndex,
	)
}

// updatePolicyState processes the received PolicyState message and updates the DNSRules/IPToEndpoint table accordingly.
func (c *GRPCClient) updatePolicyState(state *pb.PolicyState) error {
	err := c.updateIPToEndpoint(state.GetIdentityToEndpointMapping())
	if err != nil {
		return err
	}
	return nil
}

func (c *GRPCClient) updateIPToEndpoint(mappings []*pb.IdentityToEndpointMapping) error {
	wtxn := c.db.WriteTxn(c.ipToEndpointTable)
	defer wtxn.Abort()

	// Clear existing entries as we are replacing the entire mapping with the given snapshot.
	c.ipToEndpointTable.DeleteAll(wtxn)

	for _, mapping := range mappings {
		for _, epInfo := range mapping.GetEndpointInfo() {
			for _, ip := range epInfo.GetIp() {
				_, _, err := c.ipToEndpointTable.Insert(wtxn, IPtoEndpointInfo{
					IP: netip.MustParsePrefix(string(ip)),
					Endpoint: EndpointInfo{
						ID:       epInfo.GetId(),
						Identity: identity.NumericIdentity(mapping.GetIdentity()),
					},
				})
				if err != nil {
					return err
				}
			}
		}
	}
	wtxn.Commit()

	return nil
}
