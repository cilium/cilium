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
	DNSRulesTableName         = "sdp-dns-rules"
	IPtoEndpointTableName     = "sdp-ip-to-endpoint"
	PrefixToIdentityTableName = "sdp-prefix-to-identity"
)

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

	db                    *statedb.DB
	ipToEndpointTable     statedb.RWTable[IPtoEndpointInfo]
	prefixToIdentityTable statedb.RWTable[PrefixToIdentity]
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(logger *slog.Logger, db *statedb.DB, ipToEndpointTable statedb.RWTable[IPtoEndpointInfo], prefixToIdentityTable statedb.RWTable[PrefixToIdentity]) *GRPCClient {
	return &GRPCClient{
		logger:                logger,
		db:                    db,
		ipToEndpointTable:     ipToEndpointTable,
		prefixToIdentityTable: prefixToIdentityTable,
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

func NewPrefixToIdentityTable(db *statedb.DB) (statedb.RWTable[PrefixToIdentity], error) {
	return statedb.NewTable(
		db,
		PrefixToIdentityTableName,
		PrefixToIdentityIndex,
	)
}

// updatePolicyState processes the received PolicyState message and updates the DNSRules/IPToEndpoint table accordingly.
func (c *GRPCClient) updatePolicyState(state *pb.PolicyState) error {
	err := c.updateIPToEndpoint(state.GetIdentityToEndpointMapping())
	if err != nil {
		return err
	}
	err = c.updatePrefixToIdentity(state.GetIdentityToPrefixMapping())
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
