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
)

const (
	DNSRulesTableName     = "sdp-dns-rules"
	IPtoIdentityTableName = "sdp-ip-to-identity"
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
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(logger *slog.Logger) *GRPCClient {
	return &GRPCClient{
		logger: logger,
	}
}

func (c *GRPCClient) StartConnection() {
	c.logger.Info("Starting gRPC connection for standalone DNS proxy")
	// Here we would typically start the gRPC connection to the Cilium agent.
	// This is a placeholder for the actual implementation.
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

// newIPtoIdentityTable creates a new table for storing the IP to identity mappings.
func newIPtoIdentityTable(db *statedb.DB) (statedb.RWTable[IPtoIdentity], error) {
	return statedb.NewTable(
		db,
		IPtoIdentityTableName,
		idIPToIdentityIndex,
	)
}
