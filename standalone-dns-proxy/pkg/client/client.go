// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
)

const (
	DNSRulesTableName     = "sdp-dns-rules"
	IPtoIdentityTableName = "sdp-ip-to-identity"
)

// DNSRules represents the DNS rules for a specific identity.
// Note: This is a placeholder for the actual DNS rules structure. The actual structure will be implemented in future PRs.
type DNSRules struct {
	Identity identity.NumericIdentity
	Rules    []string
}

type IPtoIdentity struct {
	IP       netip.Addr
	Identity identity.NumericIdentity
}

var (
	idIndex = statedb.Index[DNSRules, identity.NumericIdentity]{
		Name: "id",
		FromObject: func(e DNSRules) index.KeySet {
			return index.NewKeySet(index.Uint32(e.Identity.Uint32()))
		},
		FromKey: func(key identity.NumericIdentity) index.Key {
			return index.Uint32(key.Uint32())
		},
		FromString: index.Uint32String,
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

// TableHeader implements the TableWritable interface for DNSRules
func (p DNSRules) TableHeader() []string {
	return []string{
		"Identity",
		"DNS Rules",
	}
}

// TableRow implements the TableWritable interface for DNSRules
func (p DNSRules) TableRow() []string {
	return p.Rules
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

// ConnectionHandler defines the interface for standalone DNS proxy connection handler
type ConnectionHandler interface {
	// StartConnection starts the gRPC connection through a controller
	// It is responsible for establishing the connection with the Cilium agent.
	// This method is called when the standalone DNS proxy starts.
	StartConnection()

	// StopConnection stops the gRPC connection and removes all controllers
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
	logger      *slog.Logger
	controllers *controller.Manager
}

// createGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func createGRPCClient(logger *slog.Logger) *GRPCClient {
	return &GRPCClient{
		logger:      logger,
		controllers: controller.NewManager(),
	}
}

func (c *GRPCClient) StartConnection() {
	c.logger.Info("Starting gRPC connection for standalone DNS proxy")
	// Here we would typically start the gRPC connection to the Cilium agent.
	// This is a placeholder for the actual implementation.
}

func (c *GRPCClient) StopConnection() {
	c.controllers.RemoveAll()
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
func newDNSRulesTable(db *statedb.DB) (statedb.RWTable[DNSRules], error) {
	tbl, err := statedb.NewTable(
		DNSRulesTableName,
		idIndex,
	)
	if err != nil {
		return nil, err
	}
	err = db.RegisterTable(tbl)
	if err != nil {
		return nil, fmt.Errorf("failed to register table %s: %w", DNSRulesTableName, err)
	}
	return tbl, nil
}

// newIPtoIdentityTable creates a new table for storing the IP to identity mappings.
func newIPtoIdentityTable(db *statedb.DB) (statedb.RWTable[IPtoIdentity], error) {
	tbl, err := statedb.NewTable(
		IPtoIdentityTableName,
		idIPToIdentityIndex,
	)
	if err != nil {
		return nil, err
	}
	err = db.RegisterTable(tbl)
	if err != nil {
		return nil, fmt.Errorf("failed to register table %s: %w", IPtoIdentityTableName, err)
	}
	return tbl, nil
}
