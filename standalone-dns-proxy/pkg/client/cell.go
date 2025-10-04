// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
)

// Cell provides the gRPC connection handler client for standalone DNS proxy.
// It is responsible for creating a client that can communicate with the Cilium agent
// to send and receive DNS rules and responses. The client is used by the standalone DNS proxy
// to communicate with the Cilium agent to enforce DNS policies.
var Cell = cell.Module(
	"sdp-grpc-client",
	"gRPC connection handler client for standalone DNS proxy",

	cell.Provide(newGRPCClient),
	cell.Provide(newDNSRulesTable),
	cell.Provide(newIPtoIdentityTable),
)

type clientParams struct {
	cell.In

	Logger        *slog.Logger
	DB            *statedb.DB
	DNSRulesTable statedb.RWTable[DNSRules]
	JobGroup      job.Group
}

// newGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func newGRPCClient(params clientParams) ConnectionHandler {
	return createGRPCClient(params.Logger, params.DB, params.DNSRulesTable)
}
