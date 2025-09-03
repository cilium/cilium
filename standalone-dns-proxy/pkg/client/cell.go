// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/time"
)

const (
	sdpCiliumAgentConnectionJob = "sdp-cilium-agent-connection"
	sdpRulesStreamJob           = "sdp-rules-stream"
)

// Cell provides the gRPC connection handler client for standalone DNS proxy.
// It is responsible for creating a client that can communicate with the Cilium agent
// to send and receive DNS rules and responses. The client is used by the standalone DNS proxy
// to communicate with the Cilium agent to enforce DNS policies.
var Cell = cell.Module(
	"sdp-grpc-client",
	"gRPC connection handler client for standalone DNS proxy",

	cell.Provide(newGRPCClient),
	cell.Provide(newDefaultDialClient),
	cell.Provide(newDNSRulesTable),
	cell.Provide(NewIPtoEndpointTable),
	cell.Provide(NewPrefixToIdentityTable),
)

type clientParams struct {
	cell.In

	Logger                *slog.Logger
	JobGroup              job.Group
	FQDNConfig            service.FQDNConfig
	DialClient            dialClient
	DB                    *statedb.DB
	DNSRulesTable         statedb.RWTable[DNSRules]
	IPtoEndpointTable     statedb.RWTable[IPtoEndpointInfo]
	PrefixToIdentityTable statedb.RWTable[PrefixToIdentity]
}

// newGRPCClient creates a new gRPC connection handler client for standalone DNS proxy
func newGRPCClient(params clientParams) ConnectionHandler {
	c := createGRPCClient(params)

	// The connectToAgent job attempts to connect to the Cilium agent every 10 seconds
	// until a connection is established.
	params.JobGroup.Add(job.Timer(sdpCiliumAgentConnectionJob, c.ConnectToAgent, 10*time.Second))

	// The EnsurePolicyStream job ensure that the policy stream is active when connected.
	// It observes the connection events and starts the policy stream when connected.
	params.JobGroup.Add(job.Observer(sdpRulesStreamJob, c.handleConnEvent, stream.FromChannel(c.connManager.Events())))

	return c
}
