// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/fqdn/messagehandler"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
)

// Cell provides the DNS message handler for the standalone DNS proxy.
// It registers the DNS message handler implementation, which processes DNS messages from the
// DNS proxy and forwards them to the gRPC client for delivery to the Cilium agent.
var Cell = cell.Module(
	"sdp-message-handler",
	"Provides DNS message handling for the standalone DNS proxy",

	cell.Provide(
		newDNSMessageHandler,
	),
)

type clientParams struct {
	cell.In

	Logger      *slog.Logger
	ConnHandler client.ConnectionHandler
}

// NewDNSMessageHandler creates a new DNS message handler for standalone DNS proxy
func newDNSMessageHandler(params clientParams) messagehandler.DNSMessageHandler {
	return &messageHandler{
		Logger:      params.Logger,
		ConnHandler: params.ConnHandler,
	}
}
