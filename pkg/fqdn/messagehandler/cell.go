// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// Cell provides the FQDN Message handler functionality
// It is responsible for handling DNS messages(requests and responses)
// sent by the proxy and updating the DNS cache, metrics and policy rules
// accordingly using the DNSMessageHandler.
var Cell = cell.Module(
	"fqdn-msg-handler",
	"FQDN Message handler functionality",

	cell.Provide(NewDNSMessageHandler),
)

type DNSMessageHandlerParams struct {
	cell.In

	Lifecycle         cell.Lifecycle
	Logger            *slog.Logger
	NameManager       namemanager.NameManager
	ProxyAccessLogger accesslog.ProxyAccessLogger
}

func NewDNSMessageHandler(params DNSMessageHandlerParams) DNSMessageHandler {
	handler := &dnsMessageHandler{
		logger:            params.Logger,
		nameManager:       params.NameManager,
		proxyAccessLogger: params.ProxyAccessLogger,
	}

	return handler
}
