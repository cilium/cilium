// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// Cell provides the FQDN Message handler functionality
var Cell = cell.Module(
	"fqdn-msg-handler",
	"FQDN Message handler functionality",

	cell.Provide(NewDNSRequestHandler),
)

type DNSRequestHandlerParams struct {
	cell.In

	Lifecycle         cell.Lifecycle
	Logger            *slog.Logger
	NameManager       namemanager.NameManager
	ProxyInstance     defaultdns.Proxy
	ProxyAccessLogger accesslog.ProxyAccessLogger
}

func NewDNSRequestHandler(params DNSRequestHandlerParams) DNSRequestHandler {
	ctx, cancelCtx := context.WithCancel(context.Background())

	handler := &dnsRequestHandler{
		ctx:               ctx,
		logger:            params.Logger,
		nameManager:       params.NameManager,
		proxyInstance:     params.ProxyInstance,
		proxyAccessLogger: params.ProxyAccessLogger,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStop: func(hookContext cell.HookContext) error {
			cancelCtx()
			return nil
		},
	})

	return handler
}
