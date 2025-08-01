// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
)

// Cell provides the proxy lookup functionality needed by DNS proxy.
// It is responsible for looking up security identities, endpoint information,
// and IP mappings required for DNS policy enforcement. This cell provides
// a ProxyLookupHandler that abstracts the lookup operations and can be
// implemented differently for local (agent) vs remote (standalone) scenarios.
var Cell = cell.Module(
	"proxy-lookup-handler",
	"Proxy Lookup functionality",

	cell.Provide(NewProxyLookupHandler),
)

type ProxyLookupParams struct {
	cell.In

	IPCache         *ipcache.IPCache
	LocalNodeStore  *node.LocalNodeStore
	EndpointManager endpointmanager.EndpointManager
}

func NewProxyLookupHandler(params ProxyLookupParams) ProxyLookupHandler {
	handler := &proxyLookupHandler{
		localNodeStore:  params.LocalNodeStore,
		endpointManager: params.EndpointManager,
		ipCache:         params.IPCache,
	}

	return handler
}
