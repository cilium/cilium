// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package creator

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/proxy"
)

// Cell provides the EndpointCreator API for creating and parsing Endpoints.
var Cell = cell.Module(
	"endpoint-creator",
	"API for creating and parsing Endpoints",

	cell.Provide(newEndpointCreator),

	// The embedded DNS proxy provides the endpoint's DNS-proxy readiness
	// signal, used to gate DNS redirect creation on proxy startup.
	cell.Provide(func(p *proxy.Proxy) endpoint.DNSProxyReadiness { return p }),
)
