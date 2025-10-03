// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/fqdn/lookup"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"
)

// Standalone DNS Proxy lookup Client Cell is responsible for providing the lookup functionality.
// It implements the ProxyLookupHandler interface which is used by the standalone DNS proxy to look up
// security identities, endpoint information, and IP mappings required for DNS policy enforcement.
// The cell
var Cell = cell.Module(
	"sdp-lookup-client",
	"Lookup functionality for the standalone DNS proxy",

	cell.Provide(newRulesClient),
)

type clientParams struct {
	cell.In

	Logger           *slog.Logger
	IPToIdentity     statedb.RWTable[client.IPtoEndpointInfo]
	PrefixToIdentity statedb.RWTable[client.PrefixToIdentity]
	DB               *statedb.DB
	JobGroup         job.Group
}

func newRulesClient(params clientParams) lookup.ProxyLookupHandler {
	r := &rulesClient{
		logger:                params.Logger,
		ipToIdentityTable:     params.IPToIdentity,
		prefixToIdentityTable: params.PrefixToIdentity,
		db:                    params.DB,
		prefixLengths:         counter.DefaultPrefixLengthCounter(),
	}

	params.JobGroup.Add(job.OneShot("sdp-watch-prefix-to-identity-mapping", r.watchPrefixToIdentityTable,
		job.WithRetry(3, &job.ExponentialBackoff{Min: 5 * time.Second, Max: 10 * time.Second}),
		job.WithShutdown()))

	return r
}
