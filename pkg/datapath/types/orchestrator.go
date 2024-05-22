// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
)

type Orchestrator interface {
	Reinitialize(ctx context.Context) error

	ReloadDatapath(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) error
	ReinitializeXDP(ctx context.Context, extraCArgs []string) error
	EndpointHash(cfg EndpointConfiguration) (string, error)
	Unload(ep Endpoint)
	WriteEndpointConfig(w io.Writer, cfg EndpointConfiguration) error
}
