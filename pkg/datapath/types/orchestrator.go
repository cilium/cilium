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

	DatapathInitialized() <-chan struct{}
	ReloadDatapath(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) (string, error)
	ReinitializeXDP(ctx context.Context, extraCArgs []string) error
	EndpointHash(cfg EndpointConfiguration) (string, error)
	WriteEndpointConfig(w io.Writer, cfg EndpointConfiguration) error
	Unload(ep Endpoint)
}
