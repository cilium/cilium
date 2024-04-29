// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
)

type Orchestrator interface {
	Reinitialize(ctx context.Context) error

	CompileAndLoad(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) error
	CompileOrLoad(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) error
	ReloadDatapath(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) error
	ReinitializeXDP(ctx context.Context, extraCArgs []string) error
	EndpointHash(cfg EndpointConfiguration) (string, error)
}
