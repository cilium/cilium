// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
)

type Orchestrator interface {
	Reinitialize(ctx context.Context) error

	DatapathInitialized() <-chan struct{}
	ReloadDatapath(ctx context.Context, ep Endpoint, stats *metrics.SpanStat) (string, error)
	EndpointHash(cfg endpoint.Config) (string, error)
	WriteEndpointConfig(w io.Writer, cfg endpoint.Config) error
	Unload(ep Endpoint)
}
