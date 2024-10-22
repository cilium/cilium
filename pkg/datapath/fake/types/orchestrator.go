// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

type FakeOrchestrator struct{}

func (f *FakeOrchestrator) Reinitialize(ctx context.Context) error {
	return nil
}

func (f *FakeOrchestrator) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) (string, error) {
	return "", nil
}

func (f *FakeOrchestrator) ReinitializeXDP(ctx context.Context, extraCArgs []string) error {
	return nil
}

func (f *FakeOrchestrator) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	return "", nil
}

func (f *FakeOrchestrator) WriteEndpointConfig(w io.Writer, cfg datapath.EndpointConfiguration) error {
	return nil
}

func (f *FakeOrchestrator) Unload(ep datapath.Endpoint) {}
