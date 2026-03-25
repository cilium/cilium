// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"

	bigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/types"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
)

// Loader is an interface to abstract out loading of datapath programs.
type Loader interface {
	CallsMapPath(id uint16) string
	Unload(ep endpoint.Endpoint)
	HostDatapathInitialized() <-chan struct{}

	ReloadDatapath(ctx context.Context, ep endpoint.Endpoint, cfg *types.LocalNodeConfiguration, stats *metrics.SpanStat) (string, error)
	EndpointHash(cfg endpoint.Config, lnCfg *types.LocalNodeConfiguration) (string, error)
	ReinitializeHostDev(ctx context.Context, mtu int) error
	Reinitialize(ctx context.Context, cfg *types.LocalNodeConfiguration, tunnelConfig tunnel.Config, iptMgr types.IptablesManager, p types.Proxy, bigtcp bigtcp.Configuration) error
	WriteEndpointConfig(w io.Writer, cfg endpoint.Config, lnCfg *types.LocalNodeConfiguration) error
}
