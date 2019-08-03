package wrapper

import (
	"context"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/loader/config"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
)

type LoaderWrapper struct{}

func (l *LoaderWrapper) CallsMapPath(id uint16) string {
	return bpf.LocalMapPath(loader.CallsMapName, id)
}

func (l *LoaderWrapper) CompileAndLoad(ctx context.Context, ep config.EndpointConfig, stats *metrics.SpanStat) error {
	return loader.CompileAndLoad(ctx, ep, stats)
}

func (l *LoaderWrapper) CompileOrLoad(ctx context.Context, ep config.EndpointConfig, stats *metrics.SpanStat) error {
	return loader.CompileOrLoad(ctx, ep, stats)
}

func (l *LoaderWrapper) ReloadDatapath(ctx context.Context, ep config.EndpointConfig, stats *metrics.SpanStat) error {
	return loader.ReloadDatapath(ctx, ep, stats)
}

func (l *LoaderWrapper) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	return loader.EndpointHash(cfg)
}

func (l *LoaderWrapper) DeleteDatapath(ctx context.Context, ifName, direction string) error {
	return loader.DeleteDatapath(ctx, ifName, direction)
}

func (l *LoaderWrapper) Unload(ep config.EndpointConfig) {
	loader.Unload(ep)
}
