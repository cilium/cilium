// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"errors"
	"io"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// minReinitInterval is the minimum interval to wait between reinitializations.
	minReinitInterval = 500 * time.Millisecond

	// reinitRetryDuration is the time to wait before retrying failed reinitialization.
	reinitRetryDuration = 10 * time.Second
)

type orchestrator struct {
	params        orchestratorParams
	initDone      bool
	dbInitialized chan struct{}
	trigger       chan reinitializeRequest
}

type reinitializeRequest struct {
	ctx     context.Context
	errChan chan error
}

type orchestratorParams struct {
	cell.In

	Loader          datapath.Loader
	ConfigWriter    datapath.ConfigWriter
	TunnelConfig    tunnel.Config
	MTU             mtu.MTU
	IPTablesManager *iptables.Manager
	Proxy           *proxy.Proxy
	DB              *statedb.DB
	Devices         statedb.Table[*tables.Device]
	NodeAddresses   statedb.Table[tables.NodeAddress]
	JobRegistry     job.Registry
	Health          cell.Health
	Lifecycle       cell.Lifecycle
	EndpointManager endpointmanager.EndpointManager
	LocalNodeStore  *node.LocalNodeStore
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	o := &orchestrator{
		params:        params,
		trigger:       make(chan reinitializeRequest, 1),
		dbInitialized: make(chan struct{}),
	}

	group := params.JobRegistry.NewGroup(params.Health)
	group.Add(job.OneShot("reconciler", o.reconciler))
	params.Lifecycle.Append(group)

	return o
}

func (o *orchestrator) reconciler(ctx context.Context, health cell.Health) error {
	// Wait until the local node has the loopback IP and internal IP (cilium_host) allocated before
	// proceeding. These are needed by the config file writer and we cannot proceed without them.
	health.OK("Waiting for Cilium internal IP")
	localNodes := stream.ToChannel(ctx,
		stream.Filter(o.params.LocalNodeStore,
			func(n node.LocalNode) bool {
				if option.Config.EnableIPv4 {
					loopback := n.IPv4Loopback != nil
					ipv4GW := n.GetCiliumInternalIP(false) != nil
					ipv4Range := n.IPv4AllocCIDR != nil
					if !ipv4GW || !ipv4Range || !loopback {
						return false
					}
				}
				if option.Config.EnableIPv6 {
					ipv6GW := n.GetCiliumInternalIP(true) != nil
					if !ipv6GW {
						return false
					}
				}
				return true
			}))
	localNode, ok := <-localNodes
	if !ok {
		// Context cancelled.
		return nil
	}

	health.OK("Initializing")
	limiter := rate.NewLimiter(minReinitInterval, 1)
	var (
		prevContext datapath.LoaderContext
		request     reinitializeRequest
		retryChan   <-chan time.Time
	)
	retryTimer, stopRetryTimer := inctimer.New()
	defer stopRetryTimer()
	for {
		loaderContext, devsWatch, addrsWatch := o.getLoaderContext(&localNode)

		if !prevContext.DeepEqual(&loaderContext) {
			if err := o.reinitialize(ctx, request, loaderContext); err != nil {
				health.Degraded("Failed to reinitialize datapath", err)
				retryChan = retryTimer.After(reinitRetryDuration)
			} else {
				retryChan = nil
				stopRetryTimer()
				prevContext = loaderContext
				health.OK("OK")
			}
		}

		request = reinitializeRequest{}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-devsWatch:
		case <-addrsWatch:
		case <-retryChan:
		case localNode = <-localNodes:
		case request = <-o.trigger:
		}

		// Limit the rate at which we reinitialize and to give the devs&addrs
		// a chance to settle down.
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func (o *orchestrator) getLoaderContext(node *node.LocalNode) (lctx datapath.LoaderContext, devWatch, addrWatch <-chan struct{}) {
	txn := o.params.DB.ReadTxn()
	nativeDevices, devsWatch := tables.SelectedDevices(o.params.Devices, txn)
	addrs, addrsWatch := o.params.NodeAddresses.All(txn)
	lctx.Devices = nativeDevices
	lctx.DeviceNames = tables.DeviceNames(nativeDevices)
	lctx.NodeAddrs = statedb.Collect(addrs)
	lctx.InternalIPv4 = node.GetCiliumInternalIP(false)
	lctx.InternalIPv6 = node.GetCiliumInternalIP(true)
	lctx.LoopbackIPv4 = node.IPv4Loopback
	lctx.NodeIPv4 = node.GetNodeIP(false)
	lctx.NodeIPv6 = node.GetNodeIP(true)
	lctx.RangeIPv4 = node.IPv4AllocCIDR
	return lctx, devsWatch, addrsWatch
}

func (o *orchestrator) Reinitialize(ctx context.Context) error {
	errChan := make(chan error)
	o.trigger <- reinitializeRequest{
		ctx:     ctx,
		errChan: errChan,
	}
	return <-errChan
}

func (o *orchestrator) reinitialize(ctx context.Context, req reinitializeRequest, lctx datapath.LoaderContext) error {
	if req.ctx != nil {
		ctx = req.ctx
	}

	var errs []error
	if err := o.params.Loader.Reinitialize(
		ctx,
		o.params.TunnelConfig,
		o.params.MTU.GetDeviceMTU(),
		o.params.IPTablesManager,
		o.params.Proxy,
		lctx,
	); err != nil {
		errs = append(errs, err)
	}

	if !o.initDone {
		close(o.dbInitialized)
		o.initDone = true
	}

	reason := "Devices changed"
	if req.ctx != nil {
		reason = "Configuration changed"
	}

	// Issue a regeneration for all endpoints, including the host endpoint.
	// This will eventually trigger calls to [ReloadDatapath], which will requery
	// the devices and addresses. It's guaranteed that it will use a LoaderContext
	// equal to or newer than what we saw here.
	regenRequest := &regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapathLoad,
		ParentContext:     ctx,
	}
	o.params.EndpointManager.RegenerateAllEndpoints(regenRequest).Wait()

	err := errors.Join(errs...)
	if req.errChan != nil {
		select {
		case req.errChan <- err:
		default:
		}
	}

	return err
}

func (o *orchestrator) CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	select {
	case <-o.dbInitialized:
	case <-ctx.Done():
		return ctx.Err()
	}

	node, _ := o.params.LocalNodeStore.Get(ctx)
	lctx, _, _ := o.getLoaderContext(&node)
	return o.params.Loader.CompileOrLoad(ctx, ep, lctx, stats)
}

func (o *orchestrator) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	select {
	case <-o.dbInitialized:
	case <-ctx.Done():
		return ctx.Err()
	}

	node, _ := o.params.LocalNodeStore.Get(ctx)
	lctx, _, _ := o.getLoaderContext(&node)
	return o.params.Loader.ReloadDatapath(ctx, ep, lctx, stats)
}

func (o *orchestrator) ReinitializeXDP(ctx context.Context, extraCArgs []string) error {
	select {
	case <-o.dbInitialized:
	case <-ctx.Done():
		return ctx.Err()
	}

	node, _ := o.params.LocalNodeStore.Get(ctx)
	lctx, _, _ := o.getLoaderContext(&node)
	return o.params.Loader.ReinitializeXDP(ctx, extraCArgs, lctx)
}

func (o *orchestrator) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	<-o.dbInitialized
	return o.params.Loader.EndpointHash(cfg)
}

func (o *orchestrator) Unload(ep datapath.Endpoint) {
	<-o.dbInitialized
	o.params.Loader.Unload(ep)
}

func (o *orchestrator) WriteEndpointConfig(w io.Writer, cfg datapath.EndpointConfiguration) error {
	<-o.dbInitialized
	node, _ := o.params.LocalNodeStore.Get(context.Background())
	lctx, _, _ := o.getLoaderContext(&node)
	return o.params.ConfigWriter.WriteEndpointConfig(w, lctx, cfg)
}
