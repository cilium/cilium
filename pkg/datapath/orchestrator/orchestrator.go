// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
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
	params orchestratorParams

	initDone              bool
	dpInitialized         chan struct{}
	trigger               chan reinitializeRequest
	latestLocalNodeConfig atomic.Pointer[datapath.LocalNodeConfiguration]
}

type reinitializeRequest struct {
	ctx     context.Context
	errChan chan error
}

type orchestratorParams struct {
	cell.In

	Log                 *slog.Logger
	Loader              datapath.Loader
	TunnelConfig        tunnel.Config
	MTU                 mtu.MTU
	IPTablesManager     datapath.IptablesManager
	Proxy               *proxy.Proxy
	DB                  *statedb.DB
	Devices             statedb.Table[*tables.Device]
	NodeAddresses       statedb.Table[tables.NodeAddress]
	DirectRoutingDevice tables.DirectRoutingDevice
	LocalNodeStore      *node.LocalNodeStore
	NodeDiscovery       *nodediscovery.NodeDiscovery
	JobRegistry         job.Registry
	Health              cell.Health
	Lifecycle           cell.Lifecycle
	EndpointManager     endpointmanager.EndpointManager
	ConfigPromise       promise.Promise[*option.DaemonConfig]
	XDPConfig           xdp.Config
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	o := &orchestrator{
		params:        params,
		trigger:       make(chan reinitializeRequest, 1),
		dpInitialized: make(chan struct{}),
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			// Reinitialize the host device in a separate, blocking start hook to make sure all
			// our dependencies can access the host device. This is necessary because one of these
			// is the Daemon, which the main reconciliation loop has to wait for.
			if err := o.params.Loader.ReinitializeHostDev(ctx, params.MTU.GetDeviceMTU()); err != nil {
				return fmt.Errorf("failed to reinitialize host device: %w", err)
			}
			return nil
		},
	})

	group := params.JobRegistry.NewGroup(params.Health)
	group.Add(job.OneShot("Reinitialize", o.reconciler, job.WithShutdown()))
	params.Lifecycle.Append(group)

	return o
}

func (o *orchestrator) reconciler(ctx context.Context, health cell.Health) error {
	// We depend on settings modified by the Daemon startup. Once the Deamon is initialized this promise
	// is resolved and we are guaranteed to have the correct settings.
	health.OK("Waiting for agent config")
	agentConfig, err := o.params.ConfigPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to get agent config: %w", err)
	}

	// Wait until the local node has the loopback IP and internal IP (cilium_host) allocated before
	// proceeding. These are needed by the config file writer and we cannot proceed without them.
	health.OK("Waiting for Cilium internal IP")
	localNodes := stream.ToChannel(ctx,
		stream.Filter(o.params.LocalNodeStore,
			func(n node.LocalNode) bool {
				if agentConfig.EnableIPv4 {
					loopback := n.IPv4Loopback != nil
					ipv4GW := n.GetCiliumInternalIP(false) != nil
					ipv4Range := n.IPv4AllocCIDR != nil
					if !ipv4GW || !ipv4Range || !loopback {
						return false
					}
				}
				if agentConfig.EnableIPv6 {
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
		request   reinitializeRequest
		retryChan <-chan time.Time
	)
	retryTimer, stopRetryTimer := inctimer.New()
	defer stopRetryTimer()
	for {
		localNodeConfig, devsWatch, addrsWatch, directRoutingDevWatch, err := newLocalNodeConfig(
			ctx,
			option.Config,
			localNode,
			o.params.MTU,
			o.params.DB.ReadTxn(),
			o.params.DirectRoutingDevice,
			o.params.Devices,
			o.params.NodeAddresses,
			o.params.XDPConfig,
		)
		if err != nil {
			health.Degraded("failed to get local node configuration", err)
		}

		// Reinitializeing is expensive, only do so if the configuration has changed.
		prevConfig := o.latestLocalNodeConfig.Load()
		if prevConfig == nil || !prevConfig.DeepEqual(&localNodeConfig) {
			if err := o.reinitialize(ctx, request, &localNodeConfig); err != nil {
				o.params.Log.Warn("Failed to initialize datapath, retrying later", logfields.Error, err, "retry-delay", reinitRetryDuration)
				health.Degraded("Failed to reinitialize datapath", err)
				retryChan = retryTimer.After(reinitRetryDuration)
			} else {
				retryChan = nil
				stopRetryTimer()
				health.OK("OK")
			}
		} else {
			// We don't need to reinitialize, but we still need to unblock the requestor if there is one.
			if request.errChan != nil {
				close(request.errChan)
			}
		}

		request = reinitializeRequest{}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-devsWatch:
		case <-addrsWatch:
		case <-directRoutingDevWatch:
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

func (o *orchestrator) Reinitialize(ctx context.Context) error {
	errChan := make(chan error)
	o.trigger <- reinitializeRequest{
		ctx:     ctx,
		errChan: errChan,
	}
	return <-errChan
}

func (o *orchestrator) reinitialize(ctx context.Context, req reinitializeRequest, localNodeConfig *datapath.LocalNodeConfiguration) error {
	if req.ctx != nil {
		ctx = req.ctx
	}

	var errs []error
	if err := o.params.Loader.Reinitialize(
		ctx,
		localNodeConfig,
		o.params.TunnelConfig,
		o.params.IPTablesManager,
		o.params.Proxy,
	); err != nil {
		errs = append(errs, err)
	}

	// Store the latest local node configuration before triggering the regeneration and
	// before closing the dpInitialized channel. This is so the proxy methods called from
	// a different routine have the same info as the latest Reinitialize call.
	o.latestLocalNodeConfig.Store(localNodeConfig)

	if !o.initDone {
		close(o.dpInitialized)
		o.initDone = true
	}

	// Issue a regeneration for all endpoints, including the host endpoint.
	// This will eventually trigger calls to [ReloadDatapath], which will requery
	// the devices and addresses. It's guaranteed that it will use a LoaderContext
	// equal to or newer than what we saw here.
	regenRequest := &regeneration.ExternalRegenerationMetadata{
		Reason:            "Configuration or devices changed",
		RegenerationLevel: regeneration.RegenerateWithDatapath,
		ParentContext:     ctx,
	}
	o.params.EndpointManager.RegenerateAllEndpoints(regenRequest).Wait()

	err := errors.Join(errs...)
	if req.errChan != nil {
		select {
		case req.errChan <- err:
		default:
		}
		close(req.errChan)
	}

	return err
}

func (o *orchestrator) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) (string, error) {
	select {
	case <-o.dpInitialized:
	case <-ctx.Done():
		return "", ctx.Err()
	}

	return o.params.Loader.ReloadDatapath(ctx, ep, o.latestLocalNodeConfig.Load(), stats)
}

func (o *orchestrator) ReinitializeXDP(ctx context.Context, extraCArgs []string) error {
	select {
	case <-o.dpInitialized:
	case <-ctx.Done():
		return ctx.Err()
	}

	return o.params.Loader.ReinitializeXDP(ctx, o.latestLocalNodeConfig.Load(), extraCArgs)
}

func (o *orchestrator) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	<-o.dpInitialized
	return o.params.Loader.EndpointHash(cfg, o.latestLocalNodeConfig.Load())
}

func (o *orchestrator) Unload(ep datapath.Endpoint) {
	<-o.dpInitialized
	o.params.Loader.Unload(ep)
}

func (o *orchestrator) WriteEndpointConfig(w io.Writer, cfg datapath.EndpointConfiguration) error {
	<-o.dpInitialized
	return o.params.Loader.WriteEndpointConfig(w, cfg, o.latestLocalNodeConfig.Load())
}
