// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
	"github.com/cilium/cilium/pkg/time"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// minReinitInterval is the minimum interval to wait between reinitializations.
	minReinitInterval = 500 * time.Millisecond

	// reinitRetryDuration is the time to wait before retrying failed reinitialization.
	reinitRetryDuration = 10 * time.Second
)

var DefaultConfig = Config{
	// By default the masquerading IP is the primary IP address of the device in
	// question.
	DeriveMasqIPAddrFromDevice: "",
}

type Config struct {
	// DeriveMasqIPAddrFromDevice specifies which device's IP addr is used for BPF masquerade.
	// This is a hidden option and by default not set. Only needed in very specific setups
	// with ECMP and multiple devices.
	// See commit d204d789746b1389cc2ba02fdd55b81a2f55b76e for original context.
	// This can be removed once https://github.com/cilium/cilium/issues/17158 is resolved.
	DeriveMasqIPAddrFromDevice string
}

func (def Config) Flags(flags *pflag.FlagSet) {
	const deriveFlag = "derive-masq-ip-addr-from-device"
	flags.String(
		deriveFlag, def.DeriveMasqIPAddrFromDevice,
		"Device name from which Cilium derives the IP addr for BPF masquerade")
	flags.MarkHidden(deriveFlag)
}

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

	Config              Config
	Log                 *slog.Logger
	Loader              datapath.Loader
	TunnelConfig        tunnel.Config
	OldMTU              mtu.MTU
	MTU                 statedb.Table[mtu.RouteMTU]
	IPTablesManager     datapath.IptablesManager
	Proxy               *proxy.Proxy
	DB                  *statedb.DB
	Devices             statedb.Table[*tables.Device]
	NodeAddresses       statedb.Table[tables.NodeAddress]
	Sysctl              sysctl.Sysctl
	DirectRoutingDevice tables.DirectRoutingDevice
	LocalNodeStore      *node.LocalNodeStore
	NodeDiscovery       *nodediscovery.NodeDiscovery
	JobGroup            job.Group
	Lifecycle           cell.Lifecycle
	EndpointManager     endpointmanager.EndpointManager
	ConfigPromise       promise.Promise[*option.DaemonConfig]
	XDPConfig           xdp.Config
	LBConfig            loadbalancer.Config
	KPRConfig           kpr.KPRConfig
	SvcRouteConfig      svcrouteconfig.RoutesConfig
	MaglevConfig        maglev.Config
	WgAgent             wgTypes.WireguardAgent
	IPsecConfig         datapath.IPsecConfig
	BIGTCPConfig        *bigtcp.Configuration
	ConnectorConfig     datapath.ConnectorConfig
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	o := &orchestrator{
		params:        params,
		trigger:       make(chan reinitializeRequest, 1),
		dpInitialized: make(chan struct{}),
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			for {
				rxt := params.DB.ReadTxn()
				mtuRoute, _, watch, found := params.MTU.GetWatch(rxt, mtu.MTURouteIndex.Query(mtu.DefaultPrefixV4))
				if !found {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-watch:
						continue
					}
				}

				// Reinitialize the host device in a separate, blocking start hook to make sure all
				// our dependencies can access the host device. This is necessary because one of these
				// is the Daemon, which the main reconciliation loop has to wait for.
				if err := o.params.Loader.ReinitializeHostDev(ctx, mtuRoute.DeviceMTU); err != nil {
					return fmt.Errorf("failed to reinitialize host device: %w", err)
				}
				return nil
			}
		},
	})

	params.JobGroup.Add(job.OneShot("reinitialize", o.reconciler, job.WithShutdown()))

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
	localNodes := stream.ToTruncatingChannel(ctx,
		stream.Filter(o.params.LocalNodeStore,
			func(n node.LocalNode) bool {
				if agentConfig.EnableIPv4 {
					loopback := n.Local.ServiceLoopbackIPv4 != nil
					ipv4GW := n.GetCiliumInternalIP(false) != nil
					ipv4Range := n.IPv4AllocCIDR != nil
					if !ipv4GW || !ipv4Range || !loopback {
						return false
					}
				}
				if agentConfig.EnableIPv6 {
					loopback := n.Local.ServiceLoopbackIPv6 != nil
					ipv6GW := n.GetCiliumInternalIP(true) != nil
					if !ipv6GW || !loopback {
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
	for {
		var prevConfig *datapath.LocalNodeConfiguration
		localNodeConfig, localNodeConfigWatch, err := newLocalNodeConfig(
			ctx,
			option.Config,
			localNode,
			o.params.Sysctl,
			o.params.TunnelConfig,
			o.params.DB.ReadTxn(),
			o.params.DirectRoutingDevice,
			o.params.Devices,
			o.params.NodeAddresses,
			o.params.Config.DeriveMasqIPAddrFromDevice,
			o.params.XDPConfig,
			o.params.LBConfig,
			o.params.KPRConfig,
			o.params.SvcRouteConfig,
			o.params.MaglevConfig,
			o.params.MTU,
			o.params.WgAgent,
			o.params.IPsecConfig,
			o.params.ConnectorConfig,
		)
		if err != nil {
			health.Degraded("failed to get local node configuration", err)
			o.params.Log.Warn("Failed to construct local node configuration", logfields.Error, err)
			if request.errChan != nil {
				select {
				case request.errChan <- err:
				default:
				}
				close(request.errChan)
			}
			if localNodeConfigWatch == nil {
				retryChan = time.After(reinitRetryDuration)
			}
			goto waitReinit
		}

		// Reinitializeing is expensive, only do so if the configuration has changed.
		prevConfig = o.latestLocalNodeConfig.Load()
		if prevConfig == nil || !prevConfig.DeepEqual(&localNodeConfig) {
			if err := o.reinitialize(ctx, request, &localNodeConfig); err != nil {
				o.params.Log.Warn("Failed to initialize datapath, retrying later",
					logfields.Error, err,
					logfields.RetryDelay, reinitRetryDuration,
				)
				health.Degraded("Failed to reinitialize datapath", err)
				retryChan = time.After(reinitRetryDuration)
			} else {
				retryChan = nil
				health.OK("OK")
			}
		} else {
			// We don't need to reinitialize, but we still need to unblock the requestor if there is one.
			if request.errChan != nil {
				close(request.errChan)
			}
		}

	waitReinit:
		request = reinitializeRequest{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-localNodeConfigWatch:
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

func (o *orchestrator) DatapathInitialized() <-chan struct{} {
	return o.dpInitialized
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

	err := o.params.Loader.Reinitialize(
		ctx,
		localNodeConfig,
		o.params.TunnelConfig,
		o.params.IPTablesManager,
		o.params.Proxy,
		o.params.BIGTCPConfig,
	)
	if err == nil {
		err = o.params.ConnectorConfig.Reinitialize()
	}
	if err != nil {
		if req.errChan != nil {
			select {
			case req.errChan <- err:
			default:
			}
			close(req.errChan)
		}
		return err
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
	return nil
}

func (o *orchestrator) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) (string, error) {
	select {
	case <-o.dpInitialized:
	case <-ctx.Done():
		return "", ctx.Err()
	}

	return o.params.Loader.ReloadDatapath(ctx, ep, o.latestLocalNodeConfig.Load(), stats)
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
