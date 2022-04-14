package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/mtu"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	wireguard "github.com/cilium/cilium/pkg/wireguard/agent"
)

const (
	startTimeout = 5 * time.Minute
	stopTimeout  = 5 * time.Minute
)

var linuxDatapathModule = fx.Module(
	"linux-datapath",

	fx.Provide(
		func(config *option.DaemonConfig) linuxdatapath.DatapathConfiguration {
			return linuxdatapath.DatapathConfiguration{
				HostDevice: defaults.HostDevice,
				ProcFs:     config.ProcFs,
			}
		}),

	fx.Provide(
		linuxdatapath.NewDatapath,
	),
)

var daemonModule = fx.Module(
	"daemon",

	fx.Provide(
		NewDaemon,

		// Lift out some objects from the daemon for modules.
		func(d *Daemon) (*ipcache.IPCache, mtu.Configuration) {
			return d.ipcache, d.mtuConfig
		},
	),

	fx.Invoke(
		preInit,
		registerDaemonStart,
		endpointManagerInit,
	),
)

func runApp(cmd *cobra.Command) {
	// Create a top-level context for the daemon. This is cancelled by the signal handler
	// in cleanup.go and will trigger stop.
	ctx, cancel := context.WithCancel(server.ServerCtx)

	initEnv(cmd)

	app := fx.New(
		fx.StartTimeout(startTimeout),
		fx.StopTimeout(stopTimeout),
		fx.WithLogger(newAppLogger),

		fx.Supply(
			fx.Annotate(ctx, fx.As(new(context.Context))),
			cancel),

		fx.Supply(option.Config),

		fx.Provide(
			iptables.NewIptablesManager,
			newEndpointManager,
		),

		// The order in which the modules are declared denotes the invoke and
		// OnStart order.
		linuxDatapathModule,
		daemonModule,
		wireguard.Module,
		optional(option.Config.EnableIPMasqAgent, ipmasqAgentModule),

		fx.Invoke(writeDotGraph),
	)

	if app.Err() != nil {
		log.WithError(app.Err()).Fatal("Failed to initialize daemon")
	}

	if option.Config.DotGraphOutputFile != "" {
		log.WithField("file", option.Config.DotGraphOutputFile).Infof("Wrote dot graph and now exiting without starting")
		os.Exit(0)
	}

	startCtx, cancel := context.WithTimeout(context.Background(), app.StartTimeout())
	defer cancel()

	if err := app.Start(startCtx); err != nil {
		if ctx.Err() != nil {
			// Context was cancelled during startup, e.g. due to interrupt. Exit
			// normally in this case.
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Wait until the daemon context is cancelled. This is done via the
	// cleaner on receipt of an interrupt.
	<-ctx.Done()

	stopCtx, cancel := context.WithTimeout(context.Background(), app.StopTimeout())
	defer cancel()

	if err := app.Stop(stopCtx); err != nil {
		log.WithError(err).Fatal("Failed to stop daemon")
	}
}

func optional(flag bool, opts ...fx.Option) fx.Option {
	if flag {
		return fx.Options(opts...)
	}
	return fx.Invoke()
}

func preInit() error {
	log.Info("Initializing daemon")
	option.Config.RunMonitorAgent = true

	if err := enableIPForwarding(); err != nil {
		return fmt.Errorf("error when enabling sysctl parameters: %w", err)
	}
	if k8s.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		if err := k8s.Init(option.Config); err != nil {
			return fmt.Errorf("unable to initialize Kubernetes subsystem: %w", err)
		}
		bootstrapStats.k8sInit.End(true)
	}
	return nil
}

func registerDaemonStart(lc fx.Lifecycle, d *Daemon, restoredEndpoints *endpointRestoreState) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			go runDaemon(d, restoredEndpoints)
			return nil
		},
	})
}

func newEndpointManager(ctx context.Context) *endpointmanager.EndpointManager {
	return WithDefaultEndpointManager(ctx, endpoint.CheckHealth)
}

func endpointManagerInit(lc fx.Lifecycle, em *endpointmanager.EndpointManager, ipcache *ipcache.IPCache, d *Daemon) {
	if em.HostEndpointExists() {
		em.InitHostEndpointLabels(d.ctx)
	} else {
		log.Info("Creating host endpoint")
		if err := em.AddHostEndpoint(
			d.ctx, d, d, ipcache, d.l7Proxy, d.identityAllocator,
			"Create host endpoint", nodeTypes.GetName(),
		); err != nil {
			log.WithError(err).Fatal("Unable to create host endpoint")
		}
	}

	if !option.Config.DryMode {
		em.Subscribe(d)
		lc.Append(fx.Hook{
			OnStop: func(context.Context) error {
				em.Unsubscribe(d)
				return nil
			},
		})
	}
}

var ipmasqAgentModule = fx.Module(
	"ipmasq-agent",

	fx.Provide(newIPMasqAgent),
	fx.Invoke(
		func(agent *ipmasq.IPMasqAgent) {},
	),
)

func newIPMasqAgent(lc fx.Lifecycle) (*ipmasq.IPMasqAgent, error) {
	agent, err := ipmasq.NewIPMasqAgent(option.Config.IPMasqAgentConfigPath)
	if agent != nil {
		lc.Append(fx.Hook{
			OnStart: func(context.Context) error {
				agent.Start()
				return nil
			},
			OnStop: func(context.Context) error {
				agent.Stop()
				return nil
			},
		})
	}
	return agent, err
}

func writeDotGraph(dot fx.DotGraph) {
	if option.Config.DotGraphOutputFile != "" {
		os.WriteFile(option.Config.DotGraphOutputFile, []byte(dot), 0644)
	}
}
