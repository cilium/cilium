// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/models"
	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/auth"
	"github.com/cilium/cilium/pkg/clustermesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/health"
	hubblecell "github.com/cilium/cilium/pkg/hubble/cell"
	"github.com/cilium/cilium/pkg/ipam"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/policymap"
	monitoragent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/time"
	wireguard "github.com/cilium/cilium/pkg/wireguard/agent"
)

// Cell provides the Cilium status collector that is responsible for
// collecting and providing the status of different Cilium modules.
var Cell = cell.Module(
	"status",
	"Collects and provides Cilium status information",

	cell.Config(Config{
		StatusCollectorWarningThreshold: 15 * time.Second,
		StatusCollectorFailureThreshold: 1 * time.Minute,
		StatusCollectorInterval:         5 * time.Second,
		StatusCollectorStackdumpPath:    "/run/cilium/state/agent.stack.gz",
	}),
	cell.Provide(newStatusCollector),
	cell.Provide(newStatusAPIHandler),
	cell.Invoke(func(StatusCollector) {}), // explicit start of statuscollector
)

type statusParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger

	Config       Config
	DaemonConfig *option.DaemonConfig

	AuthManager      *auth.AuthManager
	BigTCPConfig     *bigtcp.Configuration
	BandwidthManager datapath.BandwidthManager
	CiliumHealth     health.CiliumHealthManager
	Clientset        k8sClient.Clientset
	ClusterInfo      cmtypes.ClusterInfo
	Clustermesh      *clustermesh.ClusterMesh
	CNIConfigManager cni.CNIConfigManager
	DB               *statedb.DB
	Devices          statedb.Table[*datapathTables.Device]
	DirectRoutingDev datapathTables.DirectRoutingDevice
	Hubble           hubblecell.HubbleIntegration
	IPAM             *ipam.IPAM
	K8sWatcher       *watchers.K8sWatcher
	L7Proxy          *proxy.Proxy
	MaglevConfig     maglev.Config
	MonitorAgent     monitoragent.Agent
	NodeLocalStore   *node.LocalNodeStore
	NodeDiscovery    *nodediscovery.NodeDiscovery
	PolicyMapFactory policymap.Factory
	TunnelConfig     tunnel.Config
	WireguardAgent   *wireguard.Agent
}

// Config is the collector configuration
type Config struct {
	StatusCollectorWarningThreshold time.Duration
	StatusCollectorFailureThreshold time.Duration
	StatusCollectorInterval         time.Duration
	StatusCollectorStackdumpPath    string
}

func (r Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("status-collector-warning-threshold", r.StatusCollectorWarningThreshold, "The duration after which a probe is declared as stale")
	flags.Duration("status-collector-failure-threshold", r.StatusCollectorFailureThreshold, "The duration after which a probe is considered failed")
	flags.Duration("status-collector-interval", r.StatusCollectorInterval, "The interval between probe invocations")
	flags.String("status-collector-stackdump-path", r.StatusCollectorStackdumpPath, "The path where probe stackdumps should be written to")
}

func newStatusCollector(params statusParams) StatusCollector {
	collector := &statusCollector{
		statusParams:    params,
		statusCollector: newCollector(params.Logger, params.Config),
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			return collector.startStatusCollector(context.Background())
		},
		OnStop: func(_ cell.HookContext) error {
			// If the KVstore state is not OK, print help for user.
			if collector.statusResponse.Kvstore != nil &&
				collector.statusResponse.Kvstore.State != models.StatusStateOk &&
				collector.statusResponse.Kvstore.State != models.StatusStateDisabled {

				helpMsg := "cilium-agent depends on the availability of cilium-operator/etcd-cluster. " +
					"Check if the cilium-operator pod and etcd-cluster are running and do not have any " +
					"warnings or error messages."

				params.Logger.Error("KVStore state not OK",
					logfields.Status, collector.statusResponse.Kvstore.Msg,
					logfields.HelpMessage, helpMsg,
				)

			}
			collector.statusCollector.Close()
			return nil
		},
	})

	return collector
}

type statusAPIHandlerOut struct {
	cell.Out

	GetHealthzHandler daemonapi.GetHealthzHandler
}

func newStatusAPIHandler(collector StatusCollector) statusAPIHandlerOut {
	return statusAPIHandlerOut{
		GetHealthzHandler: &GetHealthzHandler{
			collector: collector,
		},
	}
}
