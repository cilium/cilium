// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	statedbReconciler "github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/api/v1/server"
	"github.com/cilium/cilium/daemon/cmd"
	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/daemon/cmd/legacy"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/subnet"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
)

type agentHandle struct {
	t         *testing.T
	db        *statedb.DB
	nodeAddrs statedb.Table[datapathTables.NodeAddress]
	fnh       *fakeTypes.FakeNodeHandler

	hive *hive.Hive
	log  *slog.Logger
}

func (h *agentHandle) tearDown() {
	if h == nil {
		return
	}

	// If hive is nil, we have not yet started.
	if h.hive != nil {
		if err := h.hive.Stop(h.log, context.TODO()); err != nil {
			h.t.Fatalf("Failed to stop the agent: %s", err)
		}
	}
}

func (h *agentHandle) setupCiliumAgentHive(clientset k8sClient.Clientset, extraCell cell.Cell) {
	h.hive = hive.New(
		// Extra cell from the test case. Here as the first cell so it can
		// insert lifecycle hooks before anything else.
		extraCell,

		// Provide the mocked infrastructure and datapath components
		cell.Provide(
			func() (_ statedbReconciler.Reconciler[*reconciler.DesiredRoute]) { return nil },
			func() k8sClient.Clientset { return clientset },
			func() k8sClient.Config { return clientset.Config() },
			func() cnicell.CNIConfigManager { return &fakecni.FakeCNIConfigManager{} },
			func() ctmap.GCRunner { return ctmap.NewFakeGCRunner() },
			func() policymap.Factory { return nil },
			func() *server.Server { return nil },
			func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
			func() statedb.RWTable[subnet.SubnetTableEntry] {
				return nil
			},
			k8sSynced.RejectedCRDSyncPromise,
		),
		kvstore.Cell(kvstore.DisabledBackendName),
		fakeDatapath.Cell,
		neighbor.ForwardableIPCell,
		reconciler.TableCell,
		cell.Provide(neighbor.NewCommonTestConfig(true, false)),
		prefilter.Cell,
		monitorAgent.Cell,
		metrics.Cell,
		store.Cell,
		dial.ServiceResolverCell,
		cmd.ControlPlane,
		cell.Invoke(func(_ legacy.DaemonInitialization, nh *fakeTypes.FakeNodeHandler) {
			// with dry-run enabled it's enough to depend on DaemonInitialization
			h.fnh = nh
		}),

		cell.Invoke(func(db *statedb.DB, nodeAddrs statedb.Table[datapathTables.NodeAddress]) {
			h.db = db
			h.nodeAddrs = nodeAddrs
		}),
	)

	hive.AddConfigOverride(h.hive, func(c *datapathTables.DirectRoutingDeviceConfig) {
		c.DirectRoutingDevice = "test0"
	})
}

func (h *agentHandle) populateCiliumAgentOptions(testDir string, modConfig func(*option.DaemonConfig)) {
	option.Config.Populate(h.log, h.hive.Viper())

	option.Config.RunDir = testDir
	option.Config.StateDir = testDir

	// Apply the controlplane tests default configuration
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
	option.Config.DryMode = true
	option.Config.IPAM = ipamOption.IPAMKubernetes
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)
	option.Config.Opts.SetBool(option.Debug, true)
	option.Config.EnableIPv6 = false
	option.Config.K8sRequireIPv6PodCIDR = false
	option.Config.EnableL7Proxy = false
	option.Config.Debug = true

	// Apply the test-specific agent configuration modifier
	modConfig(option.Config)

	// Unlike global configuration options, cell-specific configuration options
	// (i.e. the ones defined through cell.Config(...)) must be set to the *viper.Viper
	// object bound to the test hive.
	h.hive.Viper().Set(option.EndpointGCInterval, 0)
}

func setupTestDirectories() string {
	tempDir, err := os.MkdirTemp("", "cilium-test-")
	if err != nil {
		panic(fmt.Sprintf("TempDir() failed: %s", err))
	}
	return tempDir
}
