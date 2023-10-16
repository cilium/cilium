// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/cilium/daemon/cmd"
	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/maps/ctmap/gc"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/statedb"
)

type agentHandle struct {
	t  *testing.T
	d  *cmd.Daemon
	p  promise.Promise[*cmd.Daemon]
	dp *fakeDatapath.FakeDatapath

	hive *hive.Hive
}

func (h *agentHandle) tearDown() {
	if h == nil {
		return
	}

	// If hive is nil, we have not yet started.
	if h.hive != nil {
		if err := h.hive.Stop(context.TODO()); err != nil {
			h.t.Fatalf("Failed to stop the agent: %s", err)
		}
	}

	if h.d != nil {
		h.d.Close()
	}
}

func (h *agentHandle) setupCiliumAgentHive(clientset k8sClient.Clientset, extraCell cell.Cell) {
	h.hive = hive.New(
		// Extra cell from the test case. Here as the first cell so it can
		// insert lifecycle hooks before anything else.
		extraCell,

		// Provide the mocked infrastructure and datapath components
		cell.Provide(
			func() k8sClient.Clientset { return clientset },
			func() *option.DaemonConfig { return option.Config },
			func() cnicell.CNIConfigManager { return &fakecni.FakeCNIConfigManager{} },
			func() gc.Enabler { return gc.NewFake() },
		),
		fakeDatapath.Cell,
		monitorAgent.Cell,
		statedb.Cell,
		job.Cell,
		metrics.Cell,
		store.Cell,
		cmd.ControlPlane,
		cell.Invoke(func(p promise.Promise[*cmd.Daemon], dp *fakeDatapath.FakeDatapath) {
			h.p = p
			h.dp = dp
		}),
	)
}

func (h *agentHandle) populateCiliumAgentOptions(testDir string, modConfig func(*option.DaemonConfig)) {
	option.Config.Populate(h.hive.Viper())

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
	option.Config.EnableIPSec = false
	option.Config.EnableIPv6 = false
	option.Config.KubeProxyReplacement = option.KubeProxyReplacementTrue
	option.Config.EnableHostIPRestore = false
	option.Config.K8sRequireIPv6PodCIDR = false
	option.Config.EnableL7Proxy = false
	option.Config.EnableHealthCheckNodePort = false
	option.Config.Debug = true

	// Apply the test-specific agent configuration modifier
	modConfig(option.Config)

	// Unlike global configuration options, cell-specific configuration options
	// (i.e. the ones defined through cell.Config(...)) must be set to the *viper.Viper
	// object bound to the test hive.
	h.hive.Viper().Set(option.EndpointGCInterval, 0)

	if option.Config.EnableL7Proxy {
		proxy.DefaultDNSProxy = fqdnproxy.MockFQDNProxy{}
	}
}

func (h *agentHandle) startCiliumAgent() (*cmd.Daemon, error) {
	if err := h.hive.Start(context.TODO()); err != nil {
		return nil, err
	}

	return h.p.Await(context.TODO())
}

func setupTestDirectories() string {
	tempDir, err := os.MkdirTemp("", "cilium-test-")
	if err != nil {
		panic(fmt.Sprintf("TempDir() failed: %s", err))
	}
	return tempDir
}
