// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cilium/cilium/daemon/cmd"
	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/maps/authmap"
	fakeauthmap "github.com/cilium/cilium/pkg/maps/authmap/fake"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/option"
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/statedb"
)

type agentHandle struct {
	t       *testing.T
	d       *cmd.Daemon
	tempDir string

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

	os.RemoveAll(h.tempDir)
}

func startCiliumAgent(t *testing.T, clientset k8sClient.Clientset, extraCell cell.Cell) (*fakeDatapath.FakeDatapath, agentHandle, error) {
	var (
		err           error
		handle        agentHandle
		daemonPromise promise.Promise[*cmd.Daemon]
	)

	handle.t = t
	handle.tempDir = setupTestDirectories()
	fdp := fakeDatapath.NewDatapath()

	handle.hive = hive.New(
		// Extra cell from the test case. Here as the first cell so it can
		// insert lifecycle hooks before anything else.
		extraCell,

		// Provide the mocked infrastructure and datapath components
		cell.Provide(
			func() k8sClient.Clientset { return clientset },
			func() datapath.Datapath { return fdp },
			func() *option.DaemonConfig { return option.Config },
			func() cnicell.CNIConfigManager { return &fakecni.FakeCNIConfigManager{} },
			func() signalmap.Map { return fakesignalmap.NewFakeSignalMap([][]byte{}, time.Second) },
			func() authmap.Map { return fakeauthmap.NewFakeAuthMap() },
			func() egressmap.PolicyMap { return nil },
		),
		monitorAgent.Cell,
		tables.Cell,
		statedb.Cell,
		job.Cell,
		metrics.Cell,
		cmd.ControlPlane,
		cell.Invoke(func(p promise.Promise[*cmd.Daemon]) {
			daemonPromise = p
		}),
	)

	if err := handle.hive.Start(context.TODO()); err != nil {
		return nil, agentHandle{}, err
	}

	handle.d, err = daemonPromise.Await(context.TODO())
	return fdp, handle, err
}

func setupTestDirectories() string {
	tempDir, err := os.MkdirTemp("", "cilium-test-")
	if err != nil {
		panic(fmt.Sprintf("TempDir() failed: %s", err))
	}
	agentOption.Config.RunDir = tempDir
	agentOption.Config.StateDir = tempDir
	return tempDir
}
