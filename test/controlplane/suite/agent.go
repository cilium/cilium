// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package suite

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	fakeApiExt "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/daemon/cmd"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/endpoint"
	fakeCilium "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	fakeSlim "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	agentOption "github.com/cilium/cilium/pkg/option"
)

type agentHandle struct {
	d       *cmd.Daemon
	cancel  context.CancelFunc
	clean   func()
	tempDir string
}

func (h *agentHandle) tearDown() {
	h.d.Close()
	h.cancel()
	h.clean()
	os.RemoveAll(h.tempDir)
}

func startCiliumAgent(nodeName string, clients fakeClients) (*fakeDatapath.FakeDatapath, agentHandle, error) {
	var handle agentHandle

	handle.tempDir = setupTestDirectories()

	fdp := fakeDatapath.NewDatapath()

	ctx, cancel := context.WithCancel(context.Background())
	handle.cancel = cancel

	cleaner := cmd.NewDaemonCleanup()
	handle.clean = cleaner.Clean

	var err error
	handle.d, _, err = cmd.NewDaemon(ctx,
		cleaner,
		cmd.WithCustomEndpointManager(&dummyEpSyncher{}),
		fdp)
	if err != nil {
		return nil, agentHandle{}, err
	}
	return fdp, handle, nil
}

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

func setupTestDirectories() string {
	tempDir, err := ioutil.TempDir("", "cilium-test-")
	if err != nil {
		panic(fmt.Sprintf("TempDir() failed: %s", err))
	}
	agentOption.Config.RunDir = tempDir
	agentOption.Config.StateDir = tempDir
	return tempDir
}

type k8sConfig struct{}

func (k8sConfig) K8sAPIDiscoveryEnabled() bool {
	return true
}

func (k8sConfig) K8sLeasesFallbackDiscoveryEnabled() bool {
	return false
}

type fakeClients struct {
	core   *fake.Clientset
	slim   *fakeSlim.Clientset
	cilium *fakeCilium.Clientset
	apiext *fakeApiExt.Clientset
}
