// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controlplane

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
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	fakeCilium "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	fakeSlim "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
)

type agentHandle struct {
	d       *cmd.Daemon
	tempDir string
}

func (h *agentHandle) tearDown() {
	h.d.Close()
	os.RemoveAll(h.tempDir)
}

func startCiliumAgent(nodeName string, clients fakeClients, modConfig func(*option.DaemonConfig)) (*fakeDatapath.FakeDatapath, agentHandle, error) {
	types.SetName(nodeName)

	// Configure k8s and perform capability detection with the fake client.
	k8s.Configure("dummy", "dummy", 10.0, 10)
	version.Update(clients.core, &k8sConfig{})
	k8s.SetClients(clients.core, clients.slim, clients.cilium, clients.apiext)

	proxy.DefaultDNSProxy = fqdnproxy.MockFQDNProxy{}
	option.Config.Populate()
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
	option.Config.KubeProxyReplacement = option.KubeProxyReplacementStrict
	option.Config.EnableHostIPRestore = false
	option.Config.K8sRequireIPv6PodCIDR = false
	option.Config.K8sEnableK8sEndpointSlice = true
	option.Config.EnableL7Proxy = false
	option.Config.EnableHealthCheckNodePort = false
	option.Config.Debug = true

	// Apply the test specific configuration
	modConfig(option.Config)

	var handle agentHandle
	handle.tempDir = setupTestDirectories()

	fdp := fakeDatapath.NewDatapath()

	ctx, cancel := context.WithCancel(context.Background())
	var err error
	handle.d, _, err = cmd.NewDaemon(ctx, cancel,
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
	option.Config.RunDir = tempDir
	option.Config.StateDir = tempDir
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
