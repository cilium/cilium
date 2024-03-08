// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	TestTimeout = 5 * time.Second
)

type fixture struct {
	hive          *hive.Hive
	fakeClientSet *k8s_client.FakeClientset
	bgpcClient    cilium_client_v2alpha1.CiliumBGPClusterConfigInterface
	nodeClient    cilium_client_v2.CiliumNodeInterface
	bgpncoClient  cilium_client_v2alpha1.CiliumBGPNodeConfigOverrideInterface

	// for validations
	bgpnClient cilium_client_v2alpha1.CiliumBGPNodeConfigInterface
}

func newFixture() *fixture {
	f := &fixture{}

	f.fakeClientSet, _ = k8s_client.NewFakeClientset()

	f.bgpcClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPClusterConfigs()
	f.nodeClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2().CiliumNodes()
	f.bgpnClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPNodeConfigs()
	f.bgpncoClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPNodeConfigOverrides()

	f.hive = hive.New(
		cell.Provide(func(lc cell.Lifecycle, c k8s_client.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumBGPClusterConfig] {
			return resource.New[*cilium_api_v2alpha1.CiliumBGPClusterConfig](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPClusterConfigList](
					c.CiliumV2alpha1().CiliumBGPClusterConfigs(),
				),
			)
		}),
		cell.Provide(func(lc cell.Lifecycle, c k8s_client.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfig] {
			return resource.New[*cilium_api_v2alpha1.CiliumBGPNodeConfig](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPNodeConfigList](
					c.CiliumV2alpha1().CiliumBGPNodeConfigs(),
				),
			)
		}),

		cell.Provide(func(lc cell.Lifecycle, c k8s_client.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride] {
			return resource.New[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverride](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPNodeConfigOverrideList](
					c.CiliumV2alpha1().CiliumBGPNodeConfigOverrides(),
				),
			)
		}),

		cell.Provide(func(lc cell.Lifecycle, c k8s_client.Clientset) resource.Resource[*cilium_api_v2.CiliumNode] {
			return resource.New[*cilium_api_v2.CiliumNode](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](
					c.CiliumV2().CiliumNodes(),
				),
			)
		}),

		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableBGPControlPlane: true,
				Debug:                 true,
			}
		}),

		cell.Provide(func() k8s_client.Clientset {
			return f.fakeClientSet
		}),

		job.Cell,
		Cell,
	)

	// enable BGPv2
	hive.AddConfigOverride(f.hive, func(cfg *Config) { cfg.BGPv2Enabled = true })

	return f
}
