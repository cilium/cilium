// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/hive"
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

func newFixture(ctx context.Context, req *require.Assertions) (*fixture, func()) {
	var (
		onceCN, onceBGPCC   sync.Once
		cnWatch, bgpccWatch = make(chan struct{}), make(chan struct{})
	)

	f := &fixture{}
	f.fakeClientSet, _ = k8s_client.NewFakeClientset()

	watchReactorFn := func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
		w := action.(k8sTesting.WatchAction)
		gvr := w.GetResource()
		ns := w.GetNamespace()
		watch, err := f.fakeClientSet.CiliumFakeClientset.Tracker().Watch(gvr, ns)
		if err != nil {
			return false, nil, err
		}

		switch w.GetResource().Resource {
		case "ciliumnodes":
			onceCN.Do(func() { close(cnWatch) })
		case "ciliumbgpclusterconfigs":
			onceBGPCC.Do(func() { close(bgpccWatch) })
		default:
			return false, watch, nil
		}

		return true, watch, nil
	}

	// make sure watchers are initialized before the test starts
	watchersReadyFn := func() {
		select {
		case <-cnWatch:
		case <-ctx.Done():
			req.Fail("cilium node watcher is not initialized")
		}

		select {
		case <-bgpccWatch:
		case <-ctx.Done():
			req.Fail("cilium bgp cluster config watcher is not initialized")
		}
	}

	f.bgpcClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPClusterConfigs()
	f.nodeClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2().CiliumNodes()
	f.bgpnClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPNodeConfigs()
	f.bgpncoClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPNodeConfigOverrides()

	f.fakeClientSet.CiliumFakeClientset.PrependWatchReactor("*", watchReactorFn)

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

		Cell,
	)

	return f, watchersReadyFn
}
