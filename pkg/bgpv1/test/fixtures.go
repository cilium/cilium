// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

var (
	// log is used in the test as well as passed to gobgp instances.
	log = &logrus.Logger{
		Out:   os.Stdout,
		Hooks: make(logrus.LevelHooks),
		Formatter: &logrus.TextFormatter{
			DisableTimestamp: false,
			DisableColors:    false,
		},
		Level: logrus.DebugLevel,
	}
)

// cilium BGP config
var (
	ciliumASN        = uint32(65001)
	ciliumListenPort = uint32(1790)
)

// kubernetes policies
var (
	// base node spec
	nodeAnnotationKey    = fmt.Sprintf("%s%d", annotation.BGPVRouterAnnoPrefix, ciliumASN)
	nodeAnnotationValues = fmt.Sprintf("router-id=%s,local-port=%d",
		dummies[ciliumLink].ipv4.Addr().String(), ciliumListenPort)

	labels = map[string]string{
		"rack": "rack0",
	}

	baseNodeConf = nodeConfig{
		labels: labels,
		annotations: map[string]string{
			nodeAnnotationKey: nodeAnnotationValues,
		},
	}

	baseBGPPolicy = policyConfig{
		nodeSelector: labels,
		virtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
			{
				LocalASN: int(ciliumASN),
			},
		},
	}

	// Daemon start config
	fixtureConf = fixtureConfig{
		node:      newNodeObj(baseNodeConf),
		policy:    newPolicyObj(baseBGPPolicy),
		ipam:      ipamOption.IPAMKubernetes,
		bgpEnable: true,
	}
)

// fixture is test harness
type fixture struct {
	config        fixtureConfig
	fakeClientSet *k8sClient.FakeClientset
	policyClient  v2alpha1.CiliumBGPPeeringPolicyInterface
	hive          *hive.Hive
	bgp           *agent.Controller
}

type fixtureConfig struct {
	node      slim_core_v1.Node
	policy    cilium_api_v2alpha1.CiliumBGPPeeringPolicy
	ipam      string
	bgpEnable bool
}

func newFixture(conf fixtureConfig) *fixture {
	f := &fixture{
		config: conf,
	}

	f.fakeClientSet, _ = k8sClient.NewFakeClientset()
	f.policyClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPPeeringPolicies()

	// create default base node
	f.fakeClientSet.SlimFakeClientset.Tracker().Create(
		slim_core_v1.SchemeGroupVersion.WithResource("nodes"), conf.node.DeepCopy(), "")

	// create initial bgp policy
	f.fakeClientSet.CiliumFakeClientset.Tracker().Add(&conf.policy)

	// Construct a new Hive with mocked out dependency cells.
	f.hive = hive.New(
		// node resource
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) k8s.LocalNodeResource {
			lw := utils.ListerWatcherFromTyped[*slim_core_v1.NodeList](c.Slim().CoreV1().Nodes())
			return k8s.LocalNodeResource(resource.New[*slim_core_v1.Node](lc, lw))
		}),

		// cilium node resource
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) k8s.LocalCiliumNodeResource {
			lw := utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](c.CiliumV2().CiliumNodes())
			return k8s.LocalCiliumNodeResource(resource.New[*cilium_api_v2.CiliumNode](lc, lw))
		}),

		// service
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*slim_core_v1.Service] {
			return resource.New[*slim_core_v1.Service](
				lc, utils.ListerWatcherFromTyped[*slim_core_v1.ServiceList](
					c.Slim().CoreV1().Services(""),
				),
			)
		}),

		// Provide the mocked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return f.fakeClientSet
		}),

		// daemon config
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableBGPControlPlane: conf.bgpEnable,
				IPAM:                  conf.ipam,
			}
		}),

		// local bgp state for inspection
		cell.Invoke(func(bgp *agent.Controller) {
			f.bgp = bgp
		}),

		job.Cell,
		bgpv1.Cell,
	)

	return f
}

func setupSingleNeighbor(ctx context.Context, f *fixture) error {
	bgpPolicy := baseBGPPolicy
	bgpPolicy.virtualRouters[0] = cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		LocalASN:      int(ciliumASN),
		ExportPodCIDR: true,
		Neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
			{
				PeerAddress: dummies[instance1Link].ipv4.String(),
				PeerASN:     int(gobgpASN),
			},
		},
	}
	policyObj := newPolicyObj(bgpPolicy)

	_, err := f.policyClient.Update(ctx, &policyObj, meta_v1.UpdateOptions{})
	return err
}

// setup configures dummy links, gobgp and cilium bgp cell.
func setup(ctx context.Context, peerConfigs []gobgpConfig, fixConfig fixtureConfig) (peers []*goBGP, f *fixture, cleanup func(), err error) {
	// cleanup old dummy links if they are hanging around
	_ = teardownLinks()

	err = setupLinks()
	if err != nil {
		return
	}

	err = setupLinkIPs()
	if err != nil {
		return
	}

	// setup goBGP
	for _, pConf := range peerConfigs {
		var peer *goBGP
		peer, err = startGoBGP(ctx, pConf)
		if err != nil {
			return
		}
		peers = append(peers, peer)
	}

	// setup cilium
	f = newFixture(fixConfig)
	err = f.hive.Start(ctx)
	if err != nil {
		return
	}

	cleanup = func() {
		for _, peer := range peers {
			peer.stopGoBGP()
		}

		f.hive.Stop(ctx)
		teardownLinks()
	}

	return
}
