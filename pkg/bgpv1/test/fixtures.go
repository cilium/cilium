// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sPkg "github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
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

	baseBGPPolicy = policyConfig{
		nodeSelector: labels,
		virtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
			{
				LocalASN: int64(ciliumASN),
			},
		},
	}

	// Daemon start config
	fixtureConf = fixtureConfig{
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
	nodeStore     *node.LocalNodeStore
}

type fixtureConfig struct {
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

	// create initial bgp policy
	f.fakeClientSet.CiliumFakeClientset.Tracker().Add(&conf.policy)

	// Construct a new Hive with mocked out dependency cells.
	f.hive = hive.New(
		cell.Config(k8sPkg.DefaultConfig),

		// service
		cell.Provide(k8sPkg.ServiceResource),

		// endpoints
		cell.Provide(k8sPkg.EndpointsResource),

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

		// LocalNodeStore
		cell.Provide(func() *node.LocalNodeStore {
			store := node.NewTestLocalNodeStore(node.LocalNode{
				Node: types.Node{
					Annotations: map[string]string{
						nodeAnnotationKey: nodeAnnotationValues,
					},
					Labels: labels,
				},
			})
			f.nodeStore = store
			return store
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
		LocalASN:      int64(ciliumASN),
		ExportPodCIDR: pointer.Bool(true),
		Neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
			{
				PeerAddress: dummies[instance1Link].ipv4.String(),
				PeerASN:     int64(gobgpASN),
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

		f.bgp.BGPMgr.Stop()

		f.hive.Stop(ctx)
		teardownLinks()
	}

	return
}
