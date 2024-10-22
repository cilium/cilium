// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/sirupsen/logrus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/hive"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	k8sPkg "github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	clientset_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"
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

	baseNode = ciliumNodeConfig{
		name:        "test",
		labels:      labels,
		annotations: map[string]string{nodeAnnotationKey: nodeAnnotationValues},
	}

	baseBGPPolicy = policyConfig{
		nodeSelector: labels,
		virtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouter{
			{
				LocalASN: int64(ciliumASN),
			},
		},
	}
)

// fixture is test harness
type fixture struct {
	config        fixtureConfig
	fakeClientSet *k8sClient.FakeClientset
	policyClient  v2alpha1.CiliumBGPPeeringPolicyInterface
	secretClient  clientset_core_v1.SecretInterface
	hive          *hive.Hive
	cells         []cell.Cell
	bgp           *agent.Controller
	ciliumNode    daemon_k8s.LocalCiliumNodeResource
}

type fixtureConfig struct {
	node      cilium_api_v2.CiliumNode
	policy    cilium_api_v2alpha1.CiliumBGPPeeringPolicy
	secret    slim_core_v1.Secret
	ipam      string
	bgpEnable bool
}

func newFixtureConf() fixtureConfig {
	policyCfg := policyConfig{
		nodeSelector: baseBGPPolicy.nodeSelector,
	}
	secret := slim_core_v1.Secret{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace: "bgp-secrets",
			Name:      "a-secret",
		},
		Data: map[string]slim_core_v1.Bytes{"password": slim_core_v1.Bytes("testing-123")},
	}

	// deepcopy the VirtualRouters as the tests modify them
	for _, vr := range baseBGPPolicy.virtualRouters {
		policyCfg.virtualRouters = append(policyCfg.virtualRouters, *vr.DeepCopy())
	}
	return fixtureConfig{
		node:      newCiliumNode(baseNode),
		policy:    newPolicyObj(policyCfg),
		ipam:      ipamOption.IPAMKubernetes,
		secret:    secret,
		bgpEnable: true,
	}
}

func newFixture(conf fixtureConfig) *fixture {
	f := &fixture{
		config: conf,
	}

	f.fakeClientSet, _ = k8sClient.NewFakeClientset()
	f.policyClient = f.fakeClientSet.CiliumFakeClientset.CiliumV2alpha1().CiliumBGPPeeringPolicies()
	f.secretClient = f.fakeClientSet.SlimFakeClientset.CoreV1().Secrets("bgp-secrets")

	// create initial cilium node
	f.fakeClientSet.CiliumFakeClientset.Tracker().Add(&conf.node)

	// create initial bgp policy
	f.fakeClientSet.CiliumFakeClientset.Tracker().Add(&conf.policy)
	f.fakeClientSet.SlimFakeClientset.Tracker().Add(&conf.secret)

	// Construct a new Hive with mocked out dependency cells.
	f.cells = []cell.Cell{
		cell.Config(k8sPkg.DefaultConfig),

		// service
		cell.Provide(k8sPkg.ServiceResource),

		// endpoints
		cell.Provide(k8sPkg.EndpointsResource),

		// CiliumLoadBalancerIPPool
		cell.Provide(k8sPkg.LBIPPoolsResource),

		// cilium node
		cell.Provide(func(lc cell.Lifecycle, c k8sClient.Clientset) daemon_k8s.LocalCiliumNodeResource {
			store := resource.New[*cilium_api_v2.CiliumNode](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](
					c.CiliumV2().CiliumNodes(),
				),
			)
			f.ciliumNode = store
			return store
		}),

		// Provide the mocked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return f.fakeClientSet
		}),

		// daemon config
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableBGPControlPlane: conf.bgpEnable,
				BGPSecretsNamespace:   "bgp-secrets",
				IPAM:                  conf.ipam,
			}
		}),

		// local bgp state for inspection
		cell.Invoke(func(bgp *agent.Controller) {
			f.bgp = bgp
		}),

		metrics.Cell,
		bgpv1.Cell,
	}
	f.hive = hive.New(f.cells...)

	return f
}

func setupSingleNeighbor(ctx context.Context, f *fixture, peerASN uint32) error {
	f.config.policy.Spec.VirtualRouters[0] = cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		LocalASN:      int64(ciliumASN),
		ExportPodCIDR: ptr.To[bool](true),
		Neighbors: []cilium_api_v2alpha1.CiliumBGPNeighbor{
			{
				PeerAddress: dummies[instance1Link].ipv4.String(),
				PeerASN:     int64(peerASN),
			},
		},
	}

	_, err := f.policyClient.Update(ctx, &f.config.policy, meta_v1.UpdateOptions{})
	return err
}

// setup configures the test environment based on provided gobgp and fixture config.
func setup(ctx context.Context, t testing.TB, peerConfigs []gobgpConfig, fixConfig fixtureConfig) (peers []*goBGP, f *fixture, cleanup func(), err error) {
	f = newFixture(fixConfig)
	peers, cleanup, err = start(ctx, t, peerConfigs, f)
	return
}

// start configures dummy links, starts gobgp and cilium bgp cell.
func start(ctx context.Context, t testing.TB, peerConfigs []gobgpConfig, f *fixture) (peers []*goBGP, cleanup func(), err error) {
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

	// start goBGP
	for _, pConf := range peerConfigs {
		var peer *goBGP
		peer, err = startGoBGP(ctx, pConf)
		if err != nil {
			return
		}
		peers = append(peers, peer)
	}

	// start cilium
	tlog := hivetest.Logger(t)
	err = f.hive.Start(tlog, ctx)
	if err != nil {
		return
	}

	cleanup = func() {
		for _, peer := range peers {
			peer.stopGoBGP()
		}

		f.bgp.BGPMgr.Stop()

		f.hive.Stop(tlog, ctx)
		teardownLinks()
	}

	return
}
