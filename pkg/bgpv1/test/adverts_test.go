// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	ipam_option "github.com/cilium/cilium/pkg/ipam/option"
	ipam_types "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// maxTestDuration is allowed time for test execution
	maxTestDuration = 15 * time.Second

	// maxGracefulRestartTestDuration is max allowed time for graceful restart test
	maxGracefulRestartTestDuration = 1 * time.Minute
)

// Test_PodCIDRAdvert validates pod IPv4/v6 subnet is advertised, withdrawn and modified on node addresses change.
func Test_PodCIDRAdvert(t *testing.T) {
	testutils.PrivilegedTest(t)

	node.SetTestLocalNodeStore()
	defer node.UnsetTestLocalNodeStore()

	// steps define order in which test is run. Note, this is different from table tests, in which each unit is
	// independent. In this case, tests are run sequentially and there is dependency on previous test step.
	var steps = []struct {
		description         string
		podCIDRs            []string
		expectedRouteEvents []routeEvent
	}{
		{
			description: "advertise pod CIDRs",
			podCIDRs: []string{
				"10.1.0.0/16",
				"aaaa::/64",
			},
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.1.0.0",
					prefixLen:   16,
					isWithdrawn: false,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "aaaa::",
					prefixLen:   64,
					isWithdrawn: false,
				},
			},
		},
		{
			description: "delete pod CIDRs",
			podCIDRs:    []string{},
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.1.0.0",
					prefixLen:   16,
					isWithdrawn: true,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "aaaa::",
					prefixLen:   64,
					isWithdrawn: true,
				},
			},
		},
		{
			description: "re-add pod CIDRs",
			podCIDRs: []string{
				"10.1.0.0/16",
				"aaaa::/64",
			},
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.1.0.0",
					prefixLen:   16,
					isWithdrawn: false,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "aaaa::",
					prefixLen:   64,
					isWithdrawn: false,
				},
			},
		},
		{
			description: "update pod CIDRs",
			podCIDRs: []string{
				"10.2.0.0/16",
				"bbbb::/64",
			},
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.1.0.0",
					prefixLen:   16,
					isWithdrawn: true,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "10.2.0.0",
					prefixLen:   16,
					isWithdrawn: false,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "aaaa::",
					prefixLen:   64,
					isWithdrawn: true,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "bbbb::",
					prefixLen:   64,
					isWithdrawn: false,
				},
			},
		},
	}

	testCtx, testDone := context.WithTimeout(context.Background(), maxTestDuration)
	defer testDone()

	// setup topology
	gobgpPeers, fixture, cleanup, err := setup(testCtx, []gobgpConfig{gobgpConf}, fixtureConf)
	require.NoError(t, err)
	require.Len(t, gobgpPeers, 1)
	defer cleanup()

	// setup neighbor
	err = setupSingleNeighbor(testCtx, fixture)
	require.NoError(t, err)

	// wait for peering to come up
	err = gobgpPeers[0].waitForSessionState(testCtx, []string{"ESTABLISHED"})
	require.NoError(t, err)

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			// update node in LocalNodeStore with new PodCIDR
			// this will trigger a reconciliation as the controller is observing
			// the LocalNodeStore
			fixture.nodeStore.Update(func(n *node.LocalNode) {
				n.IPv4SecondaryAllocCIDRs = n.IPv4SecondaryAllocCIDRs[0:0]
				for _, podCIDR := range step.podCIDRs {
					n.IPv4SecondaryAllocCIDRs = append(n.IPv4SecondaryAllocCIDRs, cidr.MustParseCIDR(podCIDR))
				}
			})

			// validate expected result
			receivedEvents, err := gobgpPeers[0].getRouteEvents(testCtx, len(step.expectedRouteEvents))
			require.NoError(t, err, step.description)

			// match events in any order
			require.ElementsMatch(t, step.expectedRouteEvents, receivedEvents, step.description)
		})
	}
}

// Test_PodIPPoolAdvert validates pod ip pools are advertised to BGP peers.
func Test_PodIPPoolAdvert(t *testing.T) {
	testutils.PrivilegedTest(t)

	node.SetTestLocalNodeStore()
	defer node.UnsetTestLocalNodeStore()

	// Steps define the order that tests are run. Note, this is different from table tests,
	// in which each unit is independent. In this case, tests are run sequentially and there
	// is dependency on previous test step.
	var steps = []struct {
		name         string
		ipPools      []ipam_types.IPAMPoolAllocation
		poolLabels   map[string]string
		nodePools    map[string][]string
		poolSelector *slim_metav1.LabelSelector
		expected     []routeEvent
	}{
		{
			name: "nil pool labels",
			ipPools: []ipam_types.IPAMPoolAllocation{
				{
					Pool:  "pool1",
					CIDRs: []ipam_types.IPAMPodCIDR{"10.1.0.0/16"},
				},
			},
			poolLabels: nil,
			nodePools: map[string][]string{
				"pool1": {"10.1.1.0/24", "10.1.2.0/24"},
			},
			poolSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"no": "pool-labels"},
			},
			expected: []routeEvent{},
		},
		{
			name: "nil node pools",
			ipPools: []ipam_types.IPAMPoolAllocation{
				{
					Pool:  "pool1",
					CIDRs: []ipam_types.IPAMPodCIDR{"10.1.0.0/16"},
				},
			},
			poolLabels: map[string]string{"no": "node-cidrs"},
			nodePools:  nil,
			poolSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"no": "node-cidrs"},
			},
			expected: []routeEvent{},
		},
		{
			name: "matching ipv4 pool",
			ipPools: []ipam_types.IPAMPoolAllocation{
				{
					Pool:  "pool1",
					CIDRs: []ipam_types.IPAMPodCIDR{"11.1.0.0/16"},
				},
			},
			poolLabels: map[string]string{"label": "matched"},
			nodePools: map[string][]string{
				"pool1": {"11.1.1.0/24"},
			},
			poolSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"label": "matched"},
			},
			expected: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "11.1.1.0",
					prefixLen:   24,
					isWithdrawn: false,
				},
			},
		},
		{
			name: "update matching ipv4 pool",
			ipPools: []ipam_types.IPAMPoolAllocation{
				{
					Pool:  "pool1",
					CIDRs: []ipam_types.IPAMPodCIDR{"11.2.0.0/16"},
				},
			},
			poolLabels: map[string]string{"label": "matched"},
			nodePools: map[string][]string{
				"pool1": {"11.2.1.0/24"},
			},
			poolSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"label": "matched"},
			},
			expected: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "11.1.1.0",
					prefixLen:   24,
					isWithdrawn: true,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "11.2.1.0",
					prefixLen:   24,
					isWithdrawn: false,
				},
			},
		},
		{
			name: "matching ipv6 pool",
			ipPools: []ipam_types.IPAMPoolAllocation{
				{
					Pool:  "pool1",
					CIDRs: []ipam_types.IPAMPodCIDR{"2001:0:0:1234::/64"},
				},
			},
			poolLabels: map[string]string{"label": "matched"},
			nodePools: map[string][]string{
				"pool1": {"2001:0:0:1234:5678::/96"},
			},
			poolSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"label": "matched"},
			},
			expected: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "2001:0:0:1234:5678::",
					prefixLen:   96,
					isWithdrawn: false,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "11.2.1.0",
					prefixLen:   24,
					isWithdrawn: true,
				},
			},
		},
		{
			name: "update matching ipv6 pool",
			ipPools: []ipam_types.IPAMPoolAllocation{
				{
					Pool:  "pool1",
					CIDRs: []ipam_types.IPAMPodCIDR{"2002:0:0:1234::/64"},
				},
			},
			poolLabels: map[string]string{"label": "matched"},
			nodePools: map[string][]string{
				"pool1": {"2002:0:0:1234:5678::/96"},
			},
			poolSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"label": "matched"},
			},
			expected: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "2001:0:0:1234:5678::",
					prefixLen:   96,
					isWithdrawn: true,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "2002:0:0:1234:5678::",
					prefixLen:   96,
					isWithdrawn: false,
				},
			},
		},
	}

	testCtx, testDone := context.WithTimeout(context.Background(), maxTestDuration)
	defer testDone()

	// setup topology
	cfg := fixtureConf
	cfg.ipam = ipam_option.IPAMMultiPool
	gobgpPeers, fixture, cleanup, err := setup(testCtx, []gobgpConfig{gobgpConf}, cfg)
	require.NoError(t, err)
	require.Len(t, gobgpPeers, 1)
	defer cleanup()

	// setup neighbor
	err = setupSingleNeighbor(testCtx, fixture)
	require.NoError(t, err)

	// wait for peering to establish
	err = gobgpPeers[0].waitForSessionState(testCtx, []string{"ESTABLISHED"})
	require.NoError(t, err)

	tracker := fixture.fakeClientSet.CiliumFakeClientset.Tracker()

	for i, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			// Setup pod ip pool objects with test case pool cidrs.
			var poolObjs []*v2alpha1.CiliumPodIPPool
			for _, pool := range step.ipPools {
				var confCIDRs []ipam_types.IPAMPodCIDR
				confCIDRs = append(confCIDRs, pool.CIDRs...)
				poolObj := newIPPoolObj(ipPoolConfig{
					name:   pool.Pool,
					labels: step.poolLabels,
					cidrs:  confCIDRs,
				})
				poolObjs = append(poolObjs, poolObj)
			}

			// Add or update the pod ip pool object in the object tracker.
			if i == 0 {
				for _, obj := range poolObjs {
					err = tracker.Add(obj)
				}
			} else {
				for _, obj := range poolObjs {
					err = tracker.Update(v2alpha1.SchemeGroupVersion.WithResource("ciliumpodippools"), obj, "")
				}
			}
			require.NoError(t, err)

			// Setup the cilium node object with test case node cidrs.
			allocs := make(map[string][]string)
			for pool, cidrs := range step.nodePools {
				allocs[pool] = cidrs
			}
			nodeObj := newCiliumNode(&ciliumNodeConfig{
				name:   "test",
				allocs: allocs,
			})

			// Add or update the cilium node object in the object tracker.
			if i == 0 {
				err = tracker.Add(nodeObj)
			} else {
				err = tracker.Update(v2.SchemeGroupVersion.WithResource("ciliumnodes"), nodeObj, "")
			}
			require.NoError(t, err)

			// Setup the bgp policy object with the test case pool selector.
			fixture.config.policy.Spec.VirtualRouters[0].PodIPPoolSelector = step.poolSelector
			_, err = fixture.policyClient.Update(testCtx, &fixture.config.policy, meta_v1.UpdateOptions{})
			require.NoError(t, err)

			// Validate the expected result.
			receivedEvents, err := gobgpPeers[0].getRouteEvents(testCtx, len(step.expected))
			require.NoError(t, err, step.name)

			// Match events in any order.
			t.Logf("expected events: %v", step.expected)
			t.Logf("received events: %v", receivedEvents)
			require.ElementsMatch(t, step.expected, receivedEvents, step.name)
		})
	}
}

// Test_LBEgressAdvertisement validates Service v4 and v6 IPs is advertised, withdrawn and modified on changing policy.
func Test_LBEgressAdvertisement(t *testing.T) {
	testutils.PrivilegedTest(t)

	node.SetTestLocalNodeStore()
	defer node.UnsetTestLocalNodeStore()

	var steps = []struct {
		description         string
		srvName             string
		ingressIP           string
		op                  string // add or update
		expectedRouteEvents []routeEvent
	}{
		{
			description: "advertise service IP",
			srvName:     "service-a",
			ingressIP:   "10.100.1.1",
			op:          "add",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.100.1.1",
					prefixLen:   32,
					isWithdrawn: false,
				},
			},
		},
		{
			description: "withdraw service IP",
			srvName:     "service-a",
			ingressIP:   "",
			op:          "update",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.100.1.1",
					prefixLen:   32,
					isWithdrawn: true,
				},
			},
		},
		{
			description: "re-advertise service IP",
			srvName:     "service-a",
			ingressIP:   "10.100.1.1",
			op:          "update",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.100.1.1",
					prefixLen:   32,
					isWithdrawn: false,
				},
			},
		},
		{
			description: "update service IP",
			srvName:     "service-a",
			ingressIP:   "10.200.1.1",
			op:          "update",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "10.100.1.1",
					prefixLen:   32,
					isWithdrawn: true,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "10.200.1.1",
					prefixLen:   32,
					isWithdrawn: false,
				},
			},
		},
		{
			description: "advertise v6 service IP",
			srvName:     "service-b",
			ingressIP:   "cccc::1",
			op:          "add",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "cccc::1",
					prefixLen:   128,
					isWithdrawn: false,
				},
			},
		},
		{
			description: "withdraw v6 service IP",
			srvName:     "service-b",
			ingressIP:   "",
			op:          "update",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "cccc::1",
					prefixLen:   128,
					isWithdrawn: true,
				},
			},
		},
		{
			description: "re-advertise v6 service IP",
			srvName:     "service-b",
			ingressIP:   "cccc::1",
			op:          "update",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "cccc::1",
					prefixLen:   128,
					isWithdrawn: false,
				},
			},
		},
		{
			description: "update v6 service IP",
			srvName:     "service-b",
			ingressIP:   "dddd::1",
			op:          "update",
			expectedRouteEvents: []routeEvent{
				{
					sourceASN:   ciliumASN,
					prefix:      "cccc::1",
					prefixLen:   128,
					isWithdrawn: true,
				},
				{
					sourceASN:   ciliumASN,
					prefix:      "dddd::1",
					prefixLen:   128,
					isWithdrawn: false,
				},
			},
		},
	}

	testCtx, testDone := context.WithTimeout(context.Background(), maxTestDuration)
	defer testDone()

	// setup topology
	gobgpPeers, fixture, cleanup, err := setup(testCtx, []gobgpConfig{gobgpConf}, fixtureConf)
	require.NoError(t, err)
	require.Len(t, gobgpPeers, 1)
	defer cleanup()

	// setup neighbor
	err = setupSingleNeighbor(testCtx, fixture)
	require.NoError(t, err)

	// wait for peering to come up
	err = gobgpPeers[0].waitForSessionState(testCtx, []string{"ESTABLISHED"})
	require.NoError(t, err)

	// setup bgp policy with service selection
	fixture.config.policy.Spec.VirtualRouters[0].ServiceSelector = &slim_metav1.LabelSelector{
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			// always true match
			{
				Key:      "somekey",
				Operator: "NotIn",
				Values:   []string{"not-somekey"},
			},
		},
	}
	_, err = fixture.policyClient.Update(testCtx, &fixture.config.policy, meta_v1.UpdateOptions{})
	require.NoError(t, err)

	tracker := fixture.fakeClientSet.SlimFakeClientset.Tracker()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			srvObj := newLBServiceObj(lbSrvConfig{
				name:      step.srvName,
				ingressIP: step.ingressIP,
			})

			if step.op == "add" {
				err = tracker.Add(&srvObj)
			} else {
				err = tracker.Update(slim_metav1.Unversioned.WithResource("services"), &srvObj, "")
			}
			require.NoError(t, err, step.description)

			// validate expected result
			receivedEvents, err := gobgpPeers[0].getRouteEvents(testCtx, len(step.expectedRouteEvents))
			require.NoError(t, err, step.description)

			// match events in any order
			require.ElementsMatch(t, step.expectedRouteEvents, receivedEvents, step.description)
		})
	}
}
