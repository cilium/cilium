// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"testing"
	"time"

	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// maxTestDuration is allowed time for test execution
	maxTestDuration = 15 * time.Second
)

// Test_PodCIDRAdvert validates pod IPv4/v6 subnet is advertised, withdrawn and modified on node addresses change.
func Test_PodCIDRAdvert(t *testing.T) {
	testutils.PrivilegedTest(t)

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

	tracker := fixture.fakeClientSet.SlimFakeClientset.Tracker()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			// update node spec
			fixture.config.node.Spec.PodCIDRs = step.podCIDRs

			err := tracker.Update(corev1.SchemeGroupVersion.WithResource("nodes"), fixture.config.node.DeepCopy(), "")
			require.NoError(t, err, step.description)

			// validate expected result
			receivedEvents, err := gobgpPeers[0].getRouteEvents(testCtx, len(step.expectedRouteEvents))
			require.NoError(t, err, step.description)

			// match events in any order
			require.ElementsMatch(t, step.expectedRouteEvents, receivedEvents, step.description)
		})
	}
}

// Test_LBEgressAdvertisement validates Service v4 and v6 IPs is advertised, withdrawn and modified on changing policy.
func Test_LBEgressAdvertisement(t *testing.T) {
	testutils.PrivilegedTest(t)

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
				err = tracker.Update(slimv1.Unversioned.WithResource("services"), &srvObj, "")
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
