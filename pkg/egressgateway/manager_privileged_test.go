// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	testInterface1 = "cilium_egw1"
	testInterface2 = "cilium_egw2"

	node1 = "k8s1"
	node2 = "k8s2"
	node3 = "k8s3"

	node1IP = "192.168.1.1"
	node2IP = "192.168.1.2"
	node3IP = "192.168.1.3"

	ep1IP = "10.0.0.1"
	ep2IP = "10.0.0.2"
	ep3IP = "10.0.0.3"
	ep4IP = "10.0.0.4"

	destCIDR        = "1.1.1.0/24"
	destCIDR3       = "1.1.3.0/24"
	allZeroDestCIDR = "0.0.0.0/0"
	excludedCIDR1   = "1.1.1.22/32"
	excludedCIDR2   = "1.1.1.240/30"

	egressIP1   = "192.168.101.1"
	egressCIDR1 = "192.168.101.1/24"
	egressIP2   = "192.168.102.1"
	egressCIDR2 = "192.168.102.1/24"

	zeroIP4 = "0.0.0.0"

	// Special values for gatewayIP, see pkg/egressgateway/manager.go
	gatewayNotFoundValue     = "0.0.0.0"
	gatewayExcludedCIDRValue = "0.0.0.1"

	// Special values for egressIP, see pkg/egressgateway/manager.go
	egressIPNotFoundValue = "0.0.0.0"

	// Add IPv6 test constants
	ep1IPv6 = "fd00::1"
	ep2IPv6 = "fd00::2"
	ep3IPv6 = "fd00::3"
	ep4IPv6 = "fd00::4"

	destCIDRv6        = "2001:db8::/64"
	destCIDR3v6       = "2001:db8:3::/64"
	allZeroDestCIDRv6 = "::/0"
	excludedCIDR1v6   = "2001:db8::22/128"
	excludedCIDR2v6   = "2001:db8::f0/126"

	egressIP1v6   = "2001:db8:101::1"
	egressCIDR1v6 = "2001:db8:101::1/64"
	egressIP2v6   = "2001:db8:102::1"
	egressCIDR2v6 = "2001:db8:102::1/64"

	zeroIP6 = "::"

	// Special values for IPv6
	egressIPNotFoundValuev6 = "::"
)

var (
	ep1Labels = map[string]string{"test-key": "test-value-1"}
	ep2Labels = map[string]string{"test-key": "test-value-2"}

	identityAllocator = testidentity.NewMockIdentityAllocator(nil)

	nodeGroupNotFoundLabels = map[string]string{"label1": "notfound"}
	nodeGroup1Labels        = map[string]string{"label1": "1"}
	nodeGroup2Labels        = map[string]string{"label2": "2"}
	nodeGroup3Labels        = map[string]string{"label3": "3"}
)

type egressRule struct {
	sourceIP  string
	destCIDR  string
	egressIP  string
	gatewayIP string
}

type parsedEgressRule struct {
	sourceIP  netip.Addr
	destCIDR  netip.Prefix
	egressIP  netip.Addr
	gatewayIP netip.Addr
}

func (v *parsedEgressRule) String() string {
	return fmt.Sprintf("sourceIP: %s, destCIDR: %s, egressIP: %s, gatewayIP: %s",
		v.sourceIP.String(), v.destCIDR.String(), v.gatewayIP.String(), v.egressIP.String())
}

type rpFilterSetting struct {
	iFaceName       string
	rpFilterSetting string
}

type EgressGatewayTestSuite struct {
	manager   *Manager
	policies  fakeResource[*Policy]
	nodes     fakeResource[*cilium_api_v2.CiliumNode]
	endpoints fakeResource[*k8sTypes.CiliumEndpoint]
	sysctl    sysctl.Sysctl
}

func setupEgressGatewayTestSuite(t *testing.T) *EgressGatewayTestSuite {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	bpf.CheckOrMountFS(logger, "")

	err := rlimit.RemoveMemlock()
	require.NoError(t, err)

	nodeTypes.SetName(node1)

	k := &EgressGatewayTestSuite{}
	k.policies = make(fakeResource[*Policy])
	k.nodes = make(fakeResource[*cilium_api_v2.CiliumNode])
	k.endpoints = make(fakeResource[*k8sTypes.CiliumEndpoint])
	k.sysctl = sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	lc := hivetest.Lifecycle(t)
	policyMap4 := egressmap.CreatePrivatePolicyMap4(lc, nil, egressmap.DefaultPolicyConfig)
	policyMap6 := egressmap.CreatePrivatePolicyMap6(lc, nil, egressmap.DefaultPolicyConfig)

	k.manager, err = newEgressGatewayManager(Params{
		Logger:            logger,
		Lifecycle:         lc,
		Config:            Config{1 * time.Millisecond},
		DaemonConfig:      &option.DaemonConfig{},
		IdentityAllocator: identityAllocator,
		PolicyMap4:        policyMap4,
		PolicyMap6:        policyMap6,
		Policies:          k.policies,
		Nodes:             k.nodes,
		Endpoints:         k.endpoints,
		Sysctl:            k.sysctl,
	})
	require.NoError(t, err)
	require.NotNil(t, k.manager)

	return k
}

func TestEgressGatewayCEGPParser(t *testing.T) {
	setupEgressGatewayTestSuite(t)
	// must specify name
	policy := policyParams{
		name:             "",
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				iface: testInterface1,
			},
		},
	}

	cegp, _ := newCEGP(&policy)
	_, err := ParseCEGP(cegp)
	require.Error(t, err)

	// catch nil DestinationCIDR field
	policy = policyParams{
		name: "policy-1",
		policyGwParams: []policyGatewayParams{
			{
				iface: testInterface1,
			},
		},
	}

	cegp, _ = newCEGP(&policy)
	cegp.Spec.DestinationCIDRs = nil
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// must specify at least one DestinationCIDR
	policy = policyParams{
		name: "policy-1",
		policyGwParams: []policyGatewayParams{
			{
				iface: testInterface1,
			},
		},
	}

	cegp, _ = newCEGP(&policy)
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// catch nil EgressGateway field
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				iface: testInterface1,
			},
		},
	}

	cegp, _ = newCEGP(&policy)
	cegp.Spec.EgressGateway = nil
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// Catch EgressGateways that don't contain EgressGateway or EgressGateways fields.
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				iface: testInterface1,
			},
			{
				iface: testInterface2,
			},
		},
	}

	cegp, _ = newCEGP(&policy)
	cegp.Spec.EgressGateways = nil
	cegp.Spec.EgressGateway = nil
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// must specify some sort of endpoint selector
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				iface: testInterface1,
			},
		},
	}

	cegp, _ = newCEGP(&policy)
	cegp.Spec.Selectors[0].NamespaceSelector = nil
	cegp.Spec.Selectors[0].PodSelector = nil
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// can't specify both egress iface and IP
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				iface:    testInterface1,
				egressIP: egressIP1,
			},
			{
				iface:    testInterface2,
				egressIP: egressIP2,
			},
		},
	}

	cegp, _ = newCEGP(&policy)
	_, err = ParseCEGP(cegp)
	require.Error(t, err)
}

func TestEgressGatewayManager(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)
	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1, egressCIDR1v6})
	createTestInterface(t, k.sysctl, testInterface2, []string{egressCIDR2, egressCIDR2v6})

	policyMap4 := k.manager.policyMap4
	policyMap6 := k.manager.policyMap6

	egressGatewayManager := k.manager
	reconciliationEventsCount := egressGatewayManager.reconciliationEventsCount.Load()

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node1.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	node2 := newCiliumNode(node2, node2IP, nodeGroup2Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node2.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	// Create a new policy
	policy1 := policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertRPFilter(t, k.sysctl, []rpFilterSetting{
		{iFaceName: testInterface1, rpFilterSetting: "2"},
		{iFaceName: testInterface2, rpFilterSetting: "1"},
	})
	assertEgressRules4(t, policyMap4, []egressRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, id1 := newEndpointAndIdentity("ep-1", ep1IP, ep1IPv6, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
	})

	// Update the endpoint labels in order for it to not be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{})
	assertEgressRules6(t, policyMap6, []egressRule{})

	// Restore the old endpoint lables in order for it to be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
	})

	// Changing the DestCIDR to 0.0.0.0 results in a conflict with
	// the existing IP rules. Test that the manager is able to
	// resolve this conflict.
	policy1.destinationCIDRs = []string{allZeroDestCIDR, allZeroDestCIDRv6}
	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, allZeroDestCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, allZeroDestCIDRv6, egressIP1v6, node1IP},
	})

	// Restore old DestCIDR
	policy1.destinationCIDRs = []string{destCIDR, destCIDRv6}
	addPolicy(t, k.policies, &policy1)

	// Create a new policy
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-2",
		endpointLabels:   ep2Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup2Labels,
				iface:      testInterface1,
			},
		},
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
	})

	// Add a new endpoint and ID which matches policy-2
	ep2, _ := newEndpointAndIdentity("ep-2", ep2IP, ep2IPv6, ep2Labels)
	addEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})

	// Test excluded CIDRs by adding one to policy-1
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		excludedCIDRs:    []string{excludedCIDR1, excludedCIDR1v6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
		{ep1IPv6, excludedCIDR1v6, egressIP1v6, gatewayExcludedCIDRValue},
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})

	// Add a second excluded CIDR to policy-1
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		excludedCIDRs:    []string{excludedCIDR1, excludedCIDR2, excludedCIDR1v6, excludedCIDR2v6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
		{ep1IPv6, excludedCIDR1v6, egressIP1v6, gatewayExcludedCIDRValue},
		{ep1IPv6, excludedCIDR2v6, egressIP1v6, gatewayExcludedCIDRValue},
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})

	// Remove the first excluded CIDR from policy-1
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		excludedCIDRs:    []string{excludedCIDR2, excludedCIDR2v6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
		{ep1IPv6, excludedCIDR2v6, egressIP1v6, gatewayExcludedCIDRValue},
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})

	// Remove the second excluded CIDR
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})

	// Test matching no gateway
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroupNotFoundLabels,
				iface:      testInterface1,
			},
		},
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, zeroIP4, gatewayNotFoundValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, zeroIP6, gatewayNotFoundValue},
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})

	// Test a policy without valid egressIP
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-3",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR3, destCIDR3v6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      "no_interface",
			},
		},
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, zeroIP4, gatewayNotFoundValue},
		{ep1IP, destCIDR3, egressIPNotFoundValue, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, zeroIP6, gatewayNotFoundValue},
		{ep1IPv6, destCIDR3v6, egressIPNotFoundValuev6, node1IP},
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})

	// Update the endpoint labels in order for it to not be a match
	_ = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	addEndpoint(t, k.endpoints, &ep1)
	waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep2IPv6, destCIDRv6, zeroIP6, node2IP},
	})
}

func TestNodeSelector(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1, egressCIDR1v6})

	policyMap4 := k.manager.policyMap4
	policyMap6 := k.manager.policyMap6
	egressGatewayManager := k.manager

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	reconciliationEventsCount := egressGatewayManager.reconciliationEventsCount.Load()

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node1.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	node2 := newCiliumNode(node2, node2IP, nodeGroup2Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node2.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	// Create a new policy
	policy1 := policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
		nodeSelectors: nodeGroup2Labels,
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{})
	assertEgressRules6(t, policyMap6, []egressRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, _ := newEndpointAndIdentityWithNodeIP("ep-1", ep1IP, ep1IPv6, node1IP, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{}) // This ep1 should not match the policy-1
	assertEgressRules6(t, policyMap6, []egressRule{})

	// Produce a new endpoint ep2 similar to ep1 - with the same name & labels, but with a different IP address.
	// The ep1 will be deleted.
	ep2, _ := newEndpointAndIdentityWithNodeIP(ep1.Name, ep2IP, ep2IPv6, node2IP, ep1Labels)

	// Test event order: add new -> delete old
	addEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	deleteEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{ // This ep2 should match the policy-1
		{ep2IP, destCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{ // This ep2 should match the policy-1
		{ep2IPv6, destCIDRv6, egressIP1v6, node1IP},
	})

	// Produce a new endpoint ep3 similar to ep2 (and ep1) - with the same name & labels, but with a different IP address.
	ep3, _ := newEndpointAndIdentityWithNodeIP(ep1.Name, ep3IP, ep3IPv6, node1IP, ep1Labels)

	// Test event order: delete old -> update new
	deleteEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	addEndpoint(t, k.endpoints, &ep3)
	waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{}) // This ep3 should not match the policy-1
	assertEgressRules6(t, policyMap6, []egressRule{})
}

func TestEndpointDataStore(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1, egressCIDR1v6})

	policyMap4 := k.manager.policyMap4
	policyMap6 := k.manager.policyMap6
	egressGatewayManager := k.manager

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	reconciliationEventsCount := egressGatewayManager.reconciliationEventsCount.Load()

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node1.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	// Create a new policy
	policy1 := policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{})
	assertEgressRules6(t, policyMap6, []egressRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, _ := newEndpointAndIdentity("ep-1", ep1IP, ep1IPv6, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep1IPv6, destCIDRv6, egressIP1v6, node1IP},
	})

	// Simulate statefulset pod migrations to a different node.

	// Produce a new endpoint ep2 similar to ep1 - with the same name & labels, but with a different IP address.
	// The ep1 will be deleted.
	ep2, _ := newEndpointAndIdentity(ep1.Name, ep2IP, ep2IPv6, ep1Labels)

	// Test event order: add new -> delete old
	addEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	deleteEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep2IP, destCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep2IPv6, destCIDRv6, egressIP1v6, node1IP},
	})

	// Produce a new endpoint ep3 similar to ep2 (and ep1) - with the same name & labels, but with a different IP address.
	ep3, _ := newEndpointAndIdentity(ep1.Name, ep3IP, ep3IPv6, ep1Labels)

	// Test event order: delete old -> update new
	deleteEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	addEndpoint(t, k.endpoints, &ep3)
	waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep3IP, destCIDR, egressIP1, node1IP},
	})
	assertEgressRules6(t, policyMap6, []egressRule{
		{ep3IPv6, destCIDRv6, egressIP1v6, node1IP},
	})
}

func TestMultigatewayPolicy(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)
	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1, egressCIDR1v6})

	policyMap4 := k.manager.policyMap4
	policyMap6 := k.manager.policyMap6

	egressGatewayManager := k.manager
	reconciliationEventsCount := egressGatewayManager.reconciliationEventsCount.Load()

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	// Create a couple gateway nodes with different labels
	type testNodes struct {
		name   string
		ip     string
		labels map[string]string
		node   *nodeTypes.Node
	}
	// List of nodes is already organized by the node IP.
	nodes := []testNodes{
		{node1, node1IP, nodeGroup1Labels, nil},
		{node2, node2IP, nodeGroup2Labels, nil},
	}
	for i, node := range nodes {
		newNode := newCiliumNode(node.name, node.ip, node.labels)
		k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
			Kind:   resource.Upsert,
			Object: newNode.ToCiliumNode(),
		})
		nodes[i].node = &newNode
		reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager,
			reconciliationEventsCount)
	}
	// Sort the list of nodes by node IP
	slices.SortFunc(nodes, func(a, b testNodes) int {
		return netip.MustParseAddr(a.ip).Compare(netip.MustParseAddr(b.ip))
	})

	// Create endpoints with the same set of labels.
	type testEndpoints struct {
		name string
		ipv4 string
		ipv6 string
		ep   *k8sTypes.CiliumEndpoint
		id   *identity.Identity
	}
	eps := []testEndpoints{
		{"ep-1", ep1IP, ep1IPv6, nil, nil},
		{"ep-2", ep2IP, ep2IPv6, nil, nil},
		{"ep-3", ep3IP, ep3IPv6, nil, nil},
		{"ep-4", ep4IP, ep4IPv6, nil, nil},
	}
	for i, ep := range eps {
		newEP, newID := newEndpointAndIdentity(ep.name, ep.ipv4, ep.ipv6, ep1Labels)
		addEndpoint(t, k.endpoints, &newEP)
		eps[i].ep = &newEP
		eps[i].id = newID
		reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	}

	// Function to generate the correct assignments for endpoints.
	// List of nodes is expected to be sorted.
	assignEndpoints := func(endpoints []testEndpoints, gateways []testNodes, ipv4 bool) []egressRule {
		var rules []egressRule

		for _, endpoint := range endpoints {
			h := computeEndpointHash(endpoint.ep.UID)
			gw := gateways[h%uint32(len(gateways))]

			var sourceIP, cidr, egressIP string
			if ipv4 {
				sourceIP = endpoint.ipv4
				cidr = destCIDR
				// Egress IP is zero for nodes that are not the current node.
				if gw.name == node1 {
					egressIP = egressIP1
				} else {
					egressIP = zeroIP4
				}
			} else {
				sourceIP = endpoint.ipv6
				cidr = destCIDRv6
				// Egress IP is zero for nodes that are not the current node.
				if gw.name == node1 {
					egressIP = egressIP1v6
				} else {
					egressIP = zeroIP6
				}
			}

			rules = append(rules, egressRule{
				sourceIP:  sourceIP,
				destCIDR:  cidr,
				egressIP:  egressIP,
				gatewayIP: gw.ip,
			})
		}
		return rules
	}

	// Create a new policy
	policy1 := policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR, destCIDRv6},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
			{
				nodeLabels: nodeGroup2Labels,
				iface:      testInterface2,
			},
		},
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	// Check that the Egress rules are correctly created. Endpoints should have been assigned to
	// gateways in round-robin way.
	// Note that this is evaluated from the node1 perspective, so the entries for other nodes will
	// have a zeroIP as EgressIP.
	ipV4ExpectedpolicyMap := assignEndpoints(eps, nodes, true)
	ipV6ExpectedpolicyMap := assignEndpoints(eps, nodes, false)
	assertEgressRules4(t, policyMap4, ipV4ExpectedpolicyMap)
	assertEgressRules6(t, policyMap6, ipV6ExpectedpolicyMap)

	// Remove one endpoint and check that the remaining endpoints have not changed gateways.
	deleteEndpoint(t, k.endpoints, eps[0].ep)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	assertEgressRules4(t, policyMap4, ipV4ExpectedpolicyMap[1:])
	assertEgressRules6(t, policyMap6, ipV6ExpectedpolicyMap[1:])

	// Add one endpoint and check the configuration went back to the previous state.
	addEndpoint(t, k.endpoints, eps[0].ep)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	assertEgressRules4(t, policyMap4, ipV4ExpectedpolicyMap)
	assertEgressRules6(t, policyMap6, ipV6ExpectedpolicyMap)

	// Add a new gateway and check that the endpoints get redistributed.
	nodes = append(nodes, testNodes{
		name:   node3,
		ip:     node3IP,
		labels: nodeGroup3Labels,
	})
	newNode := newCiliumNode(node3, node3IP, nodeGroup3Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: newNode.ToCiliumNode(),
	})
	nodes[2].node = &newNode
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	policy1.policyGwParams = append(policy1.policyGwParams, policyGatewayParams{
		nodeLabels: nodeGroup3Labels,
		iface:      testInterface2,
	})
	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	ipV4ExpectedpolicyMap = assignEndpoints(eps, nodes, true)
	ipV6ExpectedpolicyMap = assignEndpoints(eps, nodes, false)
	assertEgressRules4(t, policyMap4, assignEndpoints(eps, nodes, true))
	assertEgressRules6(t, policyMap6, assignEndpoints(eps, nodes, false))

	// Remove two gateways to ensure the endpoints are migrated to the single gateway left.
	policy1.policyGwParams = policy1.policyGwParams[:1]
	addPolicy(t, k.policies, &policy1)
	waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	for i := range ipV4ExpectedpolicyMap {
		ipV4ExpectedpolicyMap[i].egressIP = egressIP1
		ipV4ExpectedpolicyMap[i].gatewayIP = nodes[0].ip
		ipV6ExpectedpolicyMap[i].egressIP = egressIP1
		ipV6ExpectedpolicyMap[i].gatewayIP = nodes[0].ip
	}
	assertEgressRules4(t, policyMap4, assignEndpoints(eps, nodes[:1], true))
	assertEgressRules6(t, policyMap6, assignEndpoints(eps, nodes[:1], false))
}

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatal(err)
	}
}

func createTestInterface(tb testing.TB, sysctl sysctl.Sysctl, iface string, addrs []string) {
	tb.Helper()

	la := netlink.NewLinkAttrs()
	la.Name = iface
	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		tb.Fatal(err)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		if err := netlink.LinkDel(link); err != nil {
			tb.Error(err)
		}
	})

	if err := netlink.LinkSetUp(link); err != nil {
		tb.Fatal(err)
	}

	for _, addr := range addrs {
		a, _ := netlink.ParseAddr(addr)
		if err := netlink.AddrAdd(link, a); err != nil {
			tb.Fatal(err)
		}
	}

	ensureRPFilterIsEnabled(tb, sysctl, iface)
}

func ensureRPFilterIsEnabled(tb testing.TB, sysctl sysctl.Sysctl, iface string) {
	rpFilterSetting := []string{"net", "ipv4", "conf", iface, "rp_filter"}

	for range 10 {
		if err := sysctl.Enable(rpFilterSetting); err != nil {
			tb.Fatal(err)
		}

		time.Sleep(100 * time.Millisecond)

		if val, err := sysctl.Read(rpFilterSetting); err == nil {
			if val == "1" {
				return
			}
		}
	}

	tb.Fatal("failed to enable rp_filter")
}

func waitForReconciliationRun(tb testing.TB, egressGatewayManager *Manager, currentRun uint64) uint64 {
	for range 100 {
		count := egressGatewayManager.reconciliationEventsCount.Load()
		if count > currentRun {
			return count
		}

		// TODO: investigate why increasing the timeout was necessary to add IPv6 tests.
		time.Sleep(30 * time.Millisecond)
	}

	tb.Fatal("Reconciliation is taking too long to run")
	return 0
}

func newCiliumNode(name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	return nodeTypes.Node{
		Name:   name,
		Labels: nodeLabels,
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   netip.MustParseAddr(nodeIP).AsSlice(),
			},
		},
	}
}

// Mock the creation of endpoint and its corresponding identity, returns endpoint and ID.
func newEndpointAndIdentity(name, ipv4, ipv6 string, epLabels map[string]string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	id, _, _ := identityAllocator.AllocateIdentity(context.Background(), labels.Map2Labels(epLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)

	return k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name: name,
			UID:  types.UID(uuid.New().String()),
		},
		Identity: &cilium_api_v2.EndpointIdentity{
			ID: int64(id.ID),
		},
		Networking: &cilium_api_v2.EndpointNetworking{
			Addressing: cilium_api_v2.AddressPairList{
				&cilium_api_v2.AddressPair{
					IPV4: ipv4,
					IPV6: ipv6,
				},
			},
		},
	}, id
}

// Mock the creation of endpoint and its corresponding identity, returns endpoint and ID.
func newEndpointAndIdentityWithNodeIP(name, ipv4, ipv6, nodeIP string, epLabels map[string]string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	id, _, _ := identityAllocator.AllocateIdentity(context.Background(), labels.Map2Labels(epLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)

	return k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name: name,
			UID:  types.UID(uuid.New().String()),
		},
		Identity: &cilium_api_v2.EndpointIdentity{
			ID: int64(id.ID),
		},
		Networking: &cilium_api_v2.EndpointNetworking{
			Addressing: cilium_api_v2.AddressPairList{
				&cilium_api_v2.AddressPair{
					IPV4: ipv4,
					IPV6: ipv6,
				},
			},
			NodeIP: nodeIP,
		},
	}, id
}

// Mock the update of endpoint and its corresponding identity, with new labels. Returns new ID.
func updateEndpointAndIdentity(endpoint *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabels map[string]string) *identity.Identity {
	ctx := context.Background()

	identityAllocator.Release(ctx, oldID, true)
	newID, _, _ := identityAllocator.AllocateIdentity(ctx, labels.Map2Labels(newEpLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)
	endpoint.Identity.ID = int64(newID.ID)
	return newID
}

func parseEgressRule(sourceIP, destCIDR, egressIP, gatewayIP string) parsedEgressRule {
	sip := netip.MustParseAddr(sourceIP)
	dc := netip.MustParsePrefix(destCIDR)
	eip := netip.MustParseAddr(egressIP)
	gip := netip.MustParseAddr(gatewayIP)

	return parsedEgressRule{
		sourceIP:  sip,
		destCIDR:  dc,
		egressIP:  eip,
		gatewayIP: gip,
	}
}

func assertEgressRules4(t *testing.T, policyMap *egressmap.PolicyMap4, rules []egressRule) {
	t.Helper()

	err := tryAssertEgressRules4(policyMap, rules)
	require.NoError(t, err)
}

func tryAssertEgressRules4(policyMap *egressmap.PolicyMap4, rules []egressRule) error {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP))
	}

	for _, r := range parsedRules {
		policyVal, err := policyMap.Lookup(r.sourceIP, r.destCIDR)
		if err != nil {
			return fmt.Errorf("cannot lookup policy entry: %w", err)
		}

		if policyVal.GetEgressAddr() != r.egressIP {
			return fmt.Errorf("mismatched egress IP. Expected: %s, Got: %s", r.String(), policyVal.String())
		}

		if policyVal.GetGatewayAddr() != r.gatewayIP {
			return fmt.Errorf("mismatched gateway IP. Expected: %s, Got: %s", r.String(), policyVal.String())
		}
	}

	untrackedRule := false
	policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressPolicyVal4) {
			for _, r := range parsedRules {
				if key.Match(r.sourceIP, r.destCIDR) && val.Match(r.egressIP, r.gatewayIP) {
					return
				}
			}

			untrackedRule = true
		})

	if untrackedRule {
		return fmt.Errorf("Untracked egress policy")
	}

	return nil
}
func assertEgressRules6(t *testing.T, policyMap *egressmap.PolicyMap6, rules []egressRule) {
	t.Helper()

	err := tryAssertEgressRules6(policyMap, rules)
	require.NoError(t, err)
}

func tryAssertEgressRules6(policyMap *egressmap.PolicyMap6, rules []egressRule) error {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP))
	}

	for _, r := range parsedRules {
		policyVal, err := policyMap.Lookup(r.sourceIP, r.destCIDR)
		if err != nil {
			return fmt.Errorf("cannot lookup policy entry: %w", err)
		}

		if policyVal.GetEgressAddr() != r.egressIP {
			return fmt.Errorf("mismatched egress IP. Expected: %s, Got: %s", r.String(), policyVal.String())
		}

		if policyVal.GetGatewayAddr() != r.gatewayIP {
			return fmt.Errorf("mismatched gateway IP. Expected: %s, Got: %s", r.String(), policyVal.String())
		}
	}

	untrackedRule := false
	policyMap.IterateWithCallback(
		func(key *egressmap.EgressPolicyKey6, val *egressmap.EgressPolicyVal6) {
			for _, r := range parsedRules {
				if key.Match(r.sourceIP, r.destCIDR) && val.Match(r.egressIP, r.gatewayIP) {
					return
				}
			}

			untrackedRule = true
		})

	if untrackedRule {
		return fmt.Errorf("Untracked egress policy")
	}

	return nil
}

func assertRPFilter(t *testing.T, sysctl sysctl.Sysctl, rpFilterSettings []rpFilterSetting) {
	t.Helper()

	err := tryAssertRPFilterSettings(sysctl, rpFilterSettings)
	require.NoError(t, err)
}

func tryAssertRPFilterSettings(sysctl sysctl.Sysctl, rpFilterSettings []rpFilterSetting) error {
	for _, setting := range rpFilterSettings {
		if val, err := sysctl.Read([]string{"net", "ipv4", "conf", setting.iFaceName, "rp_filter"}); err != nil {
			return fmt.Errorf("failed to read rp_filter")
		} else if val != setting.rpFilterSetting {
			return fmt.Errorf("mismatched rp_filter iface: %s rp_filter: %s", setting.iFaceName, val)
		}
	}

	return nil
}
