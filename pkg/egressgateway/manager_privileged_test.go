// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"fmt"
	"net/netip"
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

	node1IP = "192.168.1.1"
	node2IP = "192.168.1.2"

	ep1IP = "10.0.0.1"
	ep2IP = "10.0.0.2"
	ep3IP = "10.0.0.3"

	destCIDR        = "1.1.1.0/24"
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
)

var (
	ep1Labels = map[string]string{"test-key": "test-value-1"}
	ep2Labels = map[string]string{"test-key": "test-value-2"}

	identityAllocator = testidentity.NewMockIdentityAllocator(nil)

	nodeGroupNotFoundLabels = map[string]string{"label1": "notfound"}
	nodeGroup1Labels        = map[string]string{"label1": "1"}
	nodeGroup2Labels        = map[string]string{"label2": "2"}
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

	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	require.NoError(t, err)

	nodeTypes.SetName(node1)

	k := &EgressGatewayTestSuite{}
	k.policies = make(fakeResource[*Policy])
	k.nodes = make(fakeResource[*cilium_api_v2.CiliumNode])
	k.endpoints = make(fakeResource[*k8sTypes.CiliumEndpoint])
	k.sysctl = sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	lc := hivetest.Lifecycle(t)
	policyMap := egressmap.CreatePrivatePolicyMap(lc, egressmap.DefaultPolicyConfig)

	k.manager, err = newEgressGatewayManager(Params{
		Lifecycle:         lc,
		Config:            Config{1 * time.Millisecond},
		DaemonConfig:      &option.DaemonConfig{},
		IdentityAllocator: identityAllocator,
		PolicyMap:         policyMap,
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
		name:            "",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	cegp, _ := newCEGP(&policy)
	_, err := ParseCEGP(cegp)
	require.Error(t, err)

	// catch nil DestinationCIDR field
	policy = policyParams{
		name:  "policy-1",
		iface: testInterface1,
	}

	cegp, _ = newCEGP(&policy)
	cegp.Spec.DestinationCIDRs = nil
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// must specify at least one DestinationCIDR
	policy = policyParams{
		name:  "policy-1",
		iface: testInterface1,
	}

	cegp, _ = newCEGP(&policy)
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// catch nil EgressGateway field
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	cegp, _ = newCEGP(&policy)
	cegp.Spec.EgressGateway = nil
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// must specify some sort of endpoint selector
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	cegp, _ = newCEGP(&policy)
	cegp.Spec.Selectors[0].NamespaceSelector = nil
	cegp.Spec.Selectors[0].PodSelector = nil
	_, err = ParseCEGP(cegp)
	require.Error(t, err)

	// can't specify both egress iface and IP
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
		egressIP:        egressIP1,
	}

	cegp, _ = newCEGP(&policy)
	_, err = ParseCEGP(cegp)
	require.Error(t, err)
}

func TestEgressGatewayManager(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)
	createTestInterface(t, k.sysctl, testInterface1, egressCIDR1)
	createTestInterface(t, k.sysctl, testInterface2, egressCIDR2)

	policyMap := k.manager.policyMap
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
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertRPFilter(t, k.sysctl, []rpFilterSetting{
		{iFaceName: testInterface1, rpFilterSetting: "2"},
		{iFaceName: testInterface2, rpFilterSetting: "1"},
	})
	assertEgressRules(t, policyMap, []egressRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, id1 := newEndpointAndIdentity("ep-1", ep1IP, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Update the endpoint labels in order for it to not be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{})

	// Restore the old endpoint lables in order for it to be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Changing the DestCIDR to 0.0.0.0 results in a conflict with
	// the existing IP rules. Test that the manager is able to
	// resolve this conflict.
	policy1.destinationCIDR = allZeroDestCIDR
	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, allZeroDestCIDR, egressIP1, node1IP},
	})

	// Restore old DestCIDR
	policy1.destinationCIDR = destCIDR
	addPolicy(t, k.policies, &policy1)

	// Create a new policy
	addPolicy(t, k.policies, &policyParams{
		name:            "policy-2",
		endpointLabels:  ep2Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup2Labels,
		iface:           testInterface1,
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Add a new endpoint and ID which matches policy-2
	ep2, _ := newEndpointAndIdentity("ep-2", ep2IP, ep2Labels)
	addEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Test excluded CIDRs by adding one to policy-1
	addPolicy(t, k.policies, &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		excludedCIDRs:   []string{excludedCIDR1},
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Add a second excluded CIDR to policy-1
	addPolicy(t, k.policies, &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		excludedCIDRs:   []string{excludedCIDR1, excludedCIDR2},
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Remove the first excluded CIDR from policy-1
	addPolicy(t, k.policies, &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		excludedCIDRs:   []string{excludedCIDR2},
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Remove the second excluded CIDR
	addPolicy(t, k.policies, &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Test matching no gateway
	addPolicy(t, k.policies, &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroupNotFoundLabels,
		iface:           testInterface1,
	})
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, zeroIP4, gatewayNotFoundValue},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Update the endpoint labels in order for it to not be a match
	_ = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	addEndpoint(t, k.endpoints, &ep1)
	waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
}

func TestEndpointDataStore(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	createTestInterface(t, k.sysctl, testInterface1, egressCIDR1)

	policyMap := k.manager.policyMap
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
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, _ := newEndpointAndIdentity("ep-1", ep1IP, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Simulate statefulset pod migrations to a different node.

	// Produce a new endpoint ep2 similar to ep1 - with the same name & labels, but with a different IP address.
	// The ep1 will be deleted.
	ep2, _ := newEndpointAndIdentity(ep1.Name, ep2IP, ep1Labels)

	// Test event order: add new -> delete old
	addEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	deleteEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep2IP, destCIDR, egressIP1, node1IP},
	})

	// Produce a new endpoint ep3 similar to ep2 (and ep1) - with the same name & labels, but with a different IP address.
	ep3, _ := newEndpointAndIdentity(ep1.Name, ep3IP, ep1Labels)

	// Test event order: delete old -> update new
	deleteEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)
	addEndpoint(t, k.endpoints, &ep3)
	waitForReconciliationRun(t, egressGatewayManager, reconciliationEventsCount)

	assertEgressRules(t, policyMap, []egressRule{
		{ep3IP, destCIDR, egressIP1, node1IP},
	})
}

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatal(err)
	}
}

func createTestInterface(tb testing.TB, sysctl sysctl.Sysctl, iface string, addr string) {
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

	a, _ := netlink.ParseAddr(addr)
	if err := netlink.AddrAdd(link, a); err != nil {
		tb.Fatal(err)
	}

	ensureRPFilterIsEnabled(tb, sysctl, iface)
}

func ensureRPFilterIsEnabled(tb testing.TB, sysctl sysctl.Sysctl, iface string) {
	rpFilterSetting := fmt.Sprintf("net.ipv4.conf.%s.rp_filter", iface)

	for i := 0; i < 10; i++ {
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
	for i := 0; i < 100; i++ {
		count := egressGatewayManager.reconciliationEventsCount.Load()
		if count > currentRun {
			return count
		}

		time.Sleep(10 * time.Millisecond)
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
func newEndpointAndIdentity(name, ip string, epLabels map[string]string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
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
					IPV4: ip,
				},
			},
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

func assertEgressRules(t *testing.T, policyMap egressmap.PolicyMap, rules []egressRule) {
	t.Helper()

	err := tryAssertEgressRules(policyMap, rules)
	require.NoError(t, err)
}

func tryAssertEgressRules(policyMap egressmap.PolicyMap, rules []egressRule) error {
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
			return fmt.Errorf("mismatched egress IP")
		}

		if policyVal.GetGatewayAddr() != r.gatewayIP {
			return fmt.Errorf("mismatched gateway IP")
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

func assertRPFilter(t *testing.T, sysctl sysctl.Sysctl, rpFilterSettings []rpFilterSetting) {
	t.Helper()

	err := tryAssertRPFilterSettings(sysctl, rpFilterSettings)
	require.NoError(t, err)
}

func tryAssertRPFilterSettings(sysctl sysctl.Sysctl, rpFilterSettings []rpFilterSetting) error {
	for _, setting := range rpFilterSettings {
		if val, err := sysctl.Read(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", setting.iFaceName)); err != nil {
			return fmt.Errorf("failed to read rp_filter")
		} else if val != setting.rpFilterSetting {
			return fmt.Errorf("mismatched rp_filter iface: %s rp_filter: %s", setting.iFaceName, val)
		}
	}

	return nil
}
