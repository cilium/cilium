// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vteppolicy

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/maps/vtep_policy"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	testInterface1 = "cilium_egw1"
	testInterface2 = "cilium_egw2"

	vtepIP1 = "1.2.3.4"
	mac1    = "00:11:22:33:44:55"

	vtepIP2 = "1.2.3.5"
	mac2    = "00:11:22:33:44:56"

	node1 = "k8s1"
	node2 = "k8s2"

	node1IP = "192.168.1.1"
	node2IP = "192.168.1.2"

	ep1IP = "10.0.0.1"
	ep2IP = "10.0.0.2"
	ep3IP = "10.0.0.3"

	destCIDR = "1.1.1.0/24"

	egressCIDR1 = "192.168.101.1/24"
	egressCIDR2 = "192.168.102.1/24"
)

var (
	ep1Labels = map[string]string{"test-key": "test-value-1"}
	ep2Labels = map[string]string{"test-key": "test-value-2"}

	identityAllocator = testidentity.NewMockIdentityAllocator(nil)

	nodeGroup1Labels = map[string]string{"label1": "1"}
	nodeGroup2Labels = map[string]string{"label2": "2"}
)

type vtepRule struct {
	sourceIP string
	destCIDR string
	vtepIP   string
	vtepMAC  string
}

type parsedVtepRule struct {
	sourceIP netip.Addr
	destCIDR netip.Prefix
	vtepIP   netip.Addr
	vtepMAC  mac.MAC
}

type VtepPolicyTestSuite struct {
	manager   *Manager
	policies  fakeResource[*Policy]
	nodes     fakeResource[*cilium_api_v2.CiliumNode]
	endpoints fakeResource[*k8sTypes.CiliumEndpoint]
}

func setupVtepPolicyTestSuite(t *testing.T) *VtepPolicyTestSuite {
	testutils.PrivilegedTest(t)

	logger := hivetest.Logger(t)

	bpf.CheckOrMountFS(logger, "")

	if err := vtep.VtepMap(nil).Create(); err != nil {
		println(err)
	}

	err := rlimit.RemoveMemlock()
	require.NoError(t, err)

	nodeTypes.SetName(node1)

	k := &VtepPolicyTestSuite{}
	k.policies = make(fakeResource[*Policy])
	k.nodes = make(fakeResource[*cilium_api_v2.CiliumNode])
	k.endpoints = make(fakeResource[*k8sTypes.CiliumEndpoint])

	lc := hivetest.Lifecycle(t)
	policyMap := vtep_policy.CreatePrivatePolicyMap(lc, nil)

	k.manager, err = newVtepPolicyManager(Params{
		Logger:            logger,
		Lifecycle:         lc,
		Config:            Config{1 * time.Millisecond},
		DaemonConfig:      &option.DaemonConfig{},
		IdentityAllocator: identityAllocator,
		Policies:          k.policies,
		Endpoints:         k.endpoints,
		PolicyMap:         policyMap,
	})
	require.NoError(t, err)
	require.NotNil(t, k.manager)

	return k
}

func TestPrivilegedVtepPolicyCVPParser(t *testing.T) {
	setupVtepPolicyTestSuite(t)
	// must specify name
	policy := policyParams{
		name:             "",
		destinationCIDRs: []string{destCIDR},
	}

	cvp, _ := newCVP(&policy)
	_, err := ParseCVP(cvp)
	require.Error(t, err)

	// catch nil DestinationCIDR field
	policy = policyParams{
		name: "policy-1",
	}

	cvp, _ = newCVP(&policy)
	cvp.Spec.DestinationCIDRs = nil
	_, err = ParseCVP(cvp)
	require.Error(t, err)

	// must specify at least one DestinationCIDR
	policy = policyParams{
		name: "policy-1",
	}

	cvp, _ = newCVP(&policy)
	_, err = ParseCVP(cvp)
	require.Error(t, err)

	// catch nil VtepPolicy field
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
	}

	// must specify some sort of endpoint selector
	policy = policyParams{
		name:             "policy-1",
		destinationCIDRs: []string{destCIDR},
	}

	cvp, _ = newCVP(&policy)
	cvp.Spec.Selectors[0].NamespaceSelector = nil
	cvp.Spec.Selectors[0].PodSelector = nil
	_, err = ParseCVP(cvp)
	require.Error(t, err)
}

func TestPrivilegedVtepPolicyManager(t *testing.T) {
	k := setupVtepPolicyTestSuite(t)
	createTestInterface(t, testInterface1, []string{egressCIDR1})
	createTestInterface(t, testInterface2, []string{egressCIDR2})

	vtepPolicyManager := k.manager
	reconciliationEventsCount := vtepPolicyManager.reconciliationEventsCount.Load()
	policyMap := k.manager.policyMap

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node1.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	node2 := newCiliumNode(node2, node2IP, nodeGroup2Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node2.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	// Create a new policy
	policy1 := policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		podLabels:        nodeGroup1Labels,
		vtepIP:           vtepIP1,
		mac:              mac1,
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, id1 := newEndpointAndIdentity("ep-1", ep1IP, "", ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep1IP, destCIDR, vtepIP1, mac1},
	})

	// Update the endpoint labels in order for it to not be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{})

	// Restore the old endpoint lables in order for it to be a match
	id1 = updateEndpointAndIdentity(&ep1, id1, ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep1IP, destCIDR, vtepIP1, mac1},
	})

	// Create a new policy
	addPolicy(t, k.policies, &policyParams{
		name:             "policy-2",
		endpointLabels:   ep2Labels,
		destinationCIDRs: []string{destCIDR},
		podLabels:        nodeGroup2Labels,
		vtepIP:           vtepIP2,
		mac:              mac2,
	})
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep1IP, destCIDR, vtepIP1, mac1},
	})

	// Add a new endpoint and ID which matches policy-2
	ep2, _ := newEndpointAndIdentity("ep-2", ep2IP, "", ep2Labels)
	addEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep1IP, destCIDR, vtepIP1, mac1},
		{ep2IP, destCIDR, vtepIP2, mac2},
	})

	// Update the endpoint labels in order for it to not be a match
	_ = updateEndpointAndIdentity(&ep1, id1, map[string]string{})
	addEndpoint(t, k.endpoints, &ep1)
	waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep2IP, destCIDR, vtepIP2, mac2},
	})
}

func TestPrivilegedEndpointDataStore(t *testing.T) {
	k := setupVtepPolicyTestSuite(t)

	createTestInterface(t, testInterface1, []string{egressCIDR1})

	vtepPolicyManager := k.manager
	policyMap := k.manager.policyMap

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	reconciliationEventsCount := vtepPolicyManager.reconciliationEventsCount.Load()

	node1 := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	k.nodes.process(t, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node1.ToCiliumNode(),
	})
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	// Create a new policy
	policy1 := policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		podLabels:        nodeGroup1Labels,
		vtepIP:           vtepIP1,
		mac:              mac1,
	}

	addPolicy(t, k.policies, &policy1)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, _ := newEndpointAndIdentity("ep-1", ep1IP, "", ep1Labels)
	addEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep1IP, destCIDR, vtepIP1, mac1},
	})

	// Simulate statefulset pod migrations to a different node.

	// Produce a new endpoint ep2 similar to ep1 - with the same name & labels, but with a different IP address.
	// The ep1 will be deleted.
	ep2, _ := newEndpointAndIdentity(ep1.Name, ep2IP, "", ep1Labels)

	// Test event order: add new -> delete old
	addEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)
	deleteEndpoint(t, k.endpoints, &ep1)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep2IP, destCIDR, vtepIP1, mac1},
	})

	// Produce a new endpoint ep3 similar to ep2 (and ep1) - with the same name & labels, but with a different IP address.
	ep3, _ := newEndpointAndIdentity(ep1.Name, ep3IP, "", ep1Labels)

	// Test event order: delete old -> update new
	deleteEndpoint(t, k.endpoints, &ep2)
	reconciliationEventsCount = waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)
	addEndpoint(t, k.endpoints, &ep3)
	waitForReconciliationRun(t, vtepPolicyManager, reconciliationEventsCount)

	assertVtepRules(t, policyMap, []vtepRule{
		{ep3IP, destCIDR, vtepIP1, mac1},
	})
}

func TestCell(t *testing.T) {
	err := hive.New(Cell).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatal(err)
	}
}

func createTestInterface(tb testing.TB, iface string, addrs []string) {
	tb.Helper()

	la := netlink.NewLinkAttrs()
	la.Name = iface
	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		tb.Fatal(err)
	}

	link, err := safenetlink.LinkByName(iface)
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
}

func waitForReconciliationRun(tb testing.TB, vtepPolicyManager *Manager, currentRun uint64) uint64 {
	for range 100 {
		count := vtepPolicyManager.reconciliationEventsCount.Load()
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

// Mock the update of endpoint and its corresponding identity, with new labels. Returns new ID.
func updateEndpointAndIdentity(endpoint *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabels map[string]string) *identity.Identity {
	ctx := context.Background()

	identityAllocator.Release(ctx, oldID, true)
	newID, _, _ := identityAllocator.AllocateIdentity(ctx, labels.Map2Labels(newEpLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)
	endpoint.Identity.ID = int64(newID.ID)
	return newID
}

func parseVtepRule(sourceIP, destCIDR, vtepIP, vtepMAC string) parsedVtepRule {
	sip := netip.MustParseAddr(sourceIP)
	dc := netip.MustParsePrefix(destCIDR)
	vip := netip.MustParseAddr(vtepIP)
	vmac, _ := mac.ParseMAC(vtepMAC)

	return parsedVtepRule{
		sourceIP: sip,
		destCIDR: dc,
		vtepIP:   vip,
		vtepMAC:  vmac,
	}
}

func assertVtepRules(t *testing.T, policyMap *vtep_policy.VtepPolicyMap, rules []vtepRule) {
	t.Helper()

	err := tryAssertVtepRules(policyMap, rules)
	require.NoError(t, err)
}

func tryAssertVtepRules(policyMap *vtep_policy.VtepPolicyMap, rules []vtepRule) error {
	parsedRules := []parsedVtepRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseVtepRule(r.sourceIP, r.destCIDR, r.vtepIP, r.vtepMAC))
	}

	for _, r := range parsedRules {
		key := vtep_policy.NewKey(r.sourceIP, r.destCIDR)

		val, err := policyMap.Lookup(&key)
		if err != nil {
			return fmt.Errorf("cannot lookup policy entry: %w", err)
		}

		if val == nil {
			return fmt.Errorf("lookup successful but value is nil")
		}

		if !val.Match(r.vtepIP, r.vtepMAC) {
			return fmt.Errorf("mismatched val, wanted: %s %s, got: %s", r.vtepIP, r.vtepMAC, val)
		}
	}

	untrackedRule := false
	policyMap.IterateWithCallback(
		func(key *vtep_policy.VtepPolicyKey, val *vtep_policy.VtepPolicyVal) {
			for _, r := range parsedRules {
				if key.Match(r.sourceIP, r.destCIDR) && val.Match(r.vtepIP, r.vtepMAC) {
					return
				}
			}

			untrackedRule = true
		})

	if untrackedRule {
		return fmt.Errorf("Untracked vtep policy")
	}

	return nil
}
