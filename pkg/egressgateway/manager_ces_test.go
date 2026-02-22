// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

// newCESEndpoint creates a CiliumEndpoint that looks like what
// ConvertCoreCiliumEndpointToTypesCiliumEndpoint produces: it has Name and
// Namespace but NO UID (because CoreCiliumEndpoint doesn't carry one).
func newCESEndpoint(name, namespace, ipv4, ipv6, nodeIP string, identityID int64) *k8sTypes.CiliumEndpoint {
	ep := &k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			// UID intentionally left empty — CES endpoints have no UID
		},
		Identity: &cilium_api_v2.EndpointIdentity{
			ID: identityID,
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
	}
	return ep
}

// TestGetEndpointMetadata_CESEndpointRejected verifies that getEndpointMetadata
// accepts CES-sourced endpoints (empty UID) by falling back to namespace/name
// as the endpoint ID. This was the root cause of issue #24833.
func TestGetEndpointMetadata_CESEndpointRejected(t *testing.T) {
	ep := newCESEndpoint("pod-1", "default", ep1IP, "", node1IP, 1000)

	identityLabels := labels.Map2Labels(ep1Labels, labels.LabelSourceK8s)

	epData, err := getEndpointMetadata(ep, identityLabels)

	// After the fix: should succeed with namespace/name as ID
	require.NoError(t, err, "getEndpointMetadata should accept CES endpoints with empty UID")
	require.NotNil(t, epData)
	require.Equal(t, endpointID("default/pod-1"), epData.id,
		"CES endpoint ID should be namespace/name")
}

// TestGetEndpointMetadata_CESEndpointNamespaceNameKey verifies that for
// CES-sourced endpoints (empty UID), the endpoint ID is correctly derived
// from namespace + "/" + name.
func TestGetEndpointMetadata_CESEndpointNamespaceNameKey(t *testing.T) {
	ep := newCESEndpoint("my-pod", "production", "10.0.1.5", "", node1IP, 2000)

	identityLabels := labels.Map2Labels(ep1Labels, labels.LabelSourceK8s)

	epData, err := getEndpointMetadata(ep, identityLabels)
	require.NoError(t, err)
	require.NotNil(t, epData)

	require.Equal(t, endpointID("production/my-pod"), epData.id,
		"endpoint ID should use namespace/name format for CES endpoints")
	require.Equal(t, "10.0.1.5", epData.ips[0].String())
}

// TestGetEndpointMetadata_CEPEndpointStillUsesUID verifies that the existing
// behavior for CEP-sourced endpoints (with a real UID) is preserved — the
// endpoint ID should still be the UID.
func TestGetEndpointMetadata_CEPEndpointStillUsesUID(t *testing.T) {
	ep := &k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
			UID:       "abcd-1234-efgh",
		},
		Networking: &cilium_api_v2.EndpointNetworking{
			Addressing: cilium_api_v2.AddressPairList{
				&cilium_api_v2.AddressPair{IPV4: ep1IP},
			},
		},
	}

	identityLabels := labels.Map2Labels(ep1Labels, labels.LabelSourceK8s)

	epData, err := getEndpointMetadata(ep, identityLabels)
	require.NoError(t, err)
	require.NotNil(t, epData)
	require.Equal(t, endpointID("abcd-1234-efgh"), epData.id,
		"CEP endpoint ID should still use UID when available")
}

// TestGetEndpointMetadata_CESEndpointNoNameOrUID verifies that endpoints with
// neither UID nor Name are rejected (defensive case).
func TestGetEndpointMetadata_CESEndpointNoNameOrUID(t *testing.T) {
	ep := &k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			// No UID, no Name
		},
		Networking: &cilium_api_v2.EndpointNetworking{
			Addressing: cilium_api_v2.AddressPairList{
				&cilium_api_v2.AddressPair{IPV4: ep1IP},
			},
		},
	}

	identityLabels := labels.Map2Labels(ep1Labels, labels.LabelSourceK8s)

	_, err := getEndpointMetadata(ep, identityLabels)
	require.Error(t, err, "should reject endpoint with neither UID nor Name")
}

// TestPrivilegedCESEndpoint_AddAndDelete is an integration test that verifies
// CES-shaped endpoints (no UID) can be added to and deleted from the egress
// gateway manager's epDataStore, and that reconciliation creates correct BPF
// map entries. This validates the fix for issue #24833.
func TestPrivilegedCESEndpoint_AddAndDelete(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	egressGatewayManager := k.manager
	policyMap4 := egressGatewayManager.policyMap4

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1})

	// Sync all resources to allow reconciliation
	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	// Add a node
	node1Obj := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	addNodeAndReconcile(t, k, egressGatewayManager, &node1Obj)

	// Add a policy that selects ep1Labels
	policy1 := &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	}
	addPolicyAndReconcile(t, egressGatewayManager, k.policies, policy1)

	// Allocate an identity for the endpoint labels
	id1, _, _ := identityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep1Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)

	// Create a CES-shaped endpoint (no UID, has Name+Namespace)
	cesEp := newCESEndpoint("ep-1", "default", ep1IP, "", node1IP, int64(id1.ID))

	// --- Test: addEndpoint should accept a CES endpoint ---
	err := egressGatewayManager.addEndpoint(cesEp)
	require.NoError(t, err, "addEndpoint should not error on CES endpoint")

	expectedID := endpointID("default/ep-1")

	egressGatewayManager.Lock()
	_, found := egressGatewayManager.epDataStore[expectedID]
	egressGatewayManager.Unlock()
	require.True(t, found, "CES endpoint should be present in epDataStore with key %q", expectedID)

	// Trigger reconciliation and verify BPF map entry
	egressGatewayManager.Lock()
	egressGatewayManager.reconcileLocked()
	egressGatewayManager.Unlock()

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, 0},
	})

	// --- Test: deleteEndpoint should remove the CES endpoint ---
	egressGatewayManager.deleteEndpoint(cesEp)

	egressGatewayManager.Lock()
	_, found = egressGatewayManager.epDataStore[expectedID]
	egressGatewayManager.Unlock()
	require.False(t, found, "CES endpoint should be removed from epDataStore after delete")

	// Trigger reconciliation and verify BPF map is empty
	egressGatewayManager.Lock()
	egressGatewayManager.reconcileLocked()
	egressGatewayManager.Unlock()

	assertEgressRules4(t, policyMap4, []egressRule{})
}

// TestPrivilegedCESEndpoint_MultipleEndpointsSameNamespace verifies that
// multiple CES-sourced endpoints from the same namespace can coexist in the
// manager's epDataStore and independently match different policies.
func TestPrivilegedCESEndpoint_MultipleEndpointsSameNamespace(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	egressGatewayManager := k.manager
	policyMap4 := egressGatewayManager.policyMap4

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1})

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpoints.sync(t)

	node1Obj := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	addNodeAndReconcile(t, k, egressGatewayManager, &node1Obj)

	// Policy matching ep1Labels
	addPolicyAndReconcile(t, egressGatewayManager, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})

	// Allocate identities
	id1, _, _ := identityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep1Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)
	id2, _, _ := identityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep2Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)

	// Two CES endpoints, same namespace, different names and labels
	cesEp1 := newCESEndpoint("ep-1", "default", ep1IP, "", node1IP, int64(id1.ID))
	cesEp2 := newCESEndpoint("ep-2", "default", ep2IP, "", node1IP, int64(id2.ID))

	// Add both
	require.NoError(t, egressGatewayManager.addEndpoint(cesEp1))
	require.NoError(t, egressGatewayManager.addEndpoint(cesEp2))

	egressGatewayManager.Lock()
	_, found1 := egressGatewayManager.epDataStore[endpointID("default/ep-1")]
	_, found2 := egressGatewayManager.epDataStore[endpointID("default/ep-2")]
	egressGatewayManager.Unlock()

	require.True(t, found1, "ep-1 should be in epDataStore")
	require.True(t, found2, "ep-2 should be in epDataStore")

	// Reconcile — only ep-1 matches policy-1
	egressGatewayManager.Lock()
	egressGatewayManager.reconcileLocked()
	egressGatewayManager.Unlock()

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, 0},
	})

	// Delete ep-1, verify BPF map is cleaned up
	egressGatewayManager.deleteEndpoint(cesEp1)

	egressGatewayManager.Lock()
	egressGatewayManager.reconcileLocked()
	egressGatewayManager.Unlock()

	assertEgressRules4(t, policyMap4, []egressRule{})
}

// ---------------------------------------------------------------------------
// CES Event Flow Integration Tests
//
// These tests exercise the full CES event path: CiliumEndpointSlice events
// are fed through handleCESEvent -> onUpsertCES/onDeleteCES -> addEndpoint,
// exercising the per-slice diff tracking in cesTrackedEndpoints.
// ---------------------------------------------------------------------------

// EgressGatewayCESTestSuite is a test suite for CES-mode egress gateway tests.
// It mirrors EgressGatewayTestSuite but uses CES events instead of CEP events.
type EgressGatewayCESTestSuite struct {
	manager        *Manager
	policies       fakeResource[*Policy]
	nodes          fakeResource[*cilium_api_v2.CiliumNode]
	endpointSlices fakeResource[*cilium_api_v2alpha1.CiliumEndpointSlice]
	sysctl         sysctl.Sysctl
}

func setupEgressGatewayCESTestSuite(t *testing.T) *EgressGatewayCESTestSuite {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	bpf.CheckOrMountFS(logger, "")

	err := rlimit.RemoveMemlock()
	require.NoError(t, err)

	nodeTypes.SetName(node1)

	k := &EgressGatewayCESTestSuite{}
	k.policies = make(fakeResource[*Policy])
	k.nodes = make(fakeResource[*cilium_api_v2.CiliumNode])
	k.endpointSlices = make(fakeResource[*cilium_api_v2alpha1.CiliumEndpointSlice])
	k.sysctl = sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")

	lc := hivetest.Lifecycle(t)
	policyMap4 := egressmap.CreatePrivatePolicyMap4(lc, nil, egressmap.DefaultPolicyConfig)
	policyMap6 := egressmap.CreatePrivatePolicyMap6(lc, nil, egressmap.DefaultPolicyConfig)

	// Note: Endpoints is nil (no CEP resource), EndpointSlices is set.
	// This simulates CES-enabled mode.
	k.manager, err = newEgressGatewayManager(Params{
		Logger:            logger,
		Lifecycle:         lc,
		Config:            Config{1 * time.Millisecond},
		DaemonConfig:      &option.DaemonConfig{},
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		PolicyMap4:        policyMap4,
		PolicyMap6:        policyMap6,
		Policies:          k.policies,
		Nodes:             k.nodes,
		EndpointSlices:    k.endpointSlices,
		Sysctl:            k.sysctl,
	})
	require.NoError(t, err)
	require.NotNil(t, k.manager)

	return k
}

// cesAddNodeAndReconcile adds a CiliumNode and waits for reconciliation.
func cesAddNodeAndReconcile(tb testing.TB, k *EgressGatewayCESTestSuite, manager *Manager, node *nodeTypes.Node) {
	currentRun := manager.reconciliationEventsCount.Load()
	k.nodes.process(tb, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node.ToCiliumNode(),
	})
	waitForReconciliationRun(tb, manager, currentRun)
}

// upsertCESAndReconcile sends a CES upsert event and waits for reconciliation.
func upsertCESAndReconcile(tb testing.TB, manager *Manager, endpointSlices fakeResource[*cilium_api_v2alpha1.CiliumEndpointSlice], ces *cilium_api_v2alpha1.CiliumEndpointSlice) {
	currentRun := manager.reconciliationEventsCount.Load()
	endpointSlices.process(tb, resource.Event[*cilium_api_v2alpha1.CiliumEndpointSlice]{
		Kind:   resource.Upsert,
		Object: ces,
	})
	waitForReconciliationRun(tb, manager, currentRun)
}

// deleteCESAndReconcile sends a CES delete event and waits for reconciliation.
func deleteCESAndReconcile(tb testing.TB, manager *Manager, endpointSlices fakeResource[*cilium_api_v2alpha1.CiliumEndpointSlice], ces *cilium_api_v2alpha1.CiliumEndpointSlice) {
	currentRun := manager.reconciliationEventsCount.Load()
	endpointSlices.process(tb, resource.Event[*cilium_api_v2alpha1.CiliumEndpointSlice]{
		Kind:   resource.Delete,
		Object: ces,
	})
	waitForReconciliationRun(tb, manager, currentRun)
}

// newTestCES creates a CiliumEndpointSlice for testing.
func newTestCES(name, namespace string, endpoints ...cilium_api_v2alpha1.CoreCiliumEndpoint) *cilium_api_v2alpha1.CiliumEndpointSlice {
	return &cilium_api_v2alpha1.CiliumEndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Namespace: namespace,
		Endpoints: endpoints,
	}
}

// newTestCoreCEP creates a CoreCiliumEndpoint for testing.
func newTestCoreCEP(name string, identityID int64, ipv4, nodeIP string) cilium_api_v2alpha1.CoreCiliumEndpoint {
	return cilium_api_v2alpha1.CoreCiliumEndpoint{
		Name:       name,
		IdentityID: identityID,
		Networking: &cilium_api_v2.EndpointNetworking{
			Addressing: cilium_api_v2.AddressPairList{
				&cilium_api_v2.AddressPair{
					IPV4: ipv4,
				},
			},
			NodeIP: nodeIP,
		},
	}
}

// TestPrivilegedCESEventFlow_BasicUpsert verifies the full CES event path:
// a CiliumEndpointSlice upsert event creates BPF map entries for matching
// endpoints.
func TestPrivilegedCESEventFlow_BasicUpsert(t *testing.T) {
	k := setupEgressGatewayCESTestSuite(t)

	manager := k.manager
	policyMap4 := manager.policyMap4

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1})

	// Sync all resources
	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpointSlices.sync(t)

	// Add a node
	node1Obj := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	cesAddNodeAndReconcile(t, k, manager, &node1Obj)

	// Add a policy matching ep1Labels
	addPolicyAndReconcile(t, manager, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})

	// No endpoints yet — BPF map should be empty
	assertEgressRules4(t, policyMap4, []egressRule{})

	// Allocate an identity matching ep1Labels
	cesIdentityAllocator := manager.identityAllocator.(*testidentity.MockIdentityAllocator)
	id1, _, _ := cesIdentityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep1Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)

	// Create a CES with one endpoint matching the policy
	ces := newTestCES("slice-1", "default",
		newTestCoreCEP("ep-1", int64(id1.ID), ep1IP, node1IP),
	)
	upsertCESAndReconcile(t, manager, k.endpointSlices, ces)

	// BPF map should have the entry
	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, 0},
	})
}

// TestPrivilegedCESEventFlow_UpsertDiff verifies that when a CES is updated
// (endpoints added/removed), the manager correctly diffs and creates/deletes
// the appropriate BPF map entries.
func TestPrivilegedCESEventFlow_UpsertDiff(t *testing.T) {
	k := setupEgressGatewayCESTestSuite(t)

	manager := k.manager
	policyMap4 := manager.policyMap4

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1})

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpointSlices.sync(t)

	node1Obj := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	cesAddNodeAndReconcile(t, k, manager, &node1Obj)

	addPolicyAndReconcile(t, manager, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})

	cesIdentityAllocator := manager.identityAllocator.(*testidentity.MockIdentityAllocator)
	id1, _, _ := cesIdentityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep1Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)
	id2, _, _ := cesIdentityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep2Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)

	// Initial CES with ep-1 (matches policy) and ep-2 (doesn't match)
	ces := newTestCES("slice-1", "default",
		newTestCoreCEP("ep-1", int64(id1.ID), ep1IP, node1IP),
		newTestCoreCEP("ep-2", int64(id2.ID), ep2IP, node1IP),
	)
	upsertCESAndReconcile(t, manager, k.endpointSlices, ces)

	// Only ep-1 matches
	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, 0},
	})

	// Update CES: remove ep-1, keep ep-2 (which doesn't match policy)
	cesUpdated := newTestCES("slice-1", "default",
		newTestCoreCEP("ep-2", int64(id2.ID), ep2IP, node1IP),
	)
	upsertCESAndReconcile(t, manager, k.endpointSlices, cesUpdated)

	// ep-1 was removed from the slice → should be deleted from epDataStore
	// ep-2 doesn't match policy → BPF map should be empty
	assertEgressRules4(t, policyMap4, []egressRule{})

	// Verify ep-1 is actually gone from epDataStore
	manager.Lock()
	_, found := manager.epDataStore[endpointID("default/ep-1")]
	manager.Unlock()
	require.False(t, found, "ep-1 should be removed from epDataStore after CES diff")
}

// TestPrivilegedCESEventFlow_DeleteSlice verifies that deleting an entire
// CiliumEndpointSlice removes all its tracked endpoints from the manager.
func TestPrivilegedCESEventFlow_DeleteSlice(t *testing.T) {
	k := setupEgressGatewayCESTestSuite(t)

	manager := k.manager
	policyMap4 := manager.policyMap4

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1})

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpointSlices.sync(t)

	node1Obj := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	cesAddNodeAndReconcile(t, k, manager, &node1Obj)

	addPolicyAndReconcile(t, manager, k.policies, &policyParams{
		name:             "policy-1",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})

	cesIdentityAllocator := manager.identityAllocator.(*testidentity.MockIdentityAllocator)
	id1, _, _ := cesIdentityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep1Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)

	// Create and upsert a CES
	ces := newTestCES("slice-1", "default",
		newTestCoreCEP("ep-1", int64(id1.ID), ep1IP, node1IP),
	)
	upsertCESAndReconcile(t, manager, k.endpointSlices, ces)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP, 0},
	})

	// Delete the entire CES
	deleteCESAndReconcile(t, manager, k.endpointSlices, ces)

	// All endpoints from that slice should be removed
	assertEgressRules4(t, policyMap4, []egressRule{})

	manager.Lock()
	_, found := manager.epDataStore[endpointID("default/ep-1")]
	_, tracked := manager.cesTrackedEndpoints["slice-1"]
	manager.Unlock()
	require.False(t, found, "ep-1 should be removed from epDataStore after CES delete")
	require.False(t, tracked, "slice-1 should be removed from cesTrackedEndpoints after CES delete")
}

// TestPrivilegedCESEventFlow_DeleteUnknownSlice verifies that deleting a
// CES the manager never saw is a safe no-op.
func TestPrivilegedCESEventFlow_DeleteUnknownSlice(t *testing.T) {
	k := setupEgressGatewayCESTestSuite(t)

	manager := k.manager

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1})

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpointSlices.sync(t)

	// Delete a CES we never upserted — should be a no-op
	ces := newTestCES("unknown-slice", "default",
		newTestCoreCEP("ep-1", 12345, ep1IP, node1IP),
	)
	deleteCESAndReconcile(t, manager, k.endpointSlices, ces)

	// Manager should still be healthy with empty stores
	manager.Lock()
	require.Empty(t, manager.epDataStore)
	manager.Unlock()
}

// TestPrivilegedCESEventFlow_NodeSelector verifies that CES-sourced endpoints
// correctly carry NodeIP so that policies with nodeSelectors can match (or
// reject) endpoints based on which node they run on.
func TestPrivilegedCESEventFlow_NodeSelector(t *testing.T) {
	k := setupEgressGatewayCESTestSuite(t)

	manager := k.manager
	policyMap4 := manager.policyMap4

	createTestInterface(t, k.sysctl, testInterface1, []string{egressCIDR1})

	k.policies.sync(t)
	k.nodes.sync(t)
	k.endpointSlices.sync(t)

	// Add two nodes with different labels
	node1Obj := newCiliumNode(node1, node1IP, nodeGroup1Labels)
	cesAddNodeAndReconcile(t, k, manager, &node1Obj)

	node2Obj := newCiliumNode(node2, node2IP, nodeGroup2Labels)
	cesAddNodeAndReconcile(t, k, manager, &node2Obj)

	// Create a policy that matches ep1Labels AND requires nodeGroup2Labels
	// (i.e. only endpoints on node2 should match)
	addPolicyAndReconcile(t, manager, k.policies, &policyParams{
		name:             "policy-with-node-selector",
		endpointLabels:   ep1Labels,
		destinationCIDRs: []string{destCIDR},
		nodeSelectors:    nodeGroup2Labels,
		policyGwParams: []policyGatewayParams{
			{
				nodeLabels: nodeGroup1Labels,
				iface:      testInterface1,
			},
		},
	})

	cesIdentityAllocator := manager.identityAllocator.(*testidentity.MockIdentityAllocator)
	id1, _, _ := cesIdentityAllocator.AllocateIdentity(
		context.Background(),
		labels.Map2Labels(ep1Labels, labels.LabelSourceK8s),
		true, identity.InvalidIdentity,
	)

	// Endpoint on node1 — should NOT match (wrong node labels)
	cesOnNode1 := newTestCES("slice-node1", "default",
		newTestCoreCEP("ep-on-node1", int64(id1.ID), ep1IP, node1IP),
	)
	upsertCESAndReconcile(t, manager, k.endpointSlices, cesOnNode1)

	assertEgressRules4(t, policyMap4, []egressRule{})

	// Endpoint on node2 — should match (correct node labels)
	cesOnNode2 := newTestCES("slice-node2", "default",
		newTestCoreCEP("ep-on-node2", int64(id1.ID), ep2IP, node2IP),
	)
	upsertCESAndReconcile(t, manager, k.endpointSlices, cesOnNode2)

	assertEgressRules4(t, policyMap4, []egressRule{
		{ep2IP, destCIDR, egressIP1, node1IP, 0},
	})

	// Delete the matching CES — BPF map should be empty again
	deleteCESAndReconcile(t, manager, k.endpointSlices, cesOnNode2)

	assertEgressRules4(t, policyMap4, []egressRule{})
}
