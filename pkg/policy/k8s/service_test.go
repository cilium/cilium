// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

type fakePolicyImporter struct {
	OnUpdatePolicy func(upd *policytypes.PolicyUpdate)
}

func (f *fakePolicyImporter) UpdatePolicy(upd *policytypes.PolicyUpdate) {
	if f.OnUpdatePolicy != nil {
		f.OnUpdatePolicy(upd)
	} else {
		panic("OnUpdatePolicy(upd *policytypes.PolicyUpdate) was called but was not set")
	}
}

func addrToCIDRRule(addr netip.Addr) api.CIDRRule {
	return api.CIDRRule{
		Cidr:      api.CIDR(netip.PrefixFrom(addr, addr.BitLen()).String()),
		Generated: true,
	}
}

func sortCIDRSet(s api.CIDRRuleSlice) api.CIDRRuleSlice {
	slices.SortFunc(s, func(a, b api.CIDRRule) int {
		return cmp.Compare(a.Cidr, b.Cidr)
	})
	return s
}

type servicesFixture struct {
	db       *statedb.DB
	services statedb.RWTable[*loadbalancer.Service]
	backends statedb.RWTable[*loadbalancer.Backend]
}

func newServicesFixture(t *testing.T) servicesFixture {
	db := statedb.New()
	services, err := loadbalancer.NewServicesTable(loadbalancer.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := loadbalancer.NewBackendsTable(db)
	require.NoError(t, err)

	return servicesFixture{
		db:       db,
		services: services,
		backends: backends,
	}
}

func (sf *servicesFixture) upsertService(name loadbalancer.ServiceName, lbls, selectors map[string]string, backendAddrs []cmtypes.AddrCluster, prev *serviceEvent) serviceEvent {
	var ev serviceEvent
	ev.name = name
	ev.labels = labels.Map2Labels(lbls, "k8s")
	if prev != nil {
		copy := *prev
		ev.previous = &copy
	}

	wtxn := sf.db.WriteTxn(sf.services, sf.backends)
	defer wtxn.Commit()
	sf.services.Insert(wtxn, &loadbalancer.Service{
		Name:     name,
		Labels:   ev.labels,
		Selector: selectors,
	})
	// Clear any old associations.
	for be := range sf.backends.List(wtxn, loadbalancer.BackendByServiceName(name)) {
		sf.backends.Delete(wtxn, be)
	}
	for _, addrCluster := range backendAddrs {
		addr := loadbalancer.NewL3n4Addr(
			loadbalancer.TCP,
			addrCluster,
			0,
			loadbalancer.ScopeExternal)
		be := &loadbalancer.Backend{
			Address: addr,
		}
		be.Instances = be.Instances.Set(loadbalancer.BackendInstanceKey{
			ServiceName: name,
		}, loadbalancer.BackendParams{Address: addr})
		ev.backendRevisions = append(ev.backendRevisions, sf.backends.Revision(wtxn))
		sf.backends.Insert(wtxn, be)
	}
	return ev
}

func TestPolicyWatcher_updateToServicesPolicies(t *testing.T) {
	policyAdd := make(chan policytypes.PolicyEntries, 3)
	policyImporter := &fakePolicyImporter{
		OnUpdatePolicy: func(upd *policytypes.PolicyUpdate) {
			policyAdd <- upd.Rules
		},
	}

	barSvcLabels := map[string]string{
		"app": "bar",
	}
	barSvcSelector := api.ServiceSelector(api.NewESFromMatchRequirements(barSvcLabels, nil))

	svcByNameCNP := &types.SlimCNP{
		CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2",
				Kind:       "CiliumNetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc-by-name",
				Namespace: "test",
			},
			Spec: &api.Rule{
				EndpointSelector: api.NewESFromLabels(),
				Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									// Selects foo service by name
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "foo-svc",
										Namespace:   "foo-ns",
									},
								},
								{
									// Selects bar service by name
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "bar-svc",
										Namespace:   "bar-ns",
									},
								},
							},
						},
					},
				},
			},
			Specs: api.Rules{
				{
					EndpointSelector: api.NewESFromLabels(),
					Egress: []api.EgressRule{
						{
							EgressCommonRule: api.EgressCommonRule{
								ToServices: []api.Service{
									{
										// Selects foo service by name
										K8sService: &api.K8sServiceNamespace{
											ServiceName: "foo-svc",
											Namespace:   "foo-ns",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	svcByNameLbl := labels.NewLabel("io.cilium.k8s.policy.name", svcByNameCNP.Name, "k8s")
	svcByNameKey := resource.NewKey(svcByNameCNP)
	svcByNameResourceID := resourceIDForCiliumNetworkPolicy(svcByNameKey, svcByNameCNP)

	svcByLabelCNP := &types.SlimCNP{
		CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2",
				Kind:       "ClusterwideCiliumNetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc-by-label",
				Namespace: "",
			},
			Spec: &api.Rule{
				EndpointSelector: api.NewESFromLabels(),
				Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									// Selects bar service by label selector
									K8sServiceSelector: &api.K8sServiceSelectorNamespace{
										Selector: barSvcSelector,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	svcByLabelLbl := labels.NewLabel("io.cilium.k8s.policy.name", svcByLabelCNP.Name, "k8s")
	svcByLabelKey := resource.NewKey(svcByLabelCNP)
	svcByLabelResourceID := resourceIDForCiliumNetworkPolicy(svcByLabelKey, svcByLabelCNP)

	fooEpAddr1 := cmtypes.MustParseAddrCluster("10.1.1.1")
	fooEpAddr2 := cmtypes.MustParseAddrCluster("10.1.1.2")
	fooSvcID := loadbalancer.NewServiceName("foo-ns", "foo-svc")
	fooEps := []cmtypes.AddrCluster{fooEpAddr1, fooEpAddr2}

	barEpAddr := cmtypes.MustParseAddrCluster("192.168.1.1")
	barSvcID := loadbalancer.NewServiceName("bar-ns", "bar-svc")
	barEps := []cmtypes.AddrCluster{barEpAddr}

	// baz is similar to bar, but not an external service (thus not selectable)
	bazSvcID := loadbalancer.NewServiceName("baz-ns", "baz-svc")
	bazSvcSelector := map[string]string{
		"app": "baz",
	}

	bazEps := []cmtypes.AddrCluster{barEpAddr}

	servicesFixture := newServicesFixture(t)

	p := &policyWatcher{
		log:                hivetest.Logger(t),
		config:             &option.DaemonConfig{},
		k8sResourceSynced:  &k8sSynced.Resources{CacheStatus: make(k8sSynced.CacheStatus)},
		k8sAPIGroups:       &k8sSynced.APIGroups{},
		db:                 servicesFixture.db,
		services:           servicesFixture.services,
		backends:           servicesFixture.backends,
		policyImporter:     policyImporter,
		cnpCache:           map[resource.Key]*types.SlimCNP{},
		toServicesPolicies: map[resource.Key]struct{}{},
		cnpByServiceID:     map[loadbalancer.ServiceName]map[resource.Key]struct{}{},
		metricsManager:     NewCNPMetricsNoop(),
	}

	// Upsert policies. No services are known, so generated ToCIDRSet should be empty
	err := p.onUpsert(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)
	assert.NoError(t, err)
	rules := <-policyAdd
	assert.Len(t, rules, 2)
	assert.Empty(t, rules[0].L3)
	assert.Empty(t, rules[1].L3)

	err = p.onUpsert(svcByLabelCNP, svcByLabelKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByLabelResourceID, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Empty(t, rules[0].L3)

	// Check that policies are recognized as ToServices policies
	assert.Equal(t, map[resource.Key]struct{}{
		svcByNameKey:  {},
		svcByLabelKey: {},
	}, p.toServicesPolicies)

	select {
	case <-policyAdd:
		t.Fatalf("what1")
	default:
	}

	// Add foo-svc, which is selected by svcByNameCNP twice
	fooEv := servicesFixture.upsertService(fooSvcID, nil, nil, fooEps, nil)

	err = p.updateToServicesPolicies(fooEv)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 2)

	// Check that Spec was translated
	assert.Contains(t, rules[0].Labels, svcByNameLbl)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
	}, sortCIDRSet(rules[0].L3.CIDRRules()))

	// Check that Specs was translated
	assert.Contains(t, rules[1].Labels, svcByNameLbl)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
	}, sortCIDRSet(rules[1].L3.CIDRRules()))

	// Check that policy has been marked
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Add bar-svc, which is selected by both policies
	barEv := servicesFixture.upsertService(barSvcID, barSvcLabels, nil, barEps, nil)
	err = p.updateToServicesPolicies(barEv)
	assert.NoError(t, err)

	// Expect two policies to be updated (in any order)
	var policies [2]policytypes.PolicyEntries
	policies[0] = <-policyAdd
	policies[1] = <-policyAdd
	slices.SortFunc(policies[:], func(a, b policytypes.PolicyEntries) int {
		return cmp.Compare(len(b), len(a))
	})
	byNameRules, byLabelRules := policies[0], policies[1]

	// Check that svcByNameCNP Spec (matching foo and bar) was translated
	assert.Len(t, byNameRules, 2)
	assert.Contains(t, byNameRules[0].Labels, svcByNameLbl)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
		addrToCIDRRule(barEpAddr.Addr()),
	}, sortCIDRSet(byNameRules[0].L3.CIDRRules()))

	// Check that svcByNameCNP Specs (matching only foo) was translated
	assert.Contains(t, byNameRules[1].Labels, svcByNameLbl)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
	}, sortCIDRSet(byNameRules[1].L3.CIDRRules()))

	// Check that svcByLabelCNP Spec (matching only bar) was translated
	assert.Len(t, byLabelRules, 1)
	assert.Contains(t, byLabelRules[0].Labels, svcByLabelLbl)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(barEpAddr.Addr()),
	}, sortCIDRSet(byLabelRules[0].L3.CIDRRules()))

	// Check that policies have been marked
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
		barSvcID: {
			svcByNameKey:  {},
			svcByLabelKey: {},
		},
	}, p.cnpByServiceID)

	// Change foo-svc endpoints, which is selected by svcByNameCNP twice
	fooEv = servicesFixture.upsertService(fooSvcID, nil, nil, fooEps[:1], &fooEv)
	err = p.updateToServicesPolicies(fooEv)

	assert.NoError(t, err)
	byNameRules = <-policyAdd
	assert.Len(t, byNameRules, 2)

	// Check that svcByNameCNP Spec (matching foo and bar) was translated
	assert.Contains(t, byNameRules[0].Labels, svcByNameLbl)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(barEpAddr.Addr()),
	}, sortCIDRSet(byNameRules[0].L3.CIDRRules()))

	// Check that Specs was translated (matching only foo) was translated
	assert.Contains(t, byNameRules[1].Labels, svcByNameLbl)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
	}, sortCIDRSet(byNameRules[1].L3.CIDRRules()))

	// Delete bar-svc labels. This should remove all CIDRs from svcByLabelCNP
	barEv = servicesFixture.upsertService(barSvcID, nil, nil, barEps, &barEv)
	err = p.updateToServicesPolicies(barEv)
	assert.NoError(t, err)

	// Expect two policies to be updated (in any order)
	oldByNameRules := make(policytypes.PolicyEntries, 0)
	for _, r := range byNameRules {
		oldRule := *r
		oldByNameRules = append(oldByNameRules, &oldRule)
	}
	policies[0] = <-policyAdd
	policies[1] = <-policyAdd
	slices.SortFunc(policies[:], func(a, b policytypes.PolicyEntries) int {
		return cmp.Compare(len(b), len(a))
	})
	byNameRules, byLabelRules = policies[0], policies[1]

	// Check that svcByNameCNP has not changed
	assert.Equal(t,
		sortCIDRSet(byNameRules[0].L3.CIDRRules()),
		sortCIDRSet(oldByNameRules[0].L3.CIDRRules()))
	assert.Equal(t,
		sortCIDRSet(byNameRules[1].L3.CIDRRules()),
		sortCIDRSet(oldByNameRules[1].L3.CIDRRules()))

	// Check that svcByLabelCNP Spec no longer matches anything
	assert.Len(t, byLabelRules, 1)
	assert.Contains(t, byLabelRules[0].Labels, svcByLabelLbl)
	assert.Empty(t, byLabelRules[0].L3)

	// Check that policies have been cleared
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
		barSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Add baz-svc, which is selected by svcByLabelCNP
	bazEv := servicesFixture.upsertService(bazSvcID, barSvcLabels, bazSvcSelector, bazEps, nil)
	err = p.updateToServicesPolicies(bazEv)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	// Check that Spec was translated
	assert.Contains(t, rules[0].Labels, svcByLabelLbl)
	assert.Len(t, rules[0].L3, 1)

	bazEndpointSelector := api.NewESFromMatchRequirements(bazSvcSelector, nil)
	bazEndpointSelector.Generated = true
	var podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel
	bazEndpointSelector.AddMatch(podPrefixLbl, bazSvcID.Namespace())

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, bazEndpointSelector.LabelSelector.String(), rules[0].L3[0].Key())

	// Check that policy has been marked
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
		barSvcID: {
			svcByNameKey: {},
		},
		bazSvcID: {
			svcByLabelKey: {},
		},
	}, p.cnpByServiceID)
}

func TestPolicyWatcher_updateToServicesPoliciesTransformToEndpoint(t *testing.T) {
	policyAdd := make(chan policytypes.PolicyEntries, 1)
	policyDelete := make(chan policytypes.PolicyEntries, 1)
	policyImporter := &fakePolicyImporter{
		OnUpdatePolicy: func(upd *policytypes.PolicyUpdate) {
			if upd.Rules == nil {
				policyDelete <- nil
			} else {
				policyAdd <- upd.Rules
			}
		},
	}

	svcByNameCNP := &types.SlimCNP{
		CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2",
				Kind:       "CiliumNetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc-by-name",
				Namespace: "test",
			},
			Spec: &api.Rule{
				EndpointSelector: api.NewESFromLabels(),
				Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									// Selects foo service by name
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "foo-svc",
										Namespace:   "foo-ns",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	svcByNameLbl := labels.NewLabel("io.cilium.k8s.policy.name", svcByNameCNP.Name, "k8s")
	svcByNameKey := resource.NewKey(svcByNameCNP)
	svcByNameResourceID := resourceIDForCiliumNetworkPolicy(svcByNameKey, svcByNameCNP)

	servicesFixture := newServicesFixture(t)

	p := &policyWatcher{
		log:                hivetest.Logger(t),
		config:             &option.DaemonConfig{},
		k8sResourceSynced:  &k8sSynced.Resources{CacheStatus: make(k8sSynced.CacheStatus)},
		k8sAPIGroups:       &k8sSynced.APIGroups{},
		policyImporter:     policyImporter,
		db:                 servicesFixture.db,
		services:           servicesFixture.services,
		backends:           servicesFixture.backends,
		cnpCache:           map[resource.Key]*types.SlimCNP{},
		toServicesPolicies: map[resource.Key]struct{}{},
		cnpByServiceID:     map[loadbalancer.ServiceName]map[resource.Key]struct{}{},
		metricsManager:     NewCNPMetricsNoop(),
	}

	// Upsert policies. No services are known, so generated ToEndpoints should be empty
	err := p.onUpsert(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)
	assert.NoError(t, err)
	rules := <-policyAdd
	assert.Len(t, rules, 1)
	assert.Empty(t, rules[0].L3)

	// Check that policies are recognized as ToServices policies
	assert.Equal(t, map[resource.Key]struct{}{
		svcByNameKey: {},
	}, p.toServicesPolicies)
	fooSvcID := loadbalancer.NewServiceName("foo-ns", "foo-svc")
	fooSvcSelector := map[string]string{
		"app": "foo",
	}

	fooEv := servicesFixture.upsertService(fooSvcID, nil, fooSvcSelector, nil, nil)
	err = p.updateToServicesPolicies(fooEv)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)

	// Check that Spec was translated
	assert.Contains(t, rules[0].Labels, svcByNameLbl)
	assert.Len(t, rules[0].L3, 1)

	fooEndpointSelector := api.NewESFromMatchRequirements(maps.Clone(fooSvcSelector), nil)
	fooEndpointSelector.Generated = true
	var podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel
	fooEndpointSelector.AddMatch(podPrefixLbl, fooSvcID.Namespace())

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, fooEndpointSelector.LabelSelector.String(), rules[0].L3[0].Key())

	// Check that policies have been marked
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Change foo-svc labels. This should keep the ToEndpoints
	fooSvcLabels := map[string]string{
		"app": "foo",
		"new": "label",
	}
	fooEv = servicesFixture.upsertService(fooSvcID, fooSvcLabels, fooSvcSelector, nil, &fooEv)
	err = p.updateToServicesPolicies(fooEv)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].L3, 1)

	fooEndpointSelector = api.NewESFromMatchRequirements(maps.Clone(fooSvcSelector), nil)
	fooEndpointSelector.Generated = true
	fooEndpointSelector.AddMatch(podPrefixLbl, fooSvcID.Namespace())

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, fooEndpointSelector.LabelSelector.String(), rules[0].L3[0].Key())

	// bar-svc is selected by svcByLabelCNP
	barSvcLabels := map[string]string{
		"app": "bar",
	}
	barSvcSelector := api.ServiceSelector(api.NewESFromMatchRequirements(barSvcLabels, nil))

	svcByLabelCNP := &types.SlimCNP{
		CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2",
				Kind:       "ClusterwideCiliumNetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "svc-by-label",
				Namespace: "",
			},
			Spec: &api.Rule{
				EndpointSelector: api.NewESFromLabels(),
				Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									// Selects bar service by label selector
									K8sServiceSelector: &api.K8sServiceSelectorNamespace{
										Selector: barSvcSelector,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	// svcByLabelLbl := labels.NewLabel("io.cilium.k8s.policy.name", svcByLabelCNP.Name, "k8s")
	svcByLabelKey := resource.NewKey(svcByLabelCNP)
	svcByLabelResourceID := resourceIDForCiliumNetworkPolicy(svcByLabelKey, svcByLabelCNP)
	barSvcID := loadbalancer.NewServiceName("bar-ns", "bar-svc")
	err = p.onUpsert(svcByLabelCNP, svcByLabelKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByLabelResourceID, nil)
	// Upsert policies. No services are known, so generated ToEndpoints should be empty
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Empty(t, rules[0].L3)

	barEv := servicesFixture.upsertService(barSvcID, barSvcLabels, barSvcLabels, nil, nil)
	err = p.updateToServicesPolicies(barEv)

	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].L3, 1)

	barEndpointSelector := api.NewESFromMatchRequirements(maps.Clone(barSvcLabels), nil)
	barEndpointSelector.Generated = true
	barEndpointSelector.AddMatch(podPrefixLbl, barSvcID.Namespace())

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, barEndpointSelector.LabelSelector.String(), rules[0].L3[0].Key())

	// Check that policies have been marked
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
		barSvcID: {
			svcByLabelKey: {},
		},
	}, p.cnpByServiceID)

	// Delete bar-svc labels. This should remove all toEndpoints from svcByLabelCNP
	barEv = servicesFixture.upsertService(barSvcID, nil, barSvcLabels, nil, &barEv)
	err = p.updateToServicesPolicies(barEv)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Empty(t, rules[0].L3)

	// Check that policies have been cleared
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Delete svc-by-name policy and check that the policy is removed
	p.onDelete(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)

	// Expect policy to be deleted
	<-policyDelete

	// Check that policies have been cleared
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{}, p.cnpByServiceID)

	// Add foo-svc again, which should re-add the policy
	fooEv.previous = nil // Bypass change checks
	err = p.updateToServicesPolicies(fooEv)
	p.onUpsert(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].L3, 1)

	fooEndpointSelector = api.NewESFromMatchRequirements(maps.Clone(fooSvcSelector), nil)
	fooEndpointSelector.Generated = true
	fooEndpointSelector.AddMatch(podPrefixLbl, fooSvcID.Namespace())

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, fooEndpointSelector.LabelSelector.String(), rules[0].L3[0].Key())

	// Check that policies have been marked
	assert.Equal(t, map[loadbalancer.ServiceName]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)
}

func Test_hasMatchingToServices(t *testing.T) {
	type args struct {
		spec *api.Rule
		ev   serviceEvent
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "nil rule",
			args: args{
				spec: nil,
				ev: serviceEvent{
					name: loadbalancer.NewServiceName("test-ns", "test-svc"),
				},
			},
			want: false,
		},
		{
			name: "by name and namespace",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{K8sService: &api.K8sServiceNamespace{
									ServiceName: "test-svc",
									Namespace:   "test-ns",
								}},
							},
						},
					},
				}},
				ev: serviceEvent{
					name: loadbalancer.NewServiceName("test-ns", "test-svc"),
				},
			},
			want: true,
		},
		{
			name: "by name without namespace",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{K8sService: &api.K8sServiceNamespace{
									ServiceName: "test-svc",
									Namespace:   "",
								}},
							},
						},
					},
				}},
				ev: serviceEvent{
					name: loadbalancer.NewServiceName("test-ns", "test-svc"),
				},
			},
			want: true,
		},
		{
			name: "by name with wrong namespace",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "test-svc",
										Namespace:   "test-ns",
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name: loadbalancer.NewServiceName("not-test-ns", "test-svc"),
				},
			},
			want: false,
		},
		{
			name: "invalid namespace-only selector",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "",
										Namespace:   "test-ns",
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name: loadbalancer.NewServiceName("test-ns", "test-svc"),
				},
			},
			want: false,
		},
		{
			name: "empty selector",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "",
										Namespace:   "",
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name: loadbalancer.NewServiceName("test-ns", "test-svc"),
				},
			},
			want: false,
		},
		{
			name: "second selector",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "foo-svc",
										Namespace:   "",
									},
								},
								{
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "test-svc",
										Namespace:   "test-ns",
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name: loadbalancer.NewServiceName("test-ns", "test-svc"),
				},
			},
			want: true,
		},
		{
			name: "by label",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sServiceSelector: &api.K8sServiceSelectorNamespace{
										Selector: api.ServiceSelector(api.NewESFromMatchRequirements(map[string]string{
											"foo": "bar",
										}, nil)),
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name:   loadbalancer.NewServiceName("test-ns", "test-svc"),
					labels: labels.NewLabelsFromSortedList("baz=qux;foo=bar"),
				},
			},
			want: true,
		},
		{
			name: "by label requirements",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sServiceSelector: &api.K8sServiceSelectorNamespace{
										Selector: api.ServiceSelector(api.NewESFromMatchRequirements(nil, []slim_metav1.LabelSelectorRequirement{
											{Key: "foo", Operator: "Exists"},
										})),
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name:   loadbalancer.NewServiceName("test-ns", "test-svc"),
					labels: labels.NewLabelsFromSortedList("baz=qux;foo=bar"),
				},
			},
			want: true,
		},
		{
			name: "overspecific label selector",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sServiceSelector: &api.K8sServiceSelectorNamespace{
										Selector: api.ServiceSelector(api.NewESFromMatchRequirements(map[string]string{
											"foo": "bar",
											"not": "present",
										}, nil)),
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name:   loadbalancer.NewServiceName("test-ns", "test-svc"),
					labels: labels.NewLabelsFromSortedList("baz=qux;foo=bar"),
				},
			},
			want: false,
		},
		{
			name: "by label with wrong namespace",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sServiceSelector: &api.K8sServiceSelectorNamespace{
										Selector: api.ServiceSelector(api.NewESFromMatchRequirements(map[string]string{
											"foo": "bar",
										}, nil)),
										Namespace: "not-test-ns",
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name:   loadbalancer.NewServiceName("test-ns", "test-svc"),
					labels: labels.NewLabelsFromSortedList("baz=qux,foo=bar"),
				},
			},
			want: false,
		},
		{
			name: "by label takes precedence over by name",
			args: args{
				spec: &api.Rule{Egress: []api.EgressRule{
					{
						EgressCommonRule: api.EgressCommonRule{
							ToServices: []api.Service{
								{
									K8sService: &api.K8sServiceNamespace{
										ServiceName: "test-svc",
										Namespace:   "test-ns",
									},
									K8sServiceSelector: &api.K8sServiceSelectorNamespace{
										Selector: api.ServiceSelector(api.NewESFromMatchRequirements(map[string]string{
											"no": "match",
										}, nil)),
									},
								},
							},
						},
					},
				}},
				ev: serviceEvent{
					name:   loadbalancer.NewServiceName("test-ns", "test-svc"),
					labels: labels.NewLabelsFromSortedList("baz=qux,foo=bar"),
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, hasMatchingToServices(tt.args.spec, tt.args.ev), "hasMatchingToServices(%v, %v)", tt.args.spec, tt.args.ev)
		})
	}
}

func TestServiceEventStream(t *testing.T) {
	servicesFixture := newServicesFixture(t)
	serviceEvents := stream.ToChannel(
		t.Context(),
		serviceEventStream(servicesFixture.db, servicesFixture.services, servicesFixture.backends),
	)

	svc := loadbalancer.NewServiceName("test", "svc1")
	lbls := map[string]string{"foo": "bar"}
	addr := cmtypes.MustParseAddrCluster("10.0.0.1")

	testCases := []struct {
		step     string
		name     loadbalancer.ServiceName
		labels   map[string]string
		selector map[string]string
		backends []cmtypes.AddrCluster
		expected serviceEvent
		skip     bool
		delete   bool
	}{
		{
			step:     "initial",
			name:     svc,
			expected: serviceEvent{name: svc},
		},
		// Repeating the same will not emit event
		{
			step: "repeat",
			name: svc,
			skip: true,
		},
		// Updating labels emits event
		{
			step:     "update labels",
			name:     svc,
			labels:   lbls,
			expected: serviceEvent{name: svc, labels: labels.Map2Labels(lbls, "k8s")},
		},
		// Updating selectors emits event
		{
			step:     "update selectors",
			name:     svc,
			labels:   lbls,
			selector: lbls,
			expected: serviceEvent{name: svc, labels: labels.Map2Labels(lbls, "k8s"), selector: lbls},
		},
		// Adding backends emits event
		{
			step:     "add backends",
			name:     svc,
			labels:   lbls,
			selector: lbls,
			backends: []cmtypes.AddrCluster{addr},
			expected: serviceEvent{name: svc, labels: labels.Map2Labels(lbls, "k8s"), selector: lbls, backendRevisions: []uint64{1}},
		},
		// Deleting a service emits delete event with data from last one.
		{
			step:     "delete service",
			name:     svc,
			delete:   true,
			expected: serviceEvent{deleted: true, name: svc, labels: labels.Map2Labels(lbls, "k8s"), selector: lbls, backendRevisions: []uint64{1}},
		},
	}

	for _, testCase := range testCases {
		t.Logf("STEP: %s", testCase.step)
		if testCase.delete {
			wtxn := servicesFixture.db.WriteTxn(servicesFixture.services)
			servicesFixture.services.Delete(wtxn, &loadbalancer.Service{
				Name: testCase.name,
			})
			wtxn.Commit()
		} else {
			servicesFixture.upsertService(testCase.name, testCase.labels, testCase.selector, testCase.backends, nil)
		}
		if !testCase.skip {
			ev := <-serviceEvents
			require.True(t, ev.Equal(testCase.expected), "expected %+v to equal %+v", ev, testCase.expected)
		}
	}
}
