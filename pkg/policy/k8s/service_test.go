// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
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

type fakeService struct {
	svc *k8s.MinimalService
	eps *k8s.MinimalEndpoints
}

type fakeServiceCache map[k8s.ServiceID]fakeService

func (f fakeServiceCache) ForEachService(yield func(svcID k8s.ServiceID, svc *k8s.MinimalService, eps *k8s.MinimalEndpoints) bool) {
	for svcID, s := range f {
		if !yield(svcID, s.svc, s.eps) {
			break
		}
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

func TestPolicyWatcher_updateToServicesPolicies(t *testing.T) {
	policyAdd := make(chan api.Rules, 3)
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
	fooSvcID := k8s.ServiceID{
		Name:      "foo-svc",
		Namespace: "foo-ns",
	}
	fooSvc := &k8s.MinimalService{}
	fooEps := &k8s.MinimalEndpoints{
		Backends: map[cmtypes.AddrCluster]serviceStore.PortConfiguration{
			fooEpAddr1: {
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
			fooEpAddr2: {
				"port": {
					Protocol: loadbalancer.TCP,
					Port:     80,
				},
			},
		},
	}

	barEpAddr := cmtypes.MustParseAddrCluster("192.168.1.1")
	barSvcID := k8s.ServiceID{
		Name:      "bar-svc",
		Namespace: "bar-ns",
	}
	barSvc := &k8s.MinimalService{
		Labels: barSvcLabels,
	}
	barEps := &k8s.MinimalEndpoints{
		Backends: map[cmtypes.AddrCluster]serviceStore.PortConfiguration{
			barEpAddr: {
				"port": {
					Protocol: loadbalancer.UDP,
					Port:     53,
				},
			},
		},
	}

	// baz is similar to bar, but not an external service (thus not selectable)
	bazSvcID := k8s.ServiceID{
		Name:      "baz-svc",
		Namespace: "baz-ns",
	}
	bazSvcLabels := map[string]string{
		"app": "baz",
	}
	bazSvc := &k8s.MinimalService{
		Labels:   barSvcLabels,
		Selector: bazSvcLabels,
	}

	bazEps := &k8s.MinimalEndpoints{
		Backends: map[cmtypes.AddrCluster]serviceStore.PortConfiguration{
			barEpAddr: {
				"port": {
					Protocol: loadbalancer.UDP,
					Port:     53,
				},
			},
		},
	}

	svcCache := fakeServiceCache{}
	p := &policyWatcher{
		log:                hivetest.Logger(t),
		config:             &option.DaemonConfig{},
		k8sResourceSynced:  &k8sSynced.Resources{CacheStatus: make(k8sSynced.CacheStatus)},
		k8sAPIGroups:       &k8sSynced.APIGroups{},
		policyImporter:     policyImporter,
		svcCache:           svcCache,
		cnpCache:           map[resource.Key]*types.SlimCNP{},
		toServicesPolicies: map[resource.Key]struct{}{},
		cnpByServiceID:     map[k8s.ServiceID]map[resource.Key]struct{}{},
		metricsManager:     NewCNPMetricsNoop(),
	}

	// Upsert policies. No services are known, so generated ToCIDRSet should be empty
	err := p.onUpsert(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)
	assert.NoError(t, err)
	rules := <-policyAdd
	assert.Len(t, rules, 2)
	assert.Len(t, rules[0].Egress, 1)
	assert.Empty(t, rules[0].Egress[0].ToCIDRSet)
	assert.Len(t, rules[1].Egress, 1)
	assert.Empty(t, rules[1].Egress[0].ToCIDRSet)

	err = p.onUpsert(svcByLabelCNP, svcByLabelKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByLabelResourceID, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].Egress, 1)
	assert.Empty(t, rules[0].Egress[0].ToCIDRSet)

	// Check that policies are recognized as ToServices policies
	assert.Equal(t, map[resource.Key]struct{}{
		svcByNameKey:  {},
		svcByLabelKey: {},
	}, p.toServicesPolicies)

	// Add foo-svc, which is selected by svcByNameCNP twice
	svcCache[fooSvcID] = fakeService{
		svc: fooSvc,
		eps: fooEps,
	}
	err = p.updateToServicesPolicies(fooSvcID, fooSvc, nil, fooEps, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 2)

	// Check that Spec was translated
	assert.Len(t, rules[0].Egress, 1)
	assert.Contains(t, rules[0].Labels, svcByNameLbl)
	assert.Equal(t, svcByNameCNP.Spec.Egress[0].ToServices, rules[0].Egress[0].ToServices)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
	}, sortCIDRSet(rules[0].Egress[0].ToCIDRSet))

	// Check that Specs was translated
	assert.Len(t, rules[1].Egress, 1)
	assert.Contains(t, rules[1].Labels, svcByNameLbl)
	assert.Equal(t, svcByNameCNP.Specs[0].Egress[0].ToServices, rules[1].Egress[0].ToServices)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
	}, sortCIDRSet(rules[1].Egress[0].ToCIDRSet))

	// Check that policy has been marked
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Add bar-svc, which is selected by both policies
	svcCache[barSvcID] = fakeService{
		svc: barSvc,
		eps: barEps,
	}
	err = p.updateToServicesPolicies(barSvcID, barSvc, nil, barEps, nil)
	assert.NoError(t, err)

	// Expect two policies to be updated (in any order)
	var policies [2]api.Rules
	policies[0] = <-policyAdd
	policies[1] = <-policyAdd
	slices.SortFunc(policies[:], func(a, b api.Rules) int {
		return cmp.Compare(a.String(), b.String())
	})
	byNameRules, byLabelRules := policies[0], policies[1]

	// Check that svcByNameCNP Spec (matching foo and bar) was translated
	assert.Len(t, byNameRules, 2)
	assert.Len(t, byNameRules[0].Egress, 1)
	assert.Contains(t, byNameRules[0].Labels, svcByNameLbl)
	assert.Equal(t, svcByNameCNP.Spec.Egress[0].ToServices, byNameRules[0].Egress[0].ToServices)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
		addrToCIDRRule(barEpAddr.Addr()),
	}, sortCIDRSet(byNameRules[0].Egress[0].ToCIDRSet))

	// Check that svcByNameCNP Specs (matching only foo) was translated
	assert.Len(t, byNameRules[1].Egress, 1)
	assert.Contains(t, byNameRules[1].Labels, svcByNameLbl)
	assert.Equal(t, svcByNameCNP.Specs[0].Egress[0].ToServices, byNameRules[1].Egress[0].ToServices)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(fooEpAddr2.Addr()),
	}, sortCIDRSet(byNameRules[1].Egress[0].ToCIDRSet))

	// Check that svcByLabelCNP Spec (matching only bar) was translated
	assert.Len(t, byLabelRules, 1)
	assert.Len(t, byLabelRules[0].Egress, 1)
	assert.Contains(t, byLabelRules[0].Labels, svcByLabelLbl)
	assert.Equal(t, svcByLabelCNP.Spec.Egress[0].ToServices, byLabelRules[0].Egress[0].ToServices)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(barEpAddr.Addr()),
	}, byLabelRules[0].Egress[0].ToCIDRSet)

	// Check that policies have been marked
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
		barSvcID: {
			svcByNameKey:  {},
			svcByLabelKey: {},
		},
	}, p.cnpByServiceID)

	// Change foo-svc endpoints, which is selected by svcByNameCNP twice
	delete(fooEps.Backends, fooEpAddr2)
	err = p.updateToServicesPolicies(fooSvcID, fooSvc, fooSvc, fooEps, nil)
	assert.NoError(t, err)
	byNameRules = <-policyAdd
	assert.Len(t, byNameRules, 2)

	// Check that svcByNameCNP Spec (matching foo and bar) was translated
	assert.Len(t, byNameRules[0].Egress, 1)
	assert.Contains(t, byNameRules[0].Labels, svcByNameLbl)
	assert.Equal(t, svcByNameCNP.Spec.Egress[0].ToServices, byNameRules[0].Egress[0].ToServices)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
		addrToCIDRRule(barEpAddr.Addr()),
	}, sortCIDRSet(byNameRules[0].Egress[0].ToCIDRSet))

	// Check that Specs was translated (matching only foo) was translated
	assert.Len(t, byNameRules[1].Egress, 1)
	assert.Contains(t, byNameRules[1].Labels, svcByNameLbl)
	assert.Equal(t, svcByNameCNP.Specs[0].Egress[0].ToServices, byNameRules[1].Egress[0].ToServices)
	assert.Equal(t, api.CIDRRuleSlice{
		addrToCIDRRule(fooEpAddr1.Addr()),
	}, sortCIDRSet(byNameRules[1].Egress[0].ToCIDRSet))

	// Delete bar-svc labels. This should remove all CIDRs from svcByLabelCNP
	oldBarSvc := barSvc.DeepCopy()
	barSvc.Labels = nil
	err = p.updateToServicesPolicies(barSvcID, barSvc, oldBarSvc, barEps, barEps)
	assert.NoError(t, err)

	// Expect two policies to be updated (in any order)
	oldByNameRules := byNameRules.DeepCopy()
	policies[0] = <-policyAdd
	policies[1] = <-policyAdd
	slices.SortFunc(policies[:], func(a, b api.Rules) int {
		return cmp.Compare(a.String(), b.String())
	})
	byNameRules, byLabelRules = policies[0], policies[1]

	// Check that svcByNameCNP has not changed
	assert.Equal(t,
		sortCIDRSet(byNameRules[0].Egress[0].ToCIDRSet),
		sortCIDRSet(oldByNameRules[0].Egress[0].ToCIDRSet))
	assert.Equal(t,
		sortCIDRSet(byNameRules[1].Egress[0].ToCIDRSet),
		sortCIDRSet(oldByNameRules[1].Egress[0].ToCIDRSet))

	// Check that svcByLabelCNP Spec no longer matches anything
	assert.Len(t, byLabelRules, 1)
	assert.Len(t, byLabelRules[0].Egress, 1)
	assert.Contains(t, byLabelRules[0].Labels, svcByLabelLbl)
	assert.Equal(t, svcByLabelCNP.Spec.Egress[0].ToServices, byLabelRules[0].Egress[0].ToServices)
	assert.Empty(t, byLabelRules[0].Egress[0].ToCIDRSet)

	// Check that policies have been cleared
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
		barSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Add baz-svc, which is selected by svcByLabelCNP
	svcCache[bazSvcID] = fakeService{
		svc: bazSvc,
		eps: bazEps,
	}
	err = p.updateToServicesPolicies(bazSvcID, bazSvc, nil, bazEps, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	// Check that Spec was translated
	assert.Len(t, rules[0].Egress, 1)
	assert.Contains(t, rules[0].Labels, svcByLabelLbl)
	assert.Len(t, rules[0].Egress[0].ToEndpoints, 1)

	bazEndpointSelectors := api.NewESFromMatchRequirements(bazSvcLabels, nil)
	bazEndpointSelectors.Generated = true
	var podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel
	bazEndpointSelectors.AddMatch(podPrefixLbl, bazSvcID.Namespace)

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, bazEndpointSelectors, rules[0].Egress[0].ToEndpoints[0])

	// Check that policy has been marked
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
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
	policyAdd := make(chan api.Rules, 1)
	policyDelete := make(chan api.Rules, 1)
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

	svcCache := fakeServiceCache{}
	p := &policyWatcher{
		log:                hivetest.Logger(t),
		config:             &option.DaemonConfig{},
		k8sResourceSynced:  &k8sSynced.Resources{CacheStatus: make(k8sSynced.CacheStatus)},
		k8sAPIGroups:       &k8sSynced.APIGroups{},
		policyImporter:     policyImporter,
		svcCache:           svcCache,
		cnpCache:           map[resource.Key]*types.SlimCNP{},
		toServicesPolicies: map[resource.Key]struct{}{},
		cnpByServiceID:     map[k8s.ServiceID]map[resource.Key]struct{}{},
		metricsManager:     NewCNPMetricsNoop(),
	}

	// Upsert policies. No services are known, so generated ToEndpoints should be empty
	err := p.onUpsert(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)
	assert.NoError(t, err)
	rules := <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].Egress, 1)
	assert.Empty(t, rules[0].Egress[0].ToEndpoints)

	// Check that policies are recognized as ToServices policies
	assert.Equal(t, map[resource.Key]struct{}{
		svcByNameKey: {},
	}, p.toServicesPolicies)
	fooSvcID := k8s.ServiceID{
		Name:      "foo-svc",
		Namespace: "foo-ns",
	}
	fooSvcLabels := map[string]string{
		"app": "foo",
	}
	fooSvc := &k8s.MinimalService{
		Selector: fooSvcLabels,
	}
	svcCache[fooSvcID] = fakeService{
		svc: fooSvc,
	}
	err = p.updateToServicesPolicies(fooSvcID, fooSvc, nil, nil, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)

	// Check that Spec was translated
	assert.Len(t, rules[0].Egress, 1)
	assert.Contains(t, rules[0].Labels, svcByNameLbl)
	assert.Equal(t, svcByNameCNP.Spec.Egress[0].ToServices, rules[0].Egress[0].ToServices)
	assert.Len(t, rules[0].Egress[0].ToEndpoints, 1)

	fooEndpointSelectors := api.NewESFromMatchRequirements(fooSvcLabels, nil)
	fooEndpointSelectors.Generated = true
	var podPrefixLbl = labels.LabelSourceK8sKeyPrefix + k8sConst.PodNamespaceLabel
	fooEndpointSelectors.AddMatch(podPrefixLbl, fooSvcID.Namespace)

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, fooEndpointSelectors, rules[0].Egress[0].ToEndpoints[0])

	// Check that policies have been marked
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Change foo-svc labels. This should keep the ToEndpoints
	oldFooSvc := fooSvc.DeepCopy()
	fooSvc.Labels = map[string]string{
		"app": "foo",
		"new": "label",
	}
	err = p.updateToServicesPolicies(fooSvcID, fooSvc, oldFooSvc, nil, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].Egress, 1)
	assert.Len(t, rules[0].Egress[0].ToEndpoints, 1)

	fooEndpointSelectors = api.NewESFromMatchRequirements(fooSvcLabels, nil)
	fooEndpointSelectors.Generated = true
	fooEndpointSelectors.AddMatch(podPrefixLbl, fooSvcID.Namespace)

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, fooEndpointSelectors, rules[0].Egress[0].ToEndpoints[0])

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
	barSvcID := k8s.ServiceID{
		Name:      "bar-svc",
		Namespace: "bar-ns",
	}
	barSvc := &k8s.MinimalService{
		Labels:   barSvcLabels,
		Selector: barSvcLabels,
	}

	err = p.onUpsert(svcByLabelCNP, svcByLabelKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByLabelResourceID, nil)
	// Upsert policies. No services are known, so generated ToEndpoints should be empty
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].Egress, 1)
	assert.Empty(t, rules[0].Egress[0].ToEndpoints)

	svcCache[barSvcID] = fakeService{
		svc: barSvc,
	}
	err = p.updateToServicesPolicies(barSvcID, barSvc, nil, nil, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].Egress, 1)
	assert.Len(t, rules[0].Egress[0].ToEndpoints, 1)

	barEndpointSelectors := api.NewESFromMatchRequirements(barSvcLabels, nil)
	barEndpointSelectors.Generated = true
	barEndpointSelectors.AddMatch(podPrefixLbl, barSvcID.Namespace)

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, barEndpointSelectors, rules[0].Egress[0].ToEndpoints[0])

	// Check that policies have been marked
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
		barSvcID: {
			svcByLabelKey: {},
		},
	}, p.cnpByServiceID)

	// Delete bar-svc labels. This should remove all toEndpoints from svcByLabelCNP
	oldBarSvc := barSvc.DeepCopy()
	barSvc.Labels = nil

	err = p.updateToServicesPolicies(barSvcID, barSvc, oldBarSvc, nil, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].Egress, 1)
	assert.Empty(t, rules[0].Egress[0].ToEndpoints)

	// Check that policies have been cleared
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)

	// Delete svc-by-name policy and check that the policy is removed
	p.onDelete(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)

	// Expect policy to be deleted
	<-policyDelete

	// Check that policies have been cleared
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{}, p.cnpByServiceID)

	// Add foo-svc again, which should re-add the policy
	err = p.updateToServicesPolicies(fooSvcID, fooSvc, nil, nil, nil)
	p.onUpsert(svcByNameCNP, svcByNameKey, k8sAPIGroupCiliumNetworkPolicyV2, svcByNameResourceID, nil)
	assert.NoError(t, err)
	rules = <-policyAdd
	assert.Len(t, rules, 1)
	assert.Len(t, rules[0].Egress, 1)
	assert.Len(t, rules[0].Egress[0].ToEndpoints, 1)

	fooEndpointSelectors = api.NewESFromMatchRequirements(fooSvcLabels, nil)
	fooEndpointSelectors.Generated = true
	fooEndpointSelectors.AddMatch(podPrefixLbl, fooSvcID.Namespace)

	// The endpointSelector should be copied from the Service's selector
	assert.Equal(t, fooEndpointSelectors, rules[0].Egress[0].ToEndpoints[0])

	// Check that policies have been marked
	assert.Equal(t, map[k8s.ServiceID]map[resource.Key]struct{}{
		fooSvcID: {
			svcByNameKey: {},
		},
	}, p.cnpByServiceID)
}
func Test_hasMatchingToServices(t *testing.T) {
	type args struct {
		spec  *api.Rule
		svcID k8s.ServiceID
		svc   *k8s.MinimalService
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "nil rule",
			args: args{
				spec:  nil,
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "not-test-ns"},
				svc:   &k8s.MinimalService{},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{Labels: map[string]string{"foo": "bar", "baz": "qux"}},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{Labels: map[string]string{"foo": "bar", "baz": "qux"}},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{Labels: map[string]string{"foo": "bar", "baz": "qux"}},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{Labels: map[string]string{"foo": "bar", "baz": "qux"}},
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
				svcID: k8s.ServiceID{Name: "test-svc", Namespace: "test-ns"},
				svc:   &k8s.MinimalService{Labels: map[string]string{"foo": "bar", "baz": "qux"}},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, hasMatchingToServices(tt.args.spec, tt.args.svcID, tt.args.svc), "hasMatchingToServices(%v, %v, %v)", tt.args.spec, tt.args.svcID, tt.args.svc)
		})
	}
}

func Test_serviceNotificationsQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	upstream := make(chan k8s.ServiceNotification)
	downstream := serviceNotificationsQueue(ctx, stream.FromChannel(upstream))

	// Test that sending events in upstream does not block on unbuffered channel
	upstream <- k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc1"}}
	upstream <- k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc2"}}
	upstream <- k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc3"}}

	// Test that events are received in order
	require.Equal(t, k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc1"}}, <-downstream)
	require.Equal(t, k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc2"}}, <-downstream)
	require.Equal(t, k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc3"}}, <-downstream)
	require.Empty(t, downstream)

	// Test that Go routine exits on empty upstream if ctx is cancelled
	cancel()
	_, ok := <-downstream
	require.False(t, ok, "service notification channel was not closed on cancellation")

	// Test that Go routine exits on upstream close
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	upstream = make(chan k8s.ServiceNotification)
	downstream = serviceNotificationsQueue(ctx, stream.FromChannel(upstream))

	upstream <- k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc4"}}
	require.Equal(t, k8s.ServiceNotification{ID: k8s.ServiceID{Name: "svc4"}}, <-downstream)

	close(upstream)
	_, ok = <-downstream
	require.False(t, ok, "service notification channel was not closed on upstream close")
}
