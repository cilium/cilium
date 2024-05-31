// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilterdynamic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networking_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy/api"
)

type mockStore[T comparable] []T

func (m mockStore[T]) List() []T {
	return m
}

func (m mockStore[T]) IterKeys() resource.KeyIter {
	panic("implement me")
}

func (m mockStore[T]) Get(obj T) (item T, exists bool, err error) {
	panic("implement me")
}

func (m mockStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	panic("implement me")
}

func (m mockStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	panic("implement me")
}

func (m mockStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	panic("implement me")
}

func (m mockStore[T]) CacheStore() cache.Store {
	panic("implement me")
}

func (m mockStore[T]) Release() {
	panic("implement me")
}

// TestControllerSanity ensures that the controller calls the correct methods,
// with the correct arguments, during its Reconcile loop.
func TestControllerSanity(t *testing.T) {
	allLabels := map[string]string{
		"dummy_match_nps":             "dummy",
		"dummy_expression_nps":        "dummy",
		"dummy_cnps":                  "dummy",
		"dummy_cwnps":                 "dummy",
		"io.kubernetes.pod.namespace": "default",
		"excluded":                    "excluded",
	}

	var table = []struct {
		// name of test case
		name                                string
		err                                 error
		networkPolicyStore                  resource.Store[*slim_networking_v1.NetworkPolicy]
		ciliumNetworkPolicyStore            resource.Store[*cilium_v2.CiliumNetworkPolicy]
		ciliumClusterwideNetworkPolicyStore resource.Store[*cilium_v2.CiliumClusterwideNetworkPolicy]
	}{
		// test the normal control flow of a policy being selected and applied.
		{
			name: "successful reconcile",
			err:  nil,
			networkPolicyStore: mockStore[*slim_networking_v1.NetworkPolicy]{
				&slim_networking_v1.NetworkPolicy{
					TypeMeta: slim_metav1.TypeMeta{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "NetworkPolicy",
					},
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: slim_networking_v1.NetworkPolicySpec{
						PodSelector: slim_metav1.LabelSelector{
							MatchLabels: map[string]string{
								"dummy_match_nps": "bar",
							},
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{
								{
									Key:      "dummy_expression_nps",
									Operator: slim_metav1.LabelSelectorOpExists,
									Values:   []string{},
								},
							},
						},
					},
				},
				&slim_networking_v1.NetworkPolicy{
					TypeMeta: slim_metav1.TypeMeta{
						APIVersion: "networking.k8s.io/v1",
						Kind:       "NetworkPolicy",
					},
					ObjectMeta: slim_metav1.ObjectMeta{
						Name:      "test-policy-empty",
						Namespace: "test-namespace",
					},
					Spec: slim_networking_v1.NetworkPolicySpec{
						PodSelector: slim_metav1.LabelSelector{
							MatchLabels:      map[string]string{},
							MatchExpressions: []slim_metav1.LabelSelectorRequirement{},
						},
					},
				},
			},
			ciliumNetworkPolicyStore: mockStore[*cilium_v2.CiliumNetworkPolicy]{
				&cilium_v2.CiliumNetworkPolicy{
					TypeMeta: meta_v1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("dummy_cnps=bar")),
					},
				},
			},
			ciliumClusterwideNetworkPolicyStore: mockStore[*cilium_v2.CiliumClusterwideNetworkPolicy]{
				&cilium_v2.CiliumClusterwideNetworkPolicy{
					TypeMeta: meta_v1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumClusterwideNetworkPolicy",
					},
					ObjectMeta: meta_v1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("dummy_cwnps=bar")),
					},
				},
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {

			c := controller{
				NetworkPolicyStore:                  tt.networkPolicyStore,
				CiliumNetworkPolicyStore:            tt.ciliumNetworkPolicyStore,
				CiliumClusterwideNetworkPolicyStore: tt.ciliumClusterwideNetworkPolicyStore,
			}

			err := c.Reconcile(context.Background())

			allLabels := labels.Map2Labels(allLabels, labels.LabelSourceContainer)
			filtered, _ := labelsfilter.Filter(allLabels)
			assert.Equal(t, 5, len(filtered))

			if (tt.err == nil) != (err == nil) {
				t.Fatalf("want: %v, got: %v", tt.err, err)
			}
		})
	}
}

func TestComputeLabelsToRemove(t *testing.T) {
	expectedLabelsToAdd := labels.Labels{
		"foo2": {Key: "foo2", Value: "bar", Source: labels.LabelSourceK8s},
	}
	expectedLabelsToRemove := labels.Labels{
		"dummy":    {Key: "dummy", Value: "bar", Source: labels.LabelSourceK8s},
		"dummy2":   {Key: "dummy2", Value: "bar", Source: labels.LabelSourceK8s},
		"dummy3":   {Key: "dummy3", Value: "bar", Source: labels.LabelSourceAny},
		"no_value": {Key: "no_value", Value: "", Source: labels.LabelSourceK8s},
	}
	endpointLabels := []string{
		"k8s:dummy=bar", "k8s:dummy2=bar", "k8s:no_value", "any:dummy3=bar",
		"k8s:foo=bar",
		":foo3=bar",
		"unspec:foo4=bar",
	}
	identityLabels := labels.Labels{
		"foo":  {Key: "foo", Value: "bar", Source: labels.LabelSourceK8s},
		"foo2": {Key: "foo2", Value: "bar", Source: labels.LabelSourceK8s},
		"foo3": {Key: "foo3", Value: "bar", Source: labels.LabelSourceUnspec},
		"foo4": {Key: "foo4", Value: "bar", Source: labels.LabelSourceUnspec},
	}

	labelsToAdd, labelsToRemove := computeLabelsToAddAndRemove(identityLabels, endpointLabels)
	assert.Equal(t, expectedLabelsToAdd, labelsToAdd)
	assert.Equal(t, expectedLabelsToRemove, labelsToRemove)
}

func TestMergeAllExistingLabels(t *testing.T) {
	expectedLabels := labels.Labels{
		"pod_label":  {Key: "pod_label", Value: "bar", Source: labels.LabelSourceK8s},
		"pod2_label": {Key: "pod2_label", Value: "bar", Source: labels.LabelSourceK8s},
		"pod3_label": {Key: "pod3_label", Value: "bar", Source: labels.LabelSourceK8s},

		"ep_label":  {Key: "ep_label", Value: "bar", Source: labels.LabelSourceK8s},
		"ep2_label": {Key: "ep2_label", Value: "bar", Source: labels.LabelSourceAny},
		"ep3_label": {Key: "ep3_label", Value: "bar", Source: labels.LabelSourceUnspec},

		"io.cilium.k8s.namespace.labels.ns_label": {Key: "io.cilium.k8s.namespace.labels.ns_label", Value: "bar", Source: labels.LabelSourceK8s},
	}

	podLabels := map[string]string{
		"k8s:pod_label": "bar", "any:pod2_label": "bar", ":pod3_label": "bar",
	}
	endpointLabels := []string{
		"k8s:ep_label=bar", "any:ep2_label=bar", ":ep3_label=bar",
	}
	nsLabels := map[string]string{
		"ns_label": "bar",
	}

	assert.Equal(t, expectedLabels, mergeAllExistingLabels(podLabels, endpointLabels, nsLabels))
}

func TestGetRelevantKeyLabels(t *testing.T) {
	matchLabels := map[string]slim_metav1.MatchLabelsValue{
		"Foo":        "dummy",
		"MatchLabel": "dummy",
	}
	matchExpressionLabels := []slim_metav1.LabelSelectorRequirement{
		{Key: "Foo", Operator: "", Values: []string{"", ""}},
		{Key: "Bar", Operator: "", Values: []string{"", ""}},
	}
	expectedLabels := sets.New[string]("Foo", "Bar", "MatchLabel")

	assert.Equal(t, expectedLabels, getRelevantKeyLabels(matchLabels, matchExpressionLabels))
}

func TestNormalizeKeyLabel(t *testing.T) {
	assert.Equal(t, ":Foo", normalizeKeyLabel("any.Foo"))
	assert.Equal(t, "k8s:Foo", normalizeKeyLabel("k8s.Foo"))
	assert.Equal(t, "other_sources:foo", normalizeKeyLabel("other_sources.foo"))
}
