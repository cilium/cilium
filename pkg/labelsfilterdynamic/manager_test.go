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
