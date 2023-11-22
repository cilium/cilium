// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package policy

import (
	"testing"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"

	"github.com/stretchr/testify/assert"
)

func createPolicyLabels(ns, source, name string) labels.LabelArray {
	return labels.LabelArray{
		{
			Key:    k8sConst.PolicyLabelName,
			Value:  name,
			Source: "k8s",
		},
		{
			Key:    k8sConst.PolicyLabelNamespace,
			Value:  ns,
			Source: "k8s",
		},
		{
			Key:    k8sConst.PolicyLabelDerivedFrom,
			Value:  source,
			Source: "k8s",
		},
	}
}

func createSelector(ns, source, name string, fqdn bool) CachedSelector {
	sm := selectorManager{
		metadataLbls: createPolicyLabels(ns, source, name),
	}
	if fqdn {
		return &fqdnSelector{
			selectorManager: sm,
		}
	}
	return &labelIdentitySelector{
		selectorManager: sm,
	}
}

// Test policy selector metric, which counts the number of selectors per individual policy.
// This does accounting based on a tuple that identifies a policy (i.e. namespace, name, derivedFrom).
func TestPolicySelectorMetric(t *testing.T) {
	metrics := &mockPolicyMetrics{}
	m := newSelectorMetrics(metrics)
	s1 := createSelector("default", "CiliumNetworkPolicy", "foo", false)
	s12 := createSelector("default", "CiliumNetworkPolicy", "foo", false)
	s2 := createSelector("", "CiliumClusterwideNetworkPolicy", "foo", false)
	m.updateSelector(s1, 1, true)
	m.updateSelector(s2, 10, true)
	assert.Equal(t, 1, metrics.pm["default/CiliumNetworkPolicy/foo"])
	assert.Equal(t, 10, metrics.pm["/CiliumClusterwideNetworkPolicy/foo"])
	m.updateSelector(s12, 1, true)
	assert.Equal(t, 2, metrics.pm["default/CiliumNetworkPolicy/foo"],
		"selectors with same source tuples should count towards the same metric")

	// Two different selectors where added for the same policy, so the ref count should be 2.
	assert.Equal(t, 2, m.policyToSelectorCount[policySourceIdentifier(s1)].refs)

	// Deleting one of the selectors should decrement the ref count.
	m.deleteSelector(s1, 1)
	assert.Contains(t, metrics.pm, "default/CiliumNetworkPolicy/foo", "ref count is above 0 so metric should not be deleted")
	assert.Equal(t, 1, m.policyToSelectorCount[policySourceIdentifier(s1)].refs)
	assert.Equal(t, 1, metrics.pm["default/CiliumNetworkPolicy/foo"])

	// Deleting last reference should delete the metric.
	m.deleteSelector(s12, 1)
	assert.NotContains(t, metrics.pm, "default/CiliumNetworkPolicy/foo", "ref count is 0 so metric should be deleted")

	// s2 should not have been affected
	assert.Equal(t, 10, metrics.pm["/CiliumClusterwideNetworkPolicy/foo"])
	m.deleteSelector(s2, 10)

	// s2 only had one reference, so it should be deleted.
	assert.NotContains(t, metrics.pm, "/CiliumClusterwideNetworkPolicy/foo", "ref count is 0 so metric should be deleted")
}

// TestSelectorMetric tests the selector metric, which counts the number of selectors per selector type.
func TestSelectorMetric(t *testing.T) {
	metrics := &mockPolicyMetrics{}
	m := newSelectorMetrics(metrics)

	s1 := createSelector("default", "CiliumNetworkPolicy", "foo", false) // label
	s2 := createSelector("default", "CiliumNetworkPolicy", "foo", true)  // fqdn
	m.updateSelector(s1, 1, true)
	m.updateSelector(s2, 10, false)
	assert.Equal(t, 1, metrics.ss["endpoint/CiliumNetworkPolicy"])
	assert.Equal(t, 10, metrics.ss["fqdn/CiliumNetworkPolicy"])

	m.deleteSelector(s1, 1)
	assert.Equal(t, 0, metrics.ss["endpoint/CiliumNetworkPolicy"])
	assert.Equal(t, 10, metrics.ss["fqdn/CiliumNetworkPolicy"])
	m.deleteSelector(s2, 5)
	assert.Equal(t, 5, metrics.ss["fqdn/CiliumNetworkPolicy"])
}
