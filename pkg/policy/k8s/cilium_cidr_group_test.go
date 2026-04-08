// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"log/slog"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// Two CCGs with the same label key but different values on a shared CIDR.
func TestCIDRGroupDuplicateLabelKeys(t *testing.T) {
	pw := &policyWatcher{
		log: slog.Default(),
		cidrGroupCache: map[string]*cilium_v2.CiliumCIDRGroup{
			"app-bar": {
				ObjectMeta: metav1.ObjectMeta{
					Name:   "app-bar",
					Labels: map[string]string{"app": "bar"},
				},
				Spec: cilium_v2.CiliumCIDRGroupSpec{
					ExternalCIDRs: []api.CIDR{"10.48.0.0/24"},
				},
			},
			"app-foo": {
				ObjectMeta: metav1.ObjectMeta{
					Name:   "app-foo",
					Labels: map[string]string{"app": "foo"},
				},
				Spec: cilium_v2.CiliumCIDRGroupSpec{
					ExternalCIDRs: []api.CIDR{"10.48.0.0/24"},
				},
			},
		},
	}

	_, lblsBar := pw.cidrsAndLabelsForCIDRGroup("app-bar")
	_, lblsFoo := pw.cidrsAndLabelsForCIDRGroup("app-foo")

	// Simulate ipcache label merge: labels from different resources for the
	// same prefix are unioned into one Labels map. maps.Copy uses last-write-wins,
	// so if both CCGs produced the same map key, one label is silently dropped.
	merged := maps.Clone(lblsBar)
	maps.Copy(merged, lblsFoo)

	arr := merged.LabelArray()

	barSelector := policyTypes.ToSelector(api.CIDRRule{
		CIDRGroupSelector: api.EndpointSelector{
			LabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "bar"},
			},
		},
	})
	fooSelector := policyTypes.ToSelector(api.CIDRRule{
		CIDRGroupSelector: api.EndpointSelector{
			LabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "foo"},
			},
		},
	})

	assert.True(t, barSelector.Matches(arr),
		"CIDRGroupSelector app=bar must match after merge; labels: %v", arr)
	assert.True(t, fooSelector.Matches(arr),
		"CIDRGroupSelector app=foo must match after merge; labels: %v", arr)
}
