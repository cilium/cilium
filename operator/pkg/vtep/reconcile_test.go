// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func ep(name, cidr, tunnel, mac string) v2alpha1.VTEPEndpoint {
	return v2alpha1.VTEPEndpoint{Name: name, CIDR: cidr, TunnelEndpoint: tunnel, MAC: mac}
}

func cfg(name string, sel *slimv1.LabelSelector, uid string, eps ...v2alpha1.VTEPEndpoint) *v2alpha1.CiliumVTEPConfig {
	return &v2alpha1.CiliumVTEPConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)},
		Spec: v2alpha1.CiliumVTEPConfigSpec{
			NodeSelector:  sel,
			VTEPEndpoints: eps,
		},
	}
}

func zoneSelector(zone string) *slimv1.LabelSelector {
	return &slimv1.LabelSelector{MatchLabels: map[string]string{"topology.kubernetes.io/zone": zone}}
}

func TestResolveNode_NilSelectorMatchesAll(t *testing.T) {
	c := cfg("global", nil, "uid-global", ep("gw", "10.1.1.0/24", "10.100.0.1", "aa:bb:cc:dd:ee:01"))
	res := resolveNode("node-1", map[string]string{"zone": "a"}, []*v2alpha1.CiliumVTEPConfig{c}, slog.Default())
	require.NotNil(t, res)
	assert.Len(t, res.endpoints, 1)
	assert.Contains(t, res.endpoints, "10.1.1.0/24")
}

func TestResolveNode_NonMatchingSelector(t *testing.T) {
	c := cfg("zone-a", zoneSelector("zone-a"), "uid-a", ep("gw", "10.1.1.0/24", "10.100.0.1", "aa:bb:cc:dd:ee:01"))
	res := resolveNode("node-1", map[string]string{"topology.kubernetes.io/zone": "zone-b"}, []*v2alpha1.CiliumVTEPConfig{c}, slog.Default())
	assert.Nil(t, res, "node not matching any config should resolve to nil")
}

func TestResolveNode_MatchingSelector(t *testing.T) {
	c := cfg("zone-a", zoneSelector("zone-a"), "uid-a", ep("gw-a", "10.1.5.0/24", "10.100.1.1", "aa:bb:cc:dd:ee:01"))
	res := resolveNode("worker-a", map[string]string{"topology.kubernetes.io/zone": "zone-a"}, []*v2alpha1.CiliumVTEPConfig{c}, slog.Default())
	require.NotNil(t, res)
	require.Len(t, res.endpoints, 1)
	assert.Equal(t, "10.100.1.1", res.endpoints["10.1.5.0/24"].TunnelEndpoint)
	require.Len(t, res.owners, 1)
	assert.Equal(t, "zone-a", res.owners[0].Name)
}

func TestResolveNode_CIDRConflictDropsEndpoint(t *testing.T) {
	// Two matching configs declare the same CIDR -> neither applied.
	a := cfg("config-a", nil, "uid-a", ep("gw-a", "10.200.0.0/16", "10.100.1.1", "aa:bb:cc:00:01:01"))
	b := cfg("config-b", nil, "uid-b", ep("gw-b", "10.200.0.0/16", "10.100.2.1", "aa:bb:cc:00:02:01"))
	res := resolveNode("node-1", nil, []*v2alpha1.CiliumVTEPConfig{a, b}, slog.Default())
	require.NotNil(t, res)
	assert.Empty(t, res.endpoints, "conflicting CIDR must be dropped from both configs")
	assert.True(t, res.conflicts.Has("10.200.0.0/16"))
	assert.Len(t, res.owners, 2, "both configs still own the node")
}

func TestResolveNode_ConflictDoesNotDropOtherCIDRs(t *testing.T) {
	a := cfg("config-a", nil, "uid-a",
		ep("gw-a", "10.200.0.0/16", "10.100.1.1", "aa:bb:cc:00:01:01"),
		ep("uniq-a", "10.1.0.0/24", "10.100.1.2", "aa:bb:cc:00:01:02"))
	b := cfg("config-b", nil, "uid-b",
		ep("gw-b", "10.200.0.0/16", "10.100.2.1", "aa:bb:cc:00:02:01"),
		ep("uniq-b", "10.2.0.0/24", "10.100.2.2", "aa:bb:cc:00:02:02"))
	res := resolveNode("node-1", nil, []*v2alpha1.CiliumVTEPConfig{a, b}, slog.Default())
	require.NotNil(t, res)
	assert.NotContains(t, res.endpoints, "10.200.0.0/16", "conflicting CIDR dropped")
	assert.Contains(t, res.endpoints, "10.1.0.0/24", "non-conflicting CIDR from config-a kept")
	assert.Contains(t, res.endpoints, "10.2.0.0/24", "non-conflicting CIDR from config-b kept")
}

func TestResolveNode_MultiConfigAggregation(t *testing.T) {
	a := cfg("config-a", zoneSelector("zone-a"), "uid-a", ep("gw-a", "10.1.0.0/24", "10.100.1.1", "aa:bb:cc:00:01:01"))
	b := cfg("config-b", nil, "uid-b", ep("gw-global", "10.9.0.0/24", "10.100.9.1", "aa:bb:cc:00:09:01"))
	res := resolveNode("worker-a", map[string]string{"topology.kubernetes.io/zone": "zone-a"},
		[]*v2alpha1.CiliumVTEPConfig{a, b}, slog.Default())
	require.NotNil(t, res)
	assert.Len(t, res.endpoints, 2, "endpoints from both matching configs are aggregated")
}

// TestSelectorForConfig_InvalidSelectorErrors locks in the contract behind the
// fail-closed GC fix: a malformed nodeSelector (admitted because nodeSelector has no CEL
// validation) must surface as an error from selectorForConfig, so reconcile() detects it
// and skips the node-config GC sweep instead of tearing down VTEP state.
func TestSelectorForConfig_InvalidSelectorErrors(t *testing.T) {
	c := &v2alpha1.CiliumVTEPConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "bad"},
		Spec: v2alpha1.CiliumVTEPConfigSpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{
					{Key: "zone", Operator: slimv1.LabelSelectorOperator("NotAValidOperator"), Values: []string{"a"}},
				},
			},
		},
	}
	_, err := selectorForConfig(c)
	assert.Error(t, err, "malformed nodeSelector must error so reconcile() fails closed (skips GC)")
}

func TestNormalizeCIDR(t *testing.T) {
	got, err := normalizeCIDR("10.1.1.5/24")
	require.NoError(t, err)
	assert.Equal(t, "10.1.1.0/24", got, "host bits should be normalized")

	_, err = normalizeCIDR("not-a-cidr")
	assert.Error(t, err)
}

func TestSortedEndpoints(t *testing.T) {
	m := map[string]v2alpha1.VTEPEndpoint{
		"10.3.0.0/24": ep("c", "10.3.0.0/24", "1.1.1.3", "aa:bb:cc:dd:ee:03"),
		"10.1.0.0/24": ep("a", "10.1.0.0/24", "1.1.1.1", "aa:bb:cc:dd:ee:01"),
		"10.2.0.0/24": ep("b", "10.2.0.0/24", "1.1.1.2", "aa:bb:cc:dd:ee:02"),
	}
	out := sortedEndpoints(m)
	require.Len(t, out, 3)
	assert.Equal(t, "a", out[0].Name)
	assert.Equal(t, "b", out[1].Name)
	assert.Equal(t, "c", out[2].Name)
}

func TestOwnerReferences(t *testing.T) {
	a := cfg("config-a", nil, "uid-a")
	b := cfg("config-b", nil, "uid-b")
	dup := cfg("config-a", nil, "uid-a")
	refs := ownerReferences([]*v2alpha1.CiliumVTEPConfig{b, a, dup})
	require.Len(t, refs, 2, "duplicate UIDs are deduplicated")
	// Sorted by name.
	assert.Equal(t, "config-a", refs[0].Name)
	assert.Equal(t, "config-b", refs[1].Name)
	assert.Equal(t, v2alpha1.CVTEPKindDefinition, refs[0].Kind)
	assert.Equal(t, v2alpha1.SchemeGroupVersion.String(), refs[0].APIVersion)
}

func TestOwnerRefsEqual(t *testing.T) {
	x := []metav1.OwnerReference{{Name: "a", UID: "1"}, {Name: "b", UID: "2"}}
	y := []metav1.OwnerReference{{Name: "b", UID: "2"}, {Name: "a", UID: "1"}}
	z := []metav1.OwnerReference{{Name: "a", UID: "1"}}
	assert.True(t, ownerRefsEqual(x, y), "order-insensitive equality")
	assert.False(t, ownerRefsEqual(x, z))
}
