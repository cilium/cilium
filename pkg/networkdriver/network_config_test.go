// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// newTestCRDSyncPromise returns a promise that is already resolved, for use in tests
// that call resourceNetworkConfigReflectorConfig.
func newTestCRDSyncPromise() promise.Promise[synced.CRDSync] {
	resolver, p := promise.New[synced.CRDSync]()
	resolver.Resolve(synced.CRDSync{})
	return p
}

func TestTransformCRNC(t *testing.T) {
	t.Run("test transform network config invalid", func(t *testing.T) {
		// verifies that passing a non-CRNC object
		// causes the Transform to return ok=false (type assertion fails).
		_, ok := toResourceNetworkConfig(nil, "not-a-crnc-object")
		require.False(t, ok)
	})

	t.Run("test transform network config nil selector", func(t *testing.T) {
		crnc := &v2alpha1.CiliumResourceNetworkConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
			Spec: []v2alpha1.CiliumResourceNetworkConfigSpec{
				{NodeSelector: nil, IPPool: "pool-a"},
			},
		}
		got, ok := toResourceNetworkConfig(nil, crnc)
		require.True(t, ok)
		require.Len(t, got.Specs, 1)
		require.Equal(t, labels.Everything(), got.Specs[0].NodeSelector)
	})

	t.Run("test transform network config invalid selector", func(t *testing.T) {
		crnc := &v2alpha1.CiliumResourceNetworkConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
			Spec: []v2alpha1.CiliumResourceNetworkConfigSpec{
				{
					NodeSelector: &slimv1.LabelSelector{
						MatchExpressions: []slimv1.LabelSelectorRequirement{
							{
								Key:      "k",
								Operator: "InvalidOp", // not In/NotIn/Exists/DoesNotExist
								Values:   []string{"v"},
							},
						},
					},
				},
			},
		}
		_, ok := toResourceNetworkConfig(nil, crnc)
		require.False(t, ok)
	})

	t.Run("test transform invalid routes", func(t *testing.T) {
		crnc := &v2alpha1.CiliumResourceNetworkConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
			Spec: []v2alpha1.CiliumResourceNetworkConfigSpec{
				{
					IPv4: &v2alpha1.IPv4NetworkConfigSpec{
						StaticRoutes: []v2alpha1.IPv4StaticRouteSpec{
							{Destination: "not-a-cidr"},
						},
					},
				},
			},
		}
		_, ok := toResourceNetworkConfig(nil, crnc)
		require.False(t, ok)

		crnc = &v2alpha1.CiliumResourceNetworkConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
			Spec: []v2alpha1.CiliumResourceNetworkConfigSpec{
				{
					IPv6: &v2alpha1.IPv6NetworkConfigSpec{
						StaticRoutes: []v2alpha1.IPv6StaticRouteSpec{
							{Destination: "not-a-cidr"},
						},
					},
				},
			},
		}
		_, ok = toResourceNetworkConfig(nil, crnc)
		require.False(t, ok)
	})
}

// TestParseRoute verifies parseRoute handles all combinations correctly.
func TestParseRoute(t *testing.T) {
	t.Run("valid destination with gateway", func(t *testing.T) {
		r, err := parseRoute("10.0.0.0/8", "10.0.0.1")
		require.NoError(t, err)
		require.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), r.Destination)
		require.Equal(t, netip.MustParseAddr("10.0.0.1"), r.Gateway)
	})

	t.Run("valid destination without gateway", func(t *testing.T) {
		r, err := parseRoute("10.0.0.0/8", "")
		require.NoError(t, err)
		require.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), r.Destination)
		require.False(t, r.Gateway.IsValid())
	})

	t.Run("invalid destination", func(t *testing.T) {
		_, err := parseRoute("not-a-cidr", "")
		require.Error(t, err)
	})

	t.Run("invalid gateway", func(t *testing.T) {
		_, err := parseRoute("10.0.0.0/8", "not-an-ip")
		require.Error(t, err)
	})
}

func TestTableRow(t *testing.T) {
	t.Run("test tablerow rows", func(t *testing.T) {
		sel := labels.Everything()

		cfg := resourceNetworkConfig{
			Name: "test-config",
			Specs: []spec{
				{
					NodeSelector: sel,
					IPPool:       "pool-a",
					Vlan:         42,
					IPv4NetMask:  24,
					IPv4Routes: []route{
						{Destination: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("10.0.0.1")},
						{Destination: netip.MustParsePrefix("192.168.0.0/16")},
					},
					IPv6NetMask: 64,
					IPv6Routes: []route{
						{Destination: netip.MustParsePrefix("fd00::/48")},
					},
				},
			},
			UpdatedAt: time.Now().Add(-5 * time.Minute),
		}

		row := cfg.TableRow()
		require.Len(t, row, 3, "TableRow must return exactly 3 columns")
		require.Equal(t, "test-config", row[0])
		require.Contains(t, row[1], "pool-a", "specs column should mention pool name")
		require.Contains(t, row[1], "vlan 42", "specs column should mention vlan")
		require.Contains(t, row[1], "10.0.0.0/8", "specs column should include ipv4 route")
		require.Contains(t, row[1], "via 10.0.0.1", "specs column should include gateway")
		require.Contains(t, row[1], "fd00::/48", "specs column should include ipv6 route")
		require.NotEmpty(t, row[2], "age column should not be empty")
	})

	t.Run("test tablerow no vlan", func(t *testing.T) {
		cfg := resourceNetworkConfig{
			Name: "no-vlan",
			Specs: []spec{
				{NodeSelector: labels.Everything(), IPPool: "pool-b", Vlan: 0},
			},
			UpdatedAt: time.Now(),
		}
		row := cfg.TableRow()
		require.NotContains(t, row[1], "vlan", "vlan should not appear when zero")
	})

	t.Run("test tablerow multiple specs with separator", func(t *testing.T) {
		cfg := resourceNetworkConfig{
			Name: "multi",
			Specs: []spec{
				{NodeSelector: labels.Everything(), IPPool: "pool-a"},
				{NodeSelector: labels.Everything(), IPPool: "pool-b"},
			},
			UpdatedAt: time.Now(),
		}
		row := cfg.TableRow()
		require.Contains(t, row[1], "; ", "multiple specs should be separated by \"; \"")
	})
}

// TestNewResourceNetworkConfigTableAndReflector_Disabled verifies that the
// function returns nil when the network driver feature is disabled.
func TestNewResourceNetworkConfigTableAndReflector_Disabled(t *testing.T) {
	_, cs := k8sClient.NewFakeClientset(hivetest.Logger(t))
	db := statedb.New()
	tbl, err := newResourceNetworkConfigTableAndReflector(
		nil, db, cs,
		newTestCRDSyncPromise(),
		&option.DaemonConfig{EnableCiliumNetworkDriver: false},
	)
	require.NoError(t, err)
	require.Nil(t, tbl)
}
