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

// transformCRNC is a test helper that invokes the Transform closure from
// resourceNetworkConfigReflectorConfig so all branches inside it can be hit.
func transformCRNC(t *testing.T, crnc *v2alpha1.CiliumResourceNetworkConfig) (resourceNetworkConfig, bool) {
	t.Helper()
	_, cs := k8sClient.NewFakeClientset(hivetest.Logger(t))
	db := statedb.New()
	tbl, err := NewResourceNetworkConfigTable(db)
	require.NoError(t, err)
	cfg := resourceNetworkConfigReflectorConfig(cs, newTestCRDSyncPromise(), tbl)
	return cfg.Transform(nil, crnc)
}

// TestTransformCRNC_NonCRNCObject verifies that passing a non-CRNC object
// causes the Transform to return ok=false (type assertion fails).
func TestTransformCRNC_NonCRNCObject(t *testing.T) {
	_, cs := k8sClient.NewFakeClientset(hivetest.Logger(t))
	db := statedb.New()
	tbl, err := NewResourceNetworkConfigTable(db)
	require.NoError(t, err)
	cfg := resourceNetworkConfigReflectorConfig(cs, newTestCRDSyncPromise(), tbl)
	_, ok := cfg.Transform(nil, "not-a-crnc-object")
	require.False(t, ok)
}

// TestTransformCRNC_Success verifies the happy path: a well-formed
// CiliumResourceNetworkConfig is converted to a resourceNetworkConfig.
func TestTransformCRNC_Success(t *testing.T) {
	crnc := &v2alpha1.CiliumResourceNetworkConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Spec: []v2alpha1.CiliumResourceNetworkConfigSpec{
			{
				IPPool: "pool-a",
				VLAN:   100,
				IPv4: &v2alpha1.IPv4NetworkConfigSpec{
					NetMask: 24,
					StaticRoutes: []v2alpha1.IPv4StaticRouteSpec{
						{Destination: "10.0.0.0/8", Gateway: "10.0.0.1"},
					},
				},
				IPv6: &v2alpha1.IPv6NetworkConfigSpec{
					NetMask: 64,
					StaticRoutes: []v2alpha1.IPv6StaticRouteSpec{
						{Destination: "fd00::/48"},
					},
				},
			},
		},
	}

	got, ok := transformCRNC(t, crnc)
	require.True(t, ok)
	require.Equal(t, "cfg", got.Name)
	require.Len(t, got.Specs, 1)
	require.Equal(t, "pool-a", got.Specs[0].IPPool)
	require.EqualValues(t, 100, got.Specs[0].Vlan)
	require.Equal(t, 24, got.Specs[0].IPv4NetMask)
	require.Equal(t, 64, got.Specs[0].IPv6NetMask)
}

// TestTransformCRNC_NilNodeSelector verifies that a nil NodeSelector is treated
// as "match everything" without error.
func TestTransformCRNC_NilNodeSelector(t *testing.T) {
	crnc := &v2alpha1.CiliumResourceNetworkConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cfg"},
		Spec: []v2alpha1.CiliumResourceNetworkConfigSpec{
			{NodeSelector: nil, IPPool: "pool-a"},
		},
	}
	got, ok := transformCRNC(t, crnc)
	require.True(t, ok)
	require.Len(t, got.Specs, 1)
}

// TestTransformCRNC_InvalidNodeSelector verifies that a malformed label
// selector expression causes Transform to return ok=false.
func TestTransformCRNC_InvalidNodeSelector(t *testing.T) {
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
	_, ok := transformCRNC(t, crnc)
	require.False(t, ok)
}

// TestTransformCRNC_InvalidIPv4Route verifies that a bad IPv4 route destination
// causes Transform to return ok=false.
func TestTransformCRNC_InvalidIPv4Route(t *testing.T) {
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
	_, ok := transformCRNC(t, crnc)
	require.False(t, ok)
}

// TestTransformCRNC_InvalidIPv6Route verifies that a bad IPv6 route destination
// causes Transform to return ok=false.
func TestTransformCRNC_InvalidIPv6Route(t *testing.T) {
	crnc := &v2alpha1.CiliumResourceNetworkConfig{
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
	_, ok := transformCRNC(t, crnc)
	require.False(t, ok)
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

// TestTableRow verifies that TableRow produces the correct number of columns
// and that key fields appear in the specs column.
func TestTableRow(t *testing.T) {
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
}

// TestTableRow_NoVlan verifies that the vlan field is omitted when zero.
func TestTableRow_NoVlan(t *testing.T) {
	cfg := resourceNetworkConfig{
		Name: "no-vlan",
		Specs: []spec{
			{NodeSelector: labels.Everything(), IPPool: "pool-b", Vlan: 0},
		},
		UpdatedAt: time.Now(),
	}
	row := cfg.TableRow()
	require.NotContains(t, row[1], "vlan", "vlan should not appear when zero")
}

// TestTableRow_MultipleSpecs verifies that multiple specs are separated by "; ".
func TestTableRow_MultipleSpecs(t *testing.T) {
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
