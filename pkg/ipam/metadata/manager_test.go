// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/ipam"
	consts "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sresource "github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func selectorFromLabels(labels map[string]string) slim_labels.Selector {
	sel, _ := slim_meta_v1.LabelSelectorAsSelector(&slim_meta_v1.LabelSelector{MatchLabels: labels})
	return sel
}

func TestManager_GetIPPoolForPod(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err, "NewPodTable")
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err, "NewNamespaceTable")
	m := &manager{
		logger:      hivetest.Logger(t),
		db:          db,
		namespaces:  namespaces,
		pods:        pods,
		poolsSynced: atomic.Bool{},
	}
	m.poolsSynced.Store(true)

	txn := db.WriteTxn(pods, namespaces)
	newPod := func(namespace, name string, annotations map[string]string) k8s.LocalPod {
		return k8s.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Namespace:   namespace,
				Name:        name,
				Annotations: annotations,
			},
		}}
	}
	pods.Insert(txn, newPod("default", "client", nil))
	pods.Insert(txn, newPod("default", "custom-workload",
		map[string]string{
			annotation.IPAMPoolKey: "custom-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload2",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload3",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
			annotation.IPAMPoolKey:     "custom-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload4",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
			annotation.IPAMIPv6PoolKey: "ipv6-pool",
		}))
	pods.Insert(txn, newPod("default", "custom-workload5",
		map[string]string{
			annotation.IPAMIPv4PoolKey: "ipv4-pool",
			annotation.IPAMIPv6PoolKey: "ipv6-pool",
			annotation.IPAMPoolKey:     "custom-pool",
		}))

	pods.Insert(txn, newPod("special", "server", nil))
	pods.Insert(txn, newPod("special", "server2",
		map[string]string{
			annotation.IPAMPoolKey: "pod-pool",
		}))
	pods.Insert(txn, newPod("missing-ns", "pod", nil))

	namespaces.Insert(
		txn,
		k8s.Namespace{
			Name: "default",
		})
	namespaces.Insert(
		txn,
		k8s.Namespace{
			Name: "special",
			Annotations: map[string]string{
				annotation.IPAMPoolKey: "namespace-pool",
			},
		})

	txn.Commit()

	tests := []struct {
		name     string
		owner    string
		ipfamily ipam.Family
		wantPool string
		wantErr  error
	}{
		{
			name:     "no annotations",
			owner:    "default/client",
			ipfamily: ipam.IPv4,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "not a pod name",
			owner:    "router",
			ipfamily: ipam.IPv4,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "also not a pod name (due to underline)",
			owner:    "default/xwing_net2",
			ipfamily: ipam.IPv4,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "pod annotation",
			owner:    "default/custom-workload",
			ipfamily: ipam.IPv4,
			wantPool: "custom-pool",
		},
		{
			name:     "pod annotation only ipv4 pool request ipv4",
			owner:    "default/custom-workload2",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation only ipv4 pool request ipv6",
			owner:    "default/custom-workload2",
			ipfamily: ipam.IPv6,
			wantPool: ipam.PoolDefault().String(),
		},
		{
			name:     "pod annotation ipv4 and custom pool request ipv4",
			owner:    "default/custom-workload3",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation ipv4 and custom pool request ipv6",
			owner:    "default/custom-workload3",
			ipfamily: ipam.IPv6,
			wantPool: "custom-pool",
		},
		{
			name:     "pod annotation ipv4 and ipv6 pool request ipv4",
			owner:    "default/custom-workload4",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation ipv4 and ipv6 pool request ipv6",
			owner:    "default/custom-workload4",
			ipfamily: ipam.IPv6,
			wantPool: "ipv6-pool",
		},
		{
			name:     "pod annotation ipv4, ipv6 and custom pool request ipv4",
			owner:    "default/custom-workload3",
			ipfamily: ipam.IPv4,
			wantPool: "ipv4-pool",
		},
		{
			name:     "pod annotation ipv4, ipv6 and custom pool request ipv6",
			owner:    "default/custom-workload5",
			ipfamily: ipam.IPv6,
			wantPool: "ipv6-pool",
		},
		{
			name:     "missing pod",
			owner:    "does-not/exist",
			ipfamily: ipam.IPv4,
			wantErr:  &ResourceNotFound{Resource: "Pod"},
		},
		{
			name:     "missing namespace",
			owner:    "missing-ns/pod",
			ipfamily: ipam.IPv4,
			wantErr:  &ResourceNotFound{Resource: "Namespace"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPool, err := m.GetIPPoolForPod(tt.owner, tt.ipfamily)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetIPPoolForPod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPool != tt.wantPool {
				t.Errorf("GetIPPoolForPod() gotPool = %v, want %v", gotPool, tt.wantPool)
			}
		})
	}
}

func TestManager_handlePoolEvent_UpsertAndDelete(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)

	m := &manager{
		logger:        hivetest.Logger(t),
		db:            db,
		namespaces:    namespaces,
		pods:          pods,
		poolsSynced:   atomic.Bool{},
		compiledPools: map[string]compiledPool{},
	}

	ctx := t.Context()

	// Create ipv4 pool with selector
	p1 := &v2alpha1api.CiliumPodIPPool{
		ObjectMeta: v1.ObjectMeta{Name: "p1"},
		Spec: v2alpha1api.IPPoolSpec{
			IPv4:        &v2alpha1api.IPv4PoolSpec{},
			PodSelector: &slim_meta_v1.LabelSelector{MatchLabels: map[string]string{"team": "blue"}},
		},
	}
	// poolsSynced is false, should not compile pool
	_, err = m.GetIPPoolForPod("p1", ipam.IPv4)
	require.ErrorIs(t, err, ErrManagerPoolsNotSynced)
	err = m.handlePoolEvent(ctx, k8sresource.Event[*v2alpha1api.CiliumPodIPPool]{Kind: k8sresource.Sync, Object: p1, Done: func(error) {}})
	require.NoError(t, err)
	// pool should be marked as synced now
	pool, err := m.GetIPPoolForPod("p1", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, "default", pool)

	err = m.handlePoolEvent(ctx, k8sresource.Event[*v2alpha1api.CiliumPodIPPool]{Kind: k8sresource.Upsert, Object: p1, Done: func(error) {}})
	require.NoError(t, err)
	cp, ok := m.getCompiledPool("p1")
	require.True(t, ok, "p1 should be present in compiledPools")
	require.True(t, cp.hasV4)
	require.False(t, cp.hasV6)
	require.NotNil(t, cp.podSelector)

	// remove selector
	p1NoSel := &v2alpha1api.CiliumPodIPPool{ObjectMeta: v1.ObjectMeta{Name: "p1"}, Spec: v2alpha1api.IPPoolSpec{IPv4: &v2alpha1api.IPv4PoolSpec{}}}
	err = m.handlePoolEvent(ctx, k8sresource.Event[*v2alpha1api.CiliumPodIPPool]{Kind: k8sresource.Upsert, Object: p1NoSel, Done: func(error) {}})
	require.NoError(t, err)
	_, exists := m.getCompiledPool("p1")
	require.False(t, exists, "p1 should have been removed from compiledPools")

	// add it back and delete it again
	err = m.handlePoolEvent(ctx, k8sresource.Event[*v2alpha1api.CiliumPodIPPool]{Kind: k8sresource.Upsert, Object: p1, Done: func(error) {}})
	require.NoError(t, err)
	cp, ok = m.getCompiledPool("p1")
	require.True(t, ok, "p1 should be added back to compiledPools")

	err = m.handlePoolEvent(ctx, k8sresource.Event[*v2alpha1api.CiliumPodIPPool]{Kind: k8sresource.Delete, Object: p1, Done: func(error) {}})
	require.NoError(t, err)
	_, exists = m.getCompiledPool("p1")
	require.False(t, exists, "p1 should have been removed from compiledPools")
}

func TestManager_handlePoolEvent_BadSelectorIgnored(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)

	m := &manager{
		logger:        hivetest.Logger(t),
		db:            db,
		namespaces:    namespaces,
		pods:          pods,
		compiledPools: make(map[string]compiledPool),
	}
	m.poolsSynced.Store(true)

	ctx := context.Background()

	// selector with In operator and empty value
	badSel := &slim_meta_v1.LabelSelector{
		MatchExpressions: []slim_meta_v1.LabelSelectorRequirement{{
			Key:      "k",
			Operator: slim_meta_v1.LabelSelectorOpIn,
			Values:   []string{},
		}},
	}
	bad := &v2alpha1api.CiliumPodIPPool{
		ObjectMeta: v1.ObjectMeta{Name: "bad"},
		Spec: v2alpha1api.IPPoolSpec{
			IPv4:        &v2alpha1api.IPv4PoolSpec{},
			PodSelector: badSel,
		},
	}

	done := func(err error) {
		require.NoError(t, err, "handlePoolEvent should not return errors")
	}

	err = m.handlePoolEvent(ctx, k8sresource.Event[*v2alpha1api.CiliumPodIPPool]{Kind: k8sresource.Upsert, Object: bad, Done: done})
	require.NoError(t, err)

	// bad selector should be ignored and not compiled
	_, ok := m.getCompiledPool("bad")
	require.False(t, ok, "bad selector should be ignored and not compiled")

	// bad namespace selector should also trigger error via Done and not be compiled
	badNsSel := &slim_meta_v1.LabelSelector{
		MatchExpressions: []slim_meta_v1.LabelSelectorRequirement{{
			Key:      "ns-k",
			Operator: slim_meta_v1.LabelSelectorOpIn,
			Values:   []string{},
		}},
	}
	badNS := &v2alpha1api.CiliumPodIPPool{
		ObjectMeta: v1.ObjectMeta{Name: "bad-ns"},
		Spec: v2alpha1api.IPPoolSpec{
			IPv4:              &v2alpha1api.IPv4PoolSpec{},
			NamespaceSelector: badNsSel,
		},
	}
	err = m.handlePoolEvent(ctx, k8sresource.Event[*v2alpha1api.CiliumPodIPPool]{Kind: k8sresource.Upsert, Object: badNS, Done: done})
	require.NoError(t, err)
	_, ok = m.getCompiledPool("bad-ns")
	require.False(t, ok, "bad namespace selector should be ignored and not compiled")
}

func TestManager_SelectorBasedMatching(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)

	m := &manager{
		logger:        hivetest.Logger(t),
		db:            db,
		namespaces:    namespaces,
		pods:          pods,
		compiledPools: make(map[string]compiledPool),
	}
	m.poolsSynced.Store(true)

	txn := db.WriteTxn(pods, namespaces)

	pods.Insert(txn, k8s.LocalPod{Pod: &slim_core_v1.Pod{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace: "namespace",
			Name:      "pod",
			Labels: map[string]string{
				"app": "foo",
			},
		},
	}})
	namespaces.Insert(txn, k8s.Namespace{Name: "namespace"})
	txn.Commit()

	selSynthetic, err := slim_meta_v1.LabelSelectorAsSelector(&slim_meta_v1.LabelSelector{
		MatchLabels: map[string]string{
			consts.PodNamespaceLabel: "namespace",
			consts.PodNameLabel:      "pod",
		},
	})
	require.NoError(t, err)

	m.compiledPools = map[string]compiledPool{
		"pool-v4": {name: "poolv4", podSelector: selectorFromLabels(map[string]string{"app": "foo"}), hasV4: true, hasV6: false},
		"pool-v6": {name: "poolv6", podSelector: selectorFromLabels(map[string]string{"app": "foo"}), hasV4: false, hasV6: true},
	}

	pool, err := m.GetIPPoolForPod("namespace/pod", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, "poolv4", pool)

	pool, err = m.GetIPPoolForPod("namespace/pod", ipam.IPv6)
	require.NoError(t, err)
	require.Equal(t, "poolv6", pool)

	m.compiledPools = map[string]compiledPool{
		"pool-syn": {name: "pool-syn", podSelector: selSynthetic, hasV4: true, hasV6: true},
	}

	pool, err = m.GetIPPoolForPod("namespace/pod", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, "pool-syn", pool)
}

func TestManager_SelectorMultipleMatches_Error(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)

	m := &manager{
		logger:     hivetest.Logger(t),
		db:         db,
		namespaces: namespaces,
		pods:       pods,
	}
	m.poolsSynced.Store(true)

	txn := db.WriteTxn(pods, namespaces)
	pods.Insert(txn, k8s.LocalPod{Pod: &slim_core_v1.Pod{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace: "namespace",
			Name:      "pod",
			Labels:    map[string]string{"team": "blue"},
		},
	}})
	namespaces.Insert(txn, k8s.Namespace{Name: "namespace"})
	txn.Commit()

	m.compiledPools = map[string]compiledPool{
		"p1": {name: "p1", podSelector: selectorFromLabels(map[string]string{"team": "blue"}), hasV4: true, hasV6: false},
		"p2": {name: "p2", podSelector: selectorFromLabels(map[string]string{"team": "blue"}), hasV4: true, hasV6: false},
	}

	// Verify pools are configured
	poolCount := len(m.compiledPools)
	require.Equal(t, 2, poolCount, "should have 2 pools configured")

	pool, err := m.GetIPPoolForPod("namespace/pod", ipam.IPv4)
	require.Error(t, err)
	require.Empty(t, pool)
	require.Contains(t, err.Error(), "multiple CiliumPodIPPools match")
}

func TestManager_PodAnnotationOverridesSelector(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)

	m := &manager{
		logger:     hivetest.Logger(t),
		db:         db,
		namespaces: namespaces,
		pods:       pods,
	}
	m.poolsSynced.Store(true)

	txn := db.WriteTxn(pods, namespaces)
	pods.Insert(txn, k8s.LocalPod{Pod: &slim_core_v1.Pod{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace:   "namespace",
			Name:        "pod",
			Labels:      map[string]string{"team": "red"},
			Annotations: map[string]string{annotation.IPAMPoolKey: "annot-pool"},
		},
	}})
	namespaces.Insert(txn, k8s.Namespace{Name: "namespace"})
	txn.Commit()

	// selector matches but superceded by annotation
	selRed, err := slim_meta_v1.LabelSelectorAsSelector(&slim_meta_v1.LabelSelector{MatchLabels: map[string]string{"team": "red"}})
	require.NoError(t, err)
	m.compiledPools = map[string]compiledPool{
		"selector-pool": {name: "selector-pool", podSelector: selRed, hasV4: true, hasV6: true},
	}

	pool, err := m.GetIPPoolForPod("namespace/pod", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, "annot-pool", pool)
}

func TestManager_NamespaceAnnotationOverridesSelector(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)

	m := &manager{
		logger:     hivetest.Logger(t),
		db:         db,
		namespaces: namespaces,
		pods:       pods,
	}
	m.poolsSynced.Store(true)

	txn := db.WriteTxn(pods, namespaces)
	pods.Insert(txn, k8s.LocalPod{Pod: &slim_core_v1.Pod{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace: "namespace", Name: "pod",
			Labels: map[string]string{"tier": "backend"},
		},
	}})
	namespaces.Insert(txn, k8s.Namespace{
		Name:        "namespace",
		Annotations: map[string]string{annotation.IPAMPoolKey: "ns-pool"},
	})
	txn.Commit()

	// selector matches but superceded by namespace annotation
	selBackend, err := slim_meta_v1.LabelSelectorAsSelector(&slim_meta_v1.LabelSelector{MatchLabels: map[string]string{"tier": "backend"}})
	require.NoError(t, err)
	m.compiledPools = map[string]compiledPool{
		"green-pool": {name: "green-pool", podSelector: selBackend, hasV4: true, hasV6: true},
	}

	pool, err := m.GetIPPoolForPod("namespace/pod", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, "ns-pool", pool)
}

func TestManager_NoSelectorNoMatch(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)
	m := &manager{
		logger:     hivetest.Logger(t),
		db:         db,
		namespaces: namespaces,
		pods:       pods,
	}
	m.poolsSynced.Store(true)

	m.compiledPools = map[string]compiledPool{
		"nomatch": {name: "nomatch", podSelector: selectorFromLabels(map[string]string{"team": "nomatch"}), hasV4: true, hasV6: true},
	}

	// Add pod and namespace
	pod := k8s.LocalPod{Pod: &slim_core_v1.Pod{
		ObjectMeta: slim_meta_v1.ObjectMeta{Name: "test", Namespace: "namespace", Labels: map[string]string{"tier": "backend"}},
	}}
	ns := k8s.Namespace{Name: "namespace"}
	txn := db.WriteTxn(pods, namespaces)
	pods.Insert(txn, pod)
	namespaces.Insert(txn, ns)
	txn.Commit()

	// Should fall back to default
	pool, err := m.GetIPPoolForPod("namespace/test", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, "default", pool)
}

func TestManager_RequirePoolMatchAnnotation(t *testing.T) {
	db := statedb.New()
	pods, err := k8s.NewPodTable(db)
	require.NoError(t, err)
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err)
	m := &manager{
		logger:     hivetest.Logger(t),
		db:         db,
		namespaces: namespaces,
		pods:       pods,
	}
	m.compiledPools = map[string]compiledPool{}
	m.poolsSynced.Store(true)

	t.Run("pod annotation blocks default fallback", func(t *testing.T) {
		// Add pod with require-pool-match annotation
		pod := k8s.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:        "pod",
				Namespace:   "default",
				Annotations: map[string]string{annotation.IPAMRequirePoolMatch: "true"},
			},
		}}
		txn := db.WriteTxn(pods, namespaces)
		pods.Insert(txn, pod)

		// Add namespace without annotation
		ns := k8s.Namespace{Name: "default"}
		namespaces.Insert(txn, ns)
		txn.Commit()

		// Should return error instead of default
		_, err := m.GetIPPoolForPod("default/pod", ipam.IPv4)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no matching CiliumPodIPPool found")
		require.Contains(t, err.Error(), "require-pool-match annotation is set")
	})

	t.Run("namespace annotation blocks default fallback", func(t *testing.T) {
		// Add pod without annotation
		pod := k8s.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:      "pod2",
				Namespace: "strict-ns",
			},
		}}
		txn := db.WriteTxn(pods, namespaces)
		pods.Insert(txn, pod)

		// Add namespace with require-pool-match annotation
		ns := k8s.Namespace{
			Name:        "strict-ns",
			Annotations: map[string]string{annotation.IPAMRequirePoolMatch: "true"},
		}
		namespaces.Insert(txn, ns)
		txn.Commit()

		// Should return error instead of default
		_, err := m.GetIPPoolForPod("strict-ns/pod2", ipam.IPv4)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no matching CiliumPodIPPool found")
		require.Contains(t, err.Error(), "require-pool-match annotation is set")
	})

	t.Run("annotation false allows default fallback", func(t *testing.T) {
		// Add pod with annotation set to false
		pod := k8s.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Name:        "pod3",
				Namespace:   "namespace",
				Annotations: map[string]string{annotation.IPAMRequirePoolMatch: "false"},
			},
		}}
		txn := db.WriteTxn(pods, namespaces)
		pods.Insert(txn, pod)

		// Add namespace
		ns := k8s.Namespace{Name: "namespace"}
		namespaces.Insert(txn, ns)
		txn.Commit()

		// Should fall back to default
		pool, err := m.GetIPPoolForPod("namespace/pod3", ipam.IPv4)
		require.NoError(t, err)
		require.Equal(t, "default", pool)
	})
}

func TestDefaultManager_DefaultPool(t *testing.T) {
	defaultPoolManager := defaultIPPoolManager{}

	ipv4Pool, err := defaultPoolManager.GetIPPoolForPod("", ipam.IPv4)
	require.NoError(t, err)
	require.Equal(t, ipam.PoolDefault(), ipam.Pool(ipv4Pool))

	ipv6Pool, err := defaultPoolManager.GetIPPoolForPod("", ipam.IPv6)
	require.NoError(t, err)
	require.Equal(t, ipam.PoolDefault(), ipam.Pool(ipv6Pool))
}

func TestNamespaceSelector(t *testing.T) {
	db := statedb.New()
	pools, err := k8s.NewPodTable(db)
	require.NoError(t, err, "NewPodTable")
	namespaces, err := k8s.NewNamespaceTable(db)
	require.NoError(t, err, "NewNamespaceTable")

	m := &manager{
		logger:        slog.Default(),
		db:            db,
		namespaces:    namespaces,
		pods:          pools,
		compiledPools: make(map[string]compiledPool),
	}
	m.poolsSynced.Store(true)

	// Create dev/prod namespaces and pods
	w := db.WriteTxn(namespaces, pools)
	namespaces.Insert(w, k8s.Namespace{
		Name:   "dev",
		Labels: map[string]string{"env": "dev"},
	})
	namespaces.Insert(w, k8s.Namespace{
		Name:   "prod",
		Labels: map[string]string{"env": "prod"},
	})
	pools.Insert(w, k8s.LocalPod{Pod: &slim_core_v1.Pod{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace: "dev", Name: "pod", Labels: map[string]string{"app": "web"},
		},
	}})
	pools.Insert(w, k8s.LocalPod{Pod: &slim_core_v1.Pod{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Namespace: "prod", Name: "pod", Labels: map[string]string{"app": "web"},
		},
	}})
	w.Commit()

	t.Run("match by namespace only", func(t *testing.T) {
		m.compiledPools = make(map[string]compiledPool)
		m.setCompiledPool(compiledPool{
			name:              "dev-pool",
			namespaceSelector: selectorFromLabels(map[string]string{"env": "dev"}),
			hasV4:             true,
		})

		pool, err := m.GetIPPoolForPod("dev/pod", ipam.IPv4)
		require.NoError(t, err)
		assert.Equal(t, "dev-pool", pool)

		pool, err = m.GetIPPoolForPod("prod/pod", ipam.IPv4)
		require.NoError(t, err)
		require.Equal(t, ipam.PoolDefault().String(), pool)
	})

	t.Run("match by pod and namespace", func(t *testing.T) {
		m.compiledPools = make(map[string]compiledPool)
		m.setCompiledPool(compiledPool{
			name:              "dev-web-pool",
			podSelector:       selectorFromLabels(map[string]string{"app": "web"}),
			namespaceSelector: selectorFromLabels(map[string]string{"env": "dev"}),
			hasV4:             true,
		})

		pool, err := m.GetIPPoolForPod("dev/pod", ipam.IPv4)
		require.NoError(t, err)
		assert.Equal(t, "dev-web-pool", pool)

		pool, err = m.GetIPPoolForPod("prod/pod", ipam.IPv4)
		require.NoError(t, err)
		assert.Equal(t, ipam.PoolDefault().String(), pool)
	})

	t.Run("require-pool-match on namespace blocks fallback", func(t *testing.T) {
		m.compiledPools = make(map[string]compiledPool)

		// Add a restricted namespace/pod
		w := db.WriteTxn(namespaces, pools)
		namespaces.Insert(w, k8s.Namespace{
			Name:        "restricted",
			Annotations: map[string]string{annotation.IPAMRequirePoolMatch: "true"},
		})
		// Pod with no labels
		pools.Insert(w, k8s.LocalPod{Pod: &slim_core_v1.Pod{
			ObjectMeta: slim_meta_v1.ObjectMeta{
				Namespace: "restricted", Name: "pod", Labels: map[string]string{},
			},
		}})
		w.Commit()

		m.setCompiledPool(compiledPool{
			name:              "prod-pool",
			namespaceSelector: selectorFromLabels(map[string]string{"env": "prod"}),
			hasV4:             true,
		})

		// should not fallback to default due to ns annotation
		_, err := m.GetIPPoolForPod("restricted/pod", ipam.IPv4)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no matching CiliumPodIPPool found")
		assert.Contains(t, err.Error(), "require-pool-match annotation is set on namespace")
	})
}
