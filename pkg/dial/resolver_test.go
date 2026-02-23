// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial_test

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	k8stest "k8s.io/client-go/testing"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 30 * time.Second
)

func TestLBServiceResolver(t *testing.T) {
	testResolver(
		t,

		dial.ServiceResolverCell,

		// LB depends on these
		daemonk8s.TablesCell,
		node.LocalNodeStoreTestCell,
		source.Cell,
		cell.Provide(
			func() loadbalancer.Config { return loadbalancer.DefaultConfig },
			func() loadbalancer.ExternalConfig {
				return loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: true}
			},
			func() *loadbalancer.TestConfig { return &loadbalancer.TestConfig{} },
			func() kpr.KPRConfig {
				return kpr.KPRConfig{KubeProxyReplacement: true}
			},
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			func() *option.DaemonConfig { return &option.DaemonConfig{} },
		),

		writer.Cell,
		reflectors.Cell,
	)
}

func TestResourceServiceResolver(t *testing.T) {
	testResolver(
		t,

		cell.Provide(k8s.ServiceResource),

		dial.ResourceServiceResolverCell,
	)
}

func testResolver(t *testing.T, cells ...cell.Cell) {
	t.Cleanup(func() { testutils.GoleakVerifyNone(t) })

	var (
		tlog = hivetest.Logger(t)
		ctx  = context.Background()

		started  atomic.Bool
		cl       *k8sClient.FakeClientset
		resolver dial.Resolver
	)

	h := hive.New(
		metrics.Cell,

		k8sClient.FakeClientCell(),
		cell.Provide(k8s.DefaultServiceWatchConfig),
		cell.Config(k8s.DefaultConfig),

		cell.Invoke(func(cl_ *k8sClient.FakeClientset, resolver_ dial.Resolver) {
			cl = cl_

			// Add a reactor to check that services are being watched.
			cl.SlimFakeClientset.PrependWatchReactor("services",
				func(action k8stest.Action) (handled bool, ret watch.Interface, err error) {
					started.Store(true)
					return false, nil, nil
				},
			)
			resolver = resolver_
		}),
		cell.Group(cells...))

	require.NoError(t, h.Start(tlog, ctx))
	t.Cleanup(func() { require.NoError(t, h.Stop(tlog, ctx)) })

	_, err := cl.Slim().CoreV1().Services("bar").Create(ctx, &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
		Spec:       slim_corev1.ServiceSpec{ClusterIP: "192.168.0.1", Ports: []slim_corev1.ServicePort{{Port: 8080}}},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "Unexpected error while creating service")

	_, err = cl.Slim().CoreV1().Services("bar").Create(ctx, &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "qux", Namespace: "bar"},
		Spec:       slim_corev1.ServiceSpec{ClusterIP: slim_corev1.ClusterIPNone},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "Unexpected error while creating service")

	// Trying to resolve a name not matching a service should return the provided host/port pair
	host, port := resolver.Resolve(ctx, "foo.bar.com", "8080")
	require.Equal(t, "foo.bar.com", host)
	require.Equal(t, "8080", port)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		host, port := resolver.Resolve(ctx, "foo.bar", "8080")
		assert.Equal(c, "192.168.0.1", host)
		assert.Equal(c, "8080", port)
	}, timeout, tick)

	require.True(t, started.Load(), "The store should have started")

	host, port = resolver.Resolve(ctx, "foo.bar.svc", "8080")
	require.Equal(t, "192.168.0.1", host)
	require.Equal(t, "8080", port)

	host, port = resolver.Resolve(ctx, "foo.bar.svc.cluster.local", "9090")
	require.Equal(t, "192.168.0.1", host)
	require.Equal(t, "9090", port)

	// Trying to resolve a name for a not-existing service should return the provided host/port pair
	host, port = resolver.Resolve(ctx, "foo.baz", "8080")
	require.Equal(t, "foo.baz", host)
	require.Equal(t, "8080", port)

	// Trying to resolve a name for a service without a ClusterIP return the provided host/port pair
	host, port = resolver.Resolve(ctx, "qux.bar", "8080")
	require.Equal(t, "qux.bar", host)
	require.Equal(t, "8080", port)
}

func TestServiceURLToNamespacedName(t *testing.T) {
	tests := []struct {
		host      string
		expected  types.NamespacedName
		assertErr assert.ErrorAssertionFunc
	}{
		{
			host:      "",
			assertErr: assert.Error,
		},
		{
			host:      "foo",
			assertErr: assert.Error,
		},
		{
			host:      "foo.bar",
			expected:  types.NamespacedName{Namespace: "bar", Name: "foo"},
			assertErr: assert.NoError,
		},
		{
			host:      "foo.bar.svc",
			expected:  types.NamespacedName{Namespace: "bar", Name: "foo"},
			assertErr: assert.NoError,
		},
		{
			host:      "foo.bar.svc.other.local",
			expected:  types.NamespacedName{Namespace: "bar", Name: "foo"},
			assertErr: assert.NoError,
		},
		{
			host:      "foo.bar.qux",
			assertErr: assert.Error,
		},
		{
			host:      "foo.bar.qux.fred",
			assertErr: assert.Error,
		},
	}

	for _, tt := range tests {
		got, err := dial.ServiceURLToNamespacedName(tt.host)
		tt.assertErr(t, err, "Got incorrect error for host %q", tt.host)
		assert.Equal(t, tt.expected, got, "Got incorrect value for host %q", tt.host)
	}
}

func TestServiceBackendResolver(t *testing.T) {
	var (
		log = hivetest.Logger(t)
		ctx = t.Context()

		wr       *writer.Writer
		resolver *dial.ServiceBackendResolver
	)

	h := hive.New(
		lb.ConfigCell,
		node.LocalNodeStoreTestCell,
		writer.Cell,

		cell.Provide(
			func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
			dial.ServiceBackendResolverFactory("test1"),

			func() *option.DaemonConfig { return &option.DaemonConfig{} },
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
			source.NewSources,
			func() kpr.KPRConfig { return kpr.KPRConfig{} },
		),

		cell.Invoke(func(wr_ *writer.Writer, resolver_ *dial.ServiceBackendResolver) {
			wr = wr_
			resolver = resolver_
		}),
	)

	require.NoError(t, h.Start(hivetest.Logger(t), ctx))
	t.Cleanup(func() { require.NoError(t, h.Stop(log, context.Background())) })

	toAddr := func(proto lb.L4Type, addr string, port uint16) lb.L3n4Addr {
		return lb.NewL3n4Addr(proto, cmtypes.MustParseAddrCluster(addr), port, lb.ScopeExternal)
	}

	be := func(proto lb.L4Type, addr string, port uint16, portname string, state lb.BackendState) lb.BackendParams {
		return lb.BackendParams{
			Address:   toAddr(proto, addr, port),
			PortNames: []string{portname},
			State:     state,
		}
	}

	// Upsert test frontends and backends
	txn := wr.WriteTxn()

	svc := &lb.Service{Name: lb.NewServiceName("foo", "bar"), Source: source.Kubernetes}
	require.NoError(t, wr.UpsertServiceAndFrontends(txn, svc,
		lb.FrontendParams{
			ServiceName: svc.Name,
			Address:     toAddr(lb.TCP, "192.168.10.10", 8080),
			Type:        lb.SVCTypeClusterIP,
			PortName:    "alpha",
		},
		lb.FrontendParams{
			ServiceName: svc.Name,
			Address:     toAddr(lb.TCP, "192.168.10.10", 8081),
			Type:        lb.SVCTypeClusterIP,
			PortName:    "beta",
		},
		lb.FrontendParams{
			ServiceName: svc.Name,
			Address:     toAddr(lb.UDP, "192.168.10.10", 8080),
			Type:        lb.SVCTypeClusterIP,
			PortName:    "gamma",
		},
	), "Unexpected UpsertServiceAndFrontends error")

	require.NoError(t, wr.UpsertBackends(txn, svc.Name, source.Kubernetes,
		slices.Values([]lb.BackendParams{
			be(lb.TCP, "10.0.0.1", 9090, "alpha", lb.BackendStateActive),
			be(lb.TCP, "10.0.0.2", 9090, "alpha", lb.BackendStateActive),
			be(lb.TCP, "10.0.0.3", 9090, "alpha", lb.BackendStateActive),
			be(lb.TCP, "10.0.0.4", 9091, "beta", lb.BackendStateTerminating),
			be(lb.UDP, "10.0.0.4", 9090, "gamma", lb.BackendStateActive),
		}),
	), "Unexpected UpsertBackends error")

	txn.Commit()

	// Register the test initializers ("test1" is ignored by the resolver)
	_ = wr.RegisterInitializer("test1")
	done := wr.RegisterInitializer("test2")

	// Host is not an IP
	host, port := resolver.Resolve(ctx, "foo.bar", "80")
	require.Equal(t, "foo.bar", host)
	require.Equal(t, "80", port)

	// There are pending (non-ignored) initializers
	tctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	host, port = resolver.Resolve(tctx, "192.168.10.10", "8080")
	require.Contains(t, "192.168.10.10", host)
	require.Equal(t, "8080", port)
	cancel()

	// Mark the non-ignored initializer as completed
	txn = wr.WriteTxn()
	done(txn)
	txn.Commit()

	// Host IP which is not known
	host, port = resolver.Resolve(ctx, "1.2.3.4", "80")
	require.Equal(t, "1.2.3.4", host)
	require.Equal(t, "80", port)

	// Port does not match
	host, port = resolver.Resolve(ctx, "192.168.10.10", "80")
	require.Equal(t, "192.168.10.10", host)
	require.Equal(t, "80", port)

	// Host and port do match a known service, but has no (active) backends
	host, port = resolver.Resolve(ctx, "192.168.10.10", "8081")
	require.Equal(t, "192.168.10.10", host)
	require.Equal(t, "8081", port)

	// Host and port do match a known service
	expected := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	host, port = resolver.Resolve(ctx, "192.168.10.10", "8080")
	require.Contains(t, expected, host)
	require.Equal(t, "9090", port)

	// Subsequent requests should always hit the same backend
	for range 10 {
		got, _ := resolver.Resolve(ctx, "192.168.10.10", "8080")
		require.Equal(t, host, got)
	}

	// Remove the previously used backend
	txn = wr.WriteTxn()
	wr.ReleaseBackends(txn, svc.Name, slices.Values([]lb.L3n4Addr{toAddr(lb.TCP, host, 9090)}))
	txn.Commit()

	// Should switch to one of the remaining backends
	expected = slices.DeleteFunc(expected, func(a string) bool { return a == host })
	host, _ = resolver.Resolve(ctx, "192.168.10.10", "8080")
	require.Contains(t, expected, host)

	// Subsequent requests should again always hit the same backend
	for range 10 {
		got, _ := resolver.Resolve(ctx, "192.168.10.10", "8080")
		require.Equal(t, host, got)
	}
}
