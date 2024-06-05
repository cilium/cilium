// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stest "k8s.io/client-go/testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// Configure a generous timeout to prevent flakes when running in a noisy CI environment.
var (
	tick    = 10 * time.Millisecond
	timeout = 500 * time.Second
)

func TestServiceResolver(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	var (
		tlog = hivetest.Logger(t)
		ctx  = context.Background()

		started  atomic.Bool
		cl       *client.FakeClientset
		resolver *ServiceResolver
	)

	h := hive.New(
		client.FakeClientCell,

		cell.Module("foo", "foo", ServiceResolverCell),

		cell.Config(k8s.DefaultConfig),
		cell.Provide(k8s.ServiceResource),

		cell.Invoke(func(cl_ *client.FakeClientset, resolver_ *ServiceResolver) {
			cl = cl_
			resolver = resolver_
		}))

	require.NoError(t, h.Start(hivetest.Logger(t), ctx))
	t.Cleanup(func() { require.NoError(t, h.Stop(tlog, ctx)) })

	cl.SlimFakeClientset.PrependReactor("list", "services",
		func(action k8stest.Action) (handled bool, ret runtime.Object, err error) {
			started.Store(true)
			return false, nil, nil
		},
	)

	_, err := cl.Slim().CoreV1().Services("bar").Create(ctx, &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "foo", Namespace: "bar"},
		Spec:       slim_corev1.ServiceSpec{ClusterIP: "192.168.0.1"},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "Unexpected error while creating service")

	_, err = cl.Slim().CoreV1().Services("bar").Create(ctx, &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "qux", Namespace: "bar"},
		Spec:       slim_corev1.ServiceSpec{ClusterIP: slim_corev1.ClusterIPNone},
	}, metav1.CreateOptions{})
	require.NoError(t, err, "Unexpected error while creating service")

	// Trying to resolve a name not matching a service should return an error
	_, err = resolver.Resolve(ctx, "foo.bar.com")
	require.ErrorContains(t, err, "foo.bar.com does not match the <name>.<namespace>(.svc) form")
	require.False(t, started.Load(), "The store should not have started")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		got, err := resolver.Resolve(ctx, "foo.bar")
		assert.NoError(c, err, "Unexpected error while resolving service")
		assert.Equal(c, "192.168.0.1", got)
	}, timeout, tick)

	require.True(t, started.Load(), "The store should have started")

	got, err := resolver.Resolve(ctx, "foo.bar.svc")
	require.NoError(t, err, "Unexpected error while resolving service")
	require.Equal(t, "192.168.0.1", got)

	got, err = resolver.Resolve(ctx, "foo.bar.svc.cluster.local")
	require.NoError(t, err, "Unexpected error while resolving service")
	require.Equal(t, "192.168.0.1", got)

	// Trying to resolve a name for a not-existing service should return an error
	_, err = resolver.Resolve(ctx, "foo.baz")
	require.ErrorContains(t, err, "service \"baz/foo\" not found")

	// Trying to resolve a name for a service without a ClusterIP should return an error
	_, err = resolver.Resolve(ctx, "qux.bar")
	require.ErrorContains(t, err, "cannot parse ClusterIP address")
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
		got, err := ServiceURLToNamespacedName(tt.host)
		tt.assertErr(t, err, "Got incorrect error for host %q", tt.host)
		assert.Equal(t, tt.expected, got, "Got incorrect value for host %q", tt.host)
	}
}
