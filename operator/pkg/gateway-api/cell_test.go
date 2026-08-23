// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestIsPermanentError(t *testing.T) {
	notFound := k8serrors.NewNotFound(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses"}, "cilium")
	otherNotFound := k8serrors.NewNotFound(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "grpcroutes"}, "cilium")
	internalErr := k8serrors.NewInternalError(errors.New("etcdserver: leader changed"))

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "not found is the only permanent error",
			err:      notFound,
			expected: true,
		},
		{
			name:     "connection refused is retried, not permanent",
			err:      syscall.ECONNREFUSED,
			expected: false,
		},
		{
			name:     "connection reset is retried, not permanent",
			err:      syscall.ECONNRESET,
			expected: false,
		},
		{
			name:     "no route to host is retried, not permanent",
			err:      syscall.EHOSTUNREACH,
			expected: false,
		},
		{
			name:     "network unreachable is retried, not permanent",
			err:      syscall.ENETUNREACH,
			expected: false,
		},
		{
			name:     "server timeout is retried, not permanent",
			err:      k8serrors.NewServerTimeout(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses"}, "get", 5),
			expected: false,
		},
		{
			name:     "service unavailable is retried, not permanent",
			err:      k8serrors.NewServiceUnavailable("API server is shutting down"),
			expected: false,
		},
		{
			name:     "too many requests is retried, not permanent",
			err:      k8serrors.NewTooManyRequests("rate limited", 5),
			expected: false,
		},
		{
			name:     "timeout is retried, not permanent",
			err:      k8serrors.NewTimeoutError("request timed out", 30),
			expected: false,
		},
		{
			// The regression this guards against: cilium/cilium#48083. A 500 from
			// the apiserver (e.g. etcd losing its leader) must not be treated the
			// same as a genuine "the CRD is absent" NotFound answer.
			name:     "internal server error is retried, not permanent",
			err:      internalErr,
			expected: false,
		},
		{
			name:     "unrecognized error is retried, not permanent",
			err:      errors.New("some random error"),
			expected: false,
		},
		{
			name:     "wrapped connection refused is retried, not permanent",
			err:      errors.New("dial tcp: connect: " + syscall.ECONNREFUSED.Error()),
			expected: false,
		},
		{
			name:     "all joined errors not found is permanent",
			err:      errors.Join(notFound, otherNotFound),
			expected: true,
		},
		{
			name: "one transient error among joined not-found errors is retried, not permanent",
			// checkCRDs joins one error per missing required GVK. A single 500
			// among several otherwise-genuine NotFound answers must not be
			// masked into a permanent "CRDs not installed" verdict.
			err:      errors.Join(notFound, internalErr),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPermanentError(tt.err)
			assert.Equal(t, tt.expected, result, "isPermanentError(%v) should return %v", tt.err, tt.expected)
		})
	}
}

// makeGatewayCRD creates an apiextensions CRD object matching what checkCRD expects.
func makeGatewayCRD(gvk schema.GroupVersionKind) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: gvk.GroupKind().String(),
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{Name: gvk.Version, Served: true, Storage: true},
			},
		},
	}
}

// installRequiredCRDs creates the required Gateway API CRDs in the fake apiextensions client.
func installRequiredCRDs(t *testing.T, fcs *k8sClient.FakeClientset) {
	t.Helper()
	for _, gvk := range helpers.RequiredGVKs {
		crd := makeGatewayCRD(gvk)
		_, err := fcs.APIExtFakeClientset.ApiextensionsV1().CustomResourceDefinitions().Create(
			t.Context(), crd, metav1.CreateOptions{},
		)
		require.NoError(t, err)
	}
}

func TestDiscoverCRDsWithRetry_Success(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClient.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	installRequiredCRDs(t, fcs)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.NoError(t, err)
	require.True(t, result.Enabled)
	assert.Equal(t, cell.StatusOK, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRDs discovered", simpleHealth.Status)
}

func TestDiscoverCRDsWithRetry_CRDsNotInstalled(t *testing.T) {
	logger := hivetest.Logger(t)
	_, cs := k8sClient.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.NoError(t, err)
	require.False(t, result.Enabled)
	assert.Equal(t, cell.StatusDegraded, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRDs not installed", simpleHealth.Status)
}

func TestDiscoverCRDsWithRetry_TransientErrorThenSuccess(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClient.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	installRequiredCRDs(t, fcs)

	// Fail the first batch of CRD lookups with a transient error,
	// then let subsequent calls fall through to the default handler.
	var callCount atomic.Int32
	fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			if callCount.Add(1) <= int32(len(helpers.RequiredGVKs)) {
				return true, nil, syscall.ECONNREFUSED
			}
			return false, nil, nil
		},
	)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.NoError(t, err)
	require.True(t, result.Enabled)
	assert.Equal(t, cell.StatusOK, simpleHealth.Level)
	assert.Greater(t, int(callCount.Load()), len(helpers.RequiredGVKs))
}

// TestDiscoverCRDsWithRetry_InternalServerErrorThenSuccess reproduces the
// exact scenario in cilium/cilium#48083: the apiserver answers with a 500
// (e.g. etcd losing its leader) during CRD discovery, which must be retried
// rather than immediately and permanently disabling Gateway API.
func TestDiscoverCRDsWithRetry_InternalServerErrorThenSuccess(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClient.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	installRequiredCRDs(t, fcs)

	var callCount atomic.Int32
	fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			if callCount.Add(1) <= int32(len(helpers.RequiredGVKs)) {
				return true, nil, k8serrors.NewInternalError(errors.New("etcdserver: leader changed"))
			}
			return false, nil, nil
		},
	)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.NoError(t, err)
	require.True(t, result.Enabled)
	assert.Equal(t, cell.StatusOK, simpleHealth.Level)
	assert.Greater(t, int(callCount.Load()), len(helpers.RequiredGVKs))
}

func TestDiscoverCRDsWithRetry_TransientErrorUntilTimeout(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClient.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	// All calls return a transient error.
	fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			return true, nil, syscall.ECONNREFUSED
		},
	)

	// Short timeout so the test doesn't wait 30s.
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "gateway API CRD discovery timed out")
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRD discovery timed out after transient errors", simpleHealth.Status)
}

// TestDiscoverCRDsWithRetry_ContextAlreadyCancelled tests the race condition fix:
// when the retry context expires and checkCRDs returns an error that isPermanentError
// doesn't recognize, the function must return a fatal error instead of silently
// disabling Gateway API by treating it as "CRDs not installed".
func TestDiscoverCRDsWithRetry_ContextAlreadyCancelled(t *testing.T) {
	logger := hivetest.Logger(t)
	_, cs := k8sClient.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	// Pre-cancel the context to simulate the race where bo.Wait completes
	// just before the deadline and checkCRDs is called with an expired context.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	// Must return a fatal error, NOT {Enabled: false}.
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "gateway API CRD discovery timed out")
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
}

// TestDiscoverCRDsWithRetry_ContextDeadlineExceeded is the same scenario as above
// using a deadline (DeadlineExceeded) rather than explicit cancellation.
func TestDiscoverCRDsWithRetry_ContextDeadlineExceeded(t *testing.T) {
	logger := hivetest.Logger(t)
	_, cs := k8sClient.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	ctx, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // Ensure the deadline has expired.

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "gateway API CRD discovery timed out")
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
}
