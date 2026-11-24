// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sClientTestUtils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestAllCRDsNotFound(t *testing.T) {
	notFoundGWClass := k8serrors.NewNotFound(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses"}, "cilium")
	notFoundGateway := k8serrors.NewNotFound(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"}, "cilium")
	versionNotFound := fmt.Errorf("CRD %q does not have version %q: %w", "gatewayclasses.gateway.networking.k8s.io", "v1", k8sClient.ErrCRDVersionNotFound)
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
			name:     "not found",
			err:      notFoundGWClass,
			expected: true,
		},
		{
			name:     "CRD version not found",
			err:      versionNotFound,
			expected: true,
		},
		{
			name:     "joined not found and version not found",
			err:      errors.Join(notFoundGWClass, notFoundGateway, versionNotFound),
			expected: true,
		},
		{
			name:     "joined not found with internal server error should retry",
			err:      errors.Join(notFoundGWClass, internalErr),
			expected: false,
		},
		{
			name:     "internal error (500)",
			err:      internalErr,
			expected: false,
		},
		{
			name: "unexpected server error (500)",
			err: &k8serrors.StatusError{
				ErrStatus: metav1.Status{
					Code:   500,
					Reason: metav1.StatusReasonUnknown,
				},
			},
			expected: false,
		},
		{
			name:     "service unavailable (503)",
			err:      k8serrors.NewServiceUnavailable("API server is shutting down"),
			expected: false,
		},
		{
			name:     "server timeout (504)",
			err:      k8serrors.NewServerTimeout(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses"}, "get", 5),
			expected: false,
		},
		{
			name:     "too many requests (429)",
			err:      k8serrors.NewTooManyRequests("rate limited", 5),
			expected: false,
		},
		{
			name:     "unauthorized (401)",
			err:      k8serrors.NewUnauthorized("Unauthorized"),
			expected: false,
		},
		{
			name:     "forbidden (403)",
			err:      k8serrors.NewForbidden(schema.GroupResource{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}, "gatewayclasses.gateway.networking.k8s.io", errors.New("RBAC syncing")),
			expected: false,
		},
		{
			name:     "EOF from restarting apiserver proxy",
			err:      io.EOF,
			expected: false,
		},
		{
			name:     "connection refused",
			err:      syscall.ECONNREFUSED,
			expected: false,
		},
		{
			name:     "connection reset",
			err:      syscall.ECONNRESET,
			expected: false,
		},
		{
			name:     "timed out errno",
			err:      syscall.ETIMEDOUT,
			expected: false,
		},
		{
			name:     "generic unrecognized error",
			err:      errors.New("some unexpected error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := allCRDsNotFound(tt.err)
			assert.Equal(t, tt.expected, result, "allCRDsNotFound(%v) should return %v", tt.err, tt.expected)
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

// installCRDs creates the given CRDs in the fake apiextensions client.
func installCRDs(t *testing.T, fcs *k8sClientTestUtils.FakeClientset, gvks []schema.GroupVersionKind) {
	t.Helper()
	for _, gvk := range gvks {
		crd := makeGatewayCRD(gvk)
		_, err := fcs.APIExtFakeClientset.ApiextensionsV1().CustomResourceDefinitions().Create(
			t.Context(), crd, metav1.CreateOptions{},
		)
		require.NoError(t, err)
	}
}

// installRequiredCRDs creates the required Gateway API CRDs in the fake apiextensions client.
func installRequiredCRDs(t *testing.T, fcs *k8sClientTestUtils.FakeClientset) {
	t.Helper()
	installCRDs(t, fcs, helpers.RequiredGVKs)
}

func TestDiscoverCRDsWithRetry_Success(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	installRequiredCRDs(t, fcs)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.NoError(t, err)
	require.True(t, result.Enabled)
	assert.Empty(t, result.InstalledOptionalKinds)
	assert.Equal(t, cell.StatusOK, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRDs discovered", simpleHealth.Status)
}

func TestDiscoverCRDsWithRetry_OptionalCRDsPresentMissingAndWrongVersion(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	installRequiredCRDs(t, fcs)
	require.GreaterOrEqual(t, len(helpers.AllOptionalKinds), 2)

	// Install the first optional CRD with its expected version.
	presentOpt := helpers.AllOptionalKinds[0]
	installCRDs(t, fcs, []schema.GroupVersionKind{presentOpt})

	// Install the second optional CRD with a mismatched version so CheckCRD returns ErrCRDVersionNotFound.
	wrongVersionOpt := helpers.AllOptionalKinds[1]
	wrongVersionCRD := makeGatewayCRD(schema.GroupVersionKind{
		Group:   wrongVersionOpt.Group,
		Version: "v0unsupported",
		Kind:    wrongVersionOpt.Kind,
	})
	_, err := fcs.APIExtFakeClientset.ApiextensionsV1().CustomResourceDefinitions().Create(
		t.Context(), wrongVersionCRD, metav1.CreateOptions{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.NoError(t, err)
	require.True(t, result.Enabled)
	assert.Equal(t, []schema.GroupVersionKind{presentOpt}, result.InstalledOptionalKinds)
	assert.Equal(t, cell.StatusOK, simpleHealth.Level)
}

func TestDiscoverCRDsWithRetry_CRDsNotInstalled(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	var callCount atomic.Int32
	fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			callCount.Add(1)
			return false, nil, nil
		},
	)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "required Gateway API CRDs not found")
	assert.True(t, k8serrors.IsNotFound(err))
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRDs not installed", simpleHealth.Status)
	// Must fail fast in a single check pass without retrying.
	assert.Equal(t, len(helpers.RequiredGVKs)+len(helpers.AllOptionalKinds), int(callCount.Load()))
}

func TestDiscoverCRDsWithRetry_RequiredCRDWrongVersion(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	// Install all required CRDs except the first one has an unsupported version.
	installCRDs(t, fcs, helpers.RequiredGVKs[1:])
	wrongVersionCRD := makeGatewayCRD(schema.GroupVersionKind{
		Group:   helpers.RequiredGVKs[0].Group,
		Version: "v0unsupported",
		Kind:    helpers.RequiredGVKs[0].Kind,
	})
	_, err := fcs.APIExtFakeClientset.ApiextensionsV1().CustomResourceDefinitions().Create(
		t.Context(), wrongVersionCRD, metav1.CreateOptions{},
	)
	require.NoError(t, err)

	var callCount atomic.Int32
	fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			callCount.Add(1)
			return false, nil, nil
		},
	)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, k8sClient.ErrCRDVersionNotFound)
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRDs not installed", simpleHealth.Status)
	assert.Equal(t, len(helpers.RequiredGVKs)+len(helpers.AllOptionalKinds), int(callCount.Load()))
}

func TestDiscoverCRDsWithRetry_RetryableErrorsThenSuccess(t *testing.T) {
	retryableErrors := []struct {
		name string
		err  error
	}{
		{
			name: "connection refused",
			err:  syscall.ECONNREFUSED,
		},
		{
			name: "internal server error (500 etcd leader election)",
			err:  k8serrors.NewInternalError(errors.New("etcdserver: leader changed")),
		},
		{
			name: "forbidden (403 apiserver RBAC sync)",
			err:  k8serrors.NewForbidden(schema.GroupResource{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"}, "gatewayclasses.gateway.networking.k8s.io", errors.New("forbidden")),
		},
		{
			name: "unauthorized (401)",
			err:  k8serrors.NewUnauthorized("Unauthorized"),
		},
		{
			name: "EOF from proxy",
			err:  io.EOF,
		},
	}

	for _, tt := range retryableErrors {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
			health, simpleHealth := cell.NewSimpleHealth()

			installRequiredCRDs(t, fcs)

			var callCount atomic.Int32
			fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
				func(action k8sTesting.Action) (bool, runtime.Object, error) {
					if callCount.Add(1) <= int32(len(helpers.RequiredGVKs)) {
						return true, nil, tt.err
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
		})
	}
}

func TestDiscoverCRDsWithRetry_OptionalCRDErrorThenSuccess(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	installRequiredCRDs(t, fcs)
	optGVK := helpers.AllOptionalKinds[0]
	installCRDs(t, fcs, []schema.GroupVersionKind{optGVK})
	optCRDName := optGVK.GroupKind().String()

	// Fail the first lookup of the optional CRD with a 500 error, then succeed on retry.
	var optCalls atomic.Int32
	fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			getAction, ok := action.(k8sTesting.GetAction)
			if ok && getAction.GetName() == optCRDName && optCalls.Add(1) == 1 {
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
	assert.Equal(t, []schema.GroupVersionKind{optGVK}, result.InstalledOptionalKinds)
	assert.Equal(t, cell.StatusOK, simpleHealth.Level)
	assert.Equal(t, int32(2), optCalls.Load())
}

func TestDiscoverCRDsWithRetry_OptionalCRDErrorUntilTimeout(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	installRequiredCRDs(t, fcs)
	optCRDName := helpers.AllOptionalKinds[0].GroupKind().String()

	// Continuously return 500 for an optional CRD; discovery must retry and propagate the error on timeout.
	fcs.APIExtFakeClientset.PrependReactor("get", "customresourcedefinitions",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			getAction, ok := action.(k8sTesting.GetAction)
			if ok && getAction.GetName() == optCRDName {
				return true, nil, k8serrors.NewInternalError(errors.New("apiserver unavailable"))
			}
			return false, nil, nil
		},
	)

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "gateway API CRD discovery timed out")
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRD discovery timed out", simpleHealth.Status)
}

func TestDiscoverCRDsWithRetry_ErrorUntilTimeout(t *testing.T) {
	logger := hivetest.Logger(t)
	fcs, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	// All calls return a non-NotFound error.
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
	assert.ErrorContains(t, err, "gateway API CRD discovery timed out")
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
	assert.Equal(t, "Gateway API CRD discovery timed out", simpleHealth.Status)
}

// TestDiscoverCRDsWithRetry_ContextAlreadyCancelled verifies that when the retry
// context is already expired and checkCRDs returns errors, discoverCRDsWithRetry
// reports a timeout rather than misclassifying the failure as missing CRDs.
func TestDiscoverCRDsWithRetry_ContextAlreadyCancelled(t *testing.T) {
	logger := hivetest.Logger(t)
	_, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "gateway API CRD discovery timed out")
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
}

// TestDiscoverCRDsWithRetry_ContextDeadlineExceeded is the same scenario as above
// using a deadline (DeadlineExceeded) rather than explicit cancellation.
func TestDiscoverCRDsWithRetry_ContextDeadlineExceeded(t *testing.T) {
	logger := hivetest.Logger(t)
	_, cs := k8sClientTestUtils.NewFakeClientset(logger)
	health, simpleHealth := cell.NewSimpleHealth()

	ctx, cancel := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // Ensure the deadline has expired.

	result, err := discoverCRDsWithRetry(ctx, cs, logger, health)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "gateway API CRD discovery timed out")
	assert.Equal(t, cell.StatusStopped, simpleHealth.Level)
}
