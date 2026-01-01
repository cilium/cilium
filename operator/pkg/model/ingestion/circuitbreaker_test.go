// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestEnrichModelWithCircuitBreakers(t *testing.T) {
	ctx := context.Background()

	t.Run("nil model", func(t *testing.T) {
		c := fake.NewClientBuilder().Build()
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "model cannot be nil")
	})

	t.Run("model already has CircuitBreakers", func(t *testing.T) {
		c := fake.NewClientBuilder().Build()
		m := &model.Model{
			CircuitBreakers: map[string]interface{}{
				"test": "value",
			},
		}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.NoError(t, err)
		assert.Equal(t, map[string]interface{}{"test": "value"}, m.CircuitBreakers)
	})

	t.Run("no services with annotation", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 80},
				},
			},
		}
		c := fake.NewClientBuilder().WithObjects(svc).Build()
		m := &model.Model{}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.NoError(t, err)
		assert.Empty(t, m.CircuitBreakers)
	})

	t.Run("service with annotation, CRD exists", func(t *testing.T) {
		cb := &ciliumv2.CiliumEnvoyCircuitBreaker{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-circuit-breaker",
				Namespace: "default",
			},
			Spec: ciliumv2.CiliumEnvoyCircuitBreakerSpec{
				Thresholds: []ciliumv2.CircuitBreakerThreshold{
					{
						Priority:       "DEFAULT",
						MaxConnections: ptrToUint32(1000),
					},
				},
			},
		}
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationCircuitBreaker: "test-circuit-breaker",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 80},
					{Port: 443},
				},
			},
		}
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		require.NoError(t, ciliumv2.AddToScheme(scheme))
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, cb).Build()

		m := &model.Model{}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.NoError(t, err)
		require.NotNil(t, m.CircuitBreakers)
		assert.Equal(t, cb, m.CircuitBreakers["default/test-service:80"])
		assert.Equal(t, cb, m.CircuitBreakers["default/test-service:443"])
	})

	t.Run("service with annotation, CRD not found", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationCircuitBreaker: "nonexistent-circuit-breaker",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 80},
				},
			},
		}
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		require.NoError(t, ciliumv2.AddToScheme(scheme))
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build()

		m := &model.Model{}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.NoError(t, err)
		assert.Empty(t, m.CircuitBreakers)
	})

	t.Run("service with annotation in different namespace", func(t *testing.T) {
		cb := &ciliumv2.CiliumEnvoyCircuitBreaker{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-circuit-breaker",
				Namespace: "other-namespace",
			},
			Spec: ciliumv2.CiliumEnvoyCircuitBreakerSpec{
				Thresholds: []ciliumv2.CircuitBreakerThreshold{
					{
						Priority:       "DEFAULT",
						MaxConnections: ptrToUint32(1000),
					},
				},
			},
		}
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationCircuitBreaker: "other-namespace/test-circuit-breaker",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 80},
				},
			},
		}
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		require.NoError(t, ciliumv2.AddToScheme(scheme))
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, cb).Build()

		m := &model.Model{}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.NoError(t, err)
		require.NotNil(t, m.CircuitBreakers)
		assert.Equal(t, cb, m.CircuitBreakers["default/test-service:80"])
	})

	t.Run("service with invalid annotation format", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationCircuitBreaker: "ns1/ns2/name", // invalid format
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Port: 80},
				},
			},
		}
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build()

		m := &model.Model{}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.NoError(t, err)
		assert.Empty(t, m.CircuitBreakers)
	})

	t.Run("multiple services with different circuit breakers", func(t *testing.T) {
		cb1 := &ciliumv2.CiliumEnvoyCircuitBreaker{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cb1",
				Namespace: "default",
			},
			Spec: ciliumv2.CiliumEnvoyCircuitBreakerSpec{
				Thresholds: []ciliumv2.CircuitBreakerThreshold{
					{Priority: "DEFAULT", MaxConnections: ptrToUint32(1000)},
				},
			},
		}
		cb2 := &ciliumv2.CiliumEnvoyCircuitBreaker{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cb2",
				Namespace: "default",
			},
			Spec: ciliumv2.CiliumEnvoyCircuitBreakerSpec{
				Thresholds: []ciliumv2.CircuitBreakerThreshold{
					{Priority: "DEFAULT", MaxConnections: ptrToUint32(2000)},
				},
			},
		}
		svc1 := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "service1",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationCircuitBreaker: "cb1",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 80}},
			},
		}
		svc2 := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "service2",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationCircuitBreaker: "cb2",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 8080}},
			},
		}
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		require.NoError(t, ciliumv2.AddToScheme(scheme))
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc1, svc2, cb1, cb2).Build()

		m := &model.Model{}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.NoError(t, err)
		require.NotNil(t, m.CircuitBreakers)
		assert.Equal(t, cb1, m.CircuitBreakers["default/service1:80"])
		assert.Equal(t, cb2, m.CircuitBreakers["default/service2:8080"])
	})

	t.Run("error getting CRD (non-NotFound error)", func(t *testing.T) {
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-service",
				Namespace: "default",
				Annotations: map[string]string{
					AnnotationCircuitBreaker: "test-circuit-breaker",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 80}},
			},
		}
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		// Create a client that will return an error when getting the CRD
		c := &errorClient{
			Client:   fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc).Build(),
			getError: k8serrors.NewInternalError(assert.AnError),
		}

		m := &model.Model{}
		err := EnrichModelWithCircuitBreakers(ctx, c, nil, m)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get CircuitBreaker")
	})
}

// Helper function
func ptrToUint32(v uint32) *uint32 {
	return &v
}

// errorClient is a test helper that wraps a client and returns errors on Get operations
type errorClient struct {
	client.Client
	getError error
}

func (e *errorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*ciliumv2.CiliumEnvoyCircuitBreaker); ok {
		return e.getError
	}
	return e.Client.Get(ctx, key, obj, opts...)
}
