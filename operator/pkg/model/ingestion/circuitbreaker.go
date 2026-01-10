// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// AnnotationCircuitBreaker is the annotation key on Service to reference a CiliumEnvoyCircuitBreaker CRD.
	AnnotationCircuitBreaker = "cilium.io/circuit-breaker"
)

// EnrichModelWithCircuitBreakers collects CircuitBreaker CRDs referenced by Services
// and adds them to the model. This function should be called before translating the model.
func EnrichModelWithCircuitBreakers(ctx context.Context, c client.Client, logger *slog.Logger, m *model.Model) error {
	if m == nil {
		return fmt.Errorf("model cannot be nil")
	}

	// Skip if CircuitBreakers already collected
	if m.CircuitBreakers != nil {
		return nil
	}

	servicesList := &corev1.ServiceList{}
	if err := c.List(ctx, servicesList); err != nil {
		if logger != nil {
			logger.ErrorContext(ctx, "Unable to list Services", logfields.Error, err)
		}
		return fmt.Errorf("failed to list Services: %w", err)
	}

	circuitBreakers := make(map[string]interface{})

	for _, svc := range servicesList.Items {
		annotationValue, ok := svc.GetAnnotations()[AnnotationCircuitBreaker]
		if !ok || annotationValue == "" {
			continue
		}

		var cbNamespace, cbName string
		parts := strings.Split(annotationValue, "/")
		if len(parts) == 1 {
			cbNamespace = svc.GetNamespace()
			cbName = parts[0]
		} else if len(parts) == 2 {
			cbNamespace = parts[0]
			cbName = parts[1]
		} else {
			if logger != nil {
				logger.WarnContext(ctx, "Invalid circuit breaker annotation format",
					"service", client.ObjectKeyFromObject(&svc),
					"annotation", annotationValue)
			}
			continue
		}

		cb := &ciliumv2.CiliumEnvoyCircuitBreaker{}
		cbKey := client.ObjectKey{Namespace: cbNamespace, Name: cbName}
		if err := c.Get(ctx, cbKey, cb); err != nil {
			if k8serrors.IsNotFound(err) {
				if logger != nil {
					logger.WarnContext(ctx, "CircuitBreaker CRD not found",
						"service", client.ObjectKeyFromObject(&svc),
						"circuitBreaker", cbKey)
				}
			} else {
				if logger != nil {
					logger.ErrorContext(ctx, "Unable to get CircuitBreaker CRD",
						"service", client.ObjectKeyFromObject(&svc),
						"circuitBreaker", cbKey,
						logfields.Error, err)
				}
				return fmt.Errorf("failed to get CircuitBreaker %s/%s: %w", cbNamespace, cbName, err)
			}
			continue
		}

		for _, port := range svc.Spec.Ports {
			key := fmt.Sprintf("%s/%s:%s", svc.GetNamespace(), svc.GetName(), strconv.FormatInt(int64(port.Port), 10))
			circuitBreakers[key] = cb
		}
	}

	m.CircuitBreakers = circuitBreakers

	// Log applied CircuitBreakers
	if logger != nil && len(circuitBreakers) > 0 {
		for key, cbInterface := range circuitBreakers {
			if cb, ok := cbInterface.(*ciliumv2.CiliumEnvoyCircuitBreaker); ok {
				logger.InfoContext(ctx, "Circuit breaker applied to service",
					"service", key,
					"circuitBreaker", fmt.Sprintf("%s/%s", cb.GetNamespace(), cb.GetName()))
			}
		}
	}

	return nil
}
