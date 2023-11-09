// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"
	"strconv"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func isCiliumDefaultIngressController(ctx context.Context, c client.Client) bool {
	ciliumIngressClass := &networkingv1.IngressClass{}
	if err := c.Get(ctx, types.NamespacedName{Name: ciliumIngressClassName}, ciliumIngressClass); err != nil {
		if !errors.IsNotFound(err) {
			log.WithError(err).Warn("Failed to load Cilium IngressClass")
			return false
		}

		return false
	}

	isDefault, err := isIngressClassMarkedAsDefault(*ciliumIngressClass)
	if err != nil {
		log.WithError(err).Warn("Failed to detect default class on IngressClass cilium")
		return false
	}

	return isDefault
}

func isCiliumManagedIngress(ctx context.Context, c client.Client, ing networkingv1.Ingress) bool {
	ingressClassName := ingressClassName(ing)

	if ingressClassName != nil && *ingressClassName == ciliumIngressClassName {
		return true
	}

	// Check for default Ingress class
	return (ingressClassName == nil || *ingressClassName == "") && isCiliumDefaultIngressController(ctx, c)
}

func ingressClassName(ingress networkingv1.Ingress) *string {
	annotations := ingress.GetAnnotations()
	if className, ok := annotations["kubernetes.io/ingress.class"]; ok {
		return &className
	}

	return ingress.Spec.IngressClassName
}

// isIngressClassMarkedDefault determines if the given IngressClass has an annotation marking it as the
// default IngressClass for the cluster.
// If the annotation's value fails to parse, then an error is returned to signal that processing the
// IngressClass should be retried at a later point in time.
// There are four possible cases:
// 1. Annotation is set to "true": we are the default IngressClass.
// 2. Annotation is set to "false", a non-bool value, or is missing: we are not the default IngressClass.
func isIngressClassMarkedAsDefault(obj networkingv1.IngressClass) (bool, error) {
	if val, ok := obj.GetAnnotations()[networkingv1.AnnotationIsDefaultIngressClass]; ok {
		isDefault, err := strconv.ParseBool(val)
		if err != nil {
			return false, fmt.Errorf("failed to parse annotation value for %q: %w", networkingv1.AnnotationIsDefaultIngressClass, err)
		}

		return isDefault, nil
	}

	// If the annotation is not set, or set to an improper value,
	// we should not be the default ingress class.
	return false, nil
}
