// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// TranslationExtension modifies the translated Envoy configuration before it
// is persisted. Implementations must not persist the configuration themselves.
type TranslationExtension interface {
	// Name returns the stable extension name used in diagnostics.
	Name() string

	// Order controls execution order. Lower values run first and values must be unique.
	Order() int

	// Enabled reports whether the extension should be applied.
	Enabled() bool

	// Apply modifies cec for gateway. The extension may defer reconciliation to
	// preserve the last successfully applied configuration.
	Apply(context.Context, *gatewayv1.Gateway, *ciliumv2.CiliumEnvoyConfig) (TranslationExtensionResult, error)
}

// TranslationExtensionResult controls Gateway reconciliation after an
// extension has been applied.
type TranslationExtensionResult struct {
	DeferReconcile bool
}

func (r *gatewayReconciler) applyTranslationExtensions(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	cec *ciliumv2.CiliumEnvoyConfig,
) (bool, error) {
	if cec == nil {
		return false, nil
	}

	for _, extension := range r.translationExtensions {
		if !extension.Enabled() {
			continue
		}

		result, err := extension.Apply(ctx, gateway, cec)
		if err != nil {
			return false, fmt.Errorf("translation extension %q failed: %w", extension.Name(), err)
		}

		if result.DeferReconcile {
			return true, nil
		}
	}

	return false, nil
}

func orderTranslationExtensions(extensions []TranslationExtension) ([]TranslationExtension, error) {
	names := make(map[string]struct{}, len(extensions))
	orders := make(map[int]string, len(extensions))
	for _, extension := range extensions {
		if extension == nil {
			return nil, fmt.Errorf("translation extension must not be nil")
		}

		name := extension.Name()
		if name == "" {
			return nil, fmt.Errorf("translation extension name must not be empty")
		}

		if _, exists := names[name]; exists {
			return nil, fmt.Errorf("translation extension name %q is registered more than once", name)
		}

		names[name] = struct{}{}
		order := extension.Order()
		if existing, exists := orders[order]; exists {
			return nil, fmt.Errorf("translation extensions %q and %q use the same order %d", existing, name, order)
		}

		orders[order] = name
	}

	ordered := slices.Clone(extensions)
	slices.SortFunc(ordered, func(a, b TranslationExtension) int {
		return cmp.Compare(a.Order(), b.Order())
	})
	return ordered, nil
}
